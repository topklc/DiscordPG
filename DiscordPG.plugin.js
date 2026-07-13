/**
 * @name DiscordPG
 * @author topklc
 * @authorId 0
 * @version 1.12.0
 * @description End-to-end PGP encryption for Discord messages using OpenPGP.js. Generate/import keys, encrypt to your contacts, and auto-decrypt incoming PGP blocks inline. Use "/pgp on" or "/pgp off" in a channel to toggle encryption.
 * @website https://github.com/topklc/DiscordPG
 * @source https://github.com/topklc/DiscordPG/blob/main/DiscordPG.plugin.js
 * @updateUrl https://raw.githubusercontent.com/topklc/DiscordPG/main/DiscordPG.plugin.js
 */

/*
 * SECURITY NOTES: read before trusting this with anything serious:
 *  - Your private key and passphrase are stored in plaintext in the BetterDiscord
 *    data folder. Anyone with access to your machine/profile can read them.
 *  - Discord message content is limited to 2000 characters. PGP ciphertext is large,
 *    so only short messages fit. Long messages will be rejected by Discord.
 *  - This uses in-plugin OpenPGP.js (downloaded from jsDelivr on first run). Review
 *    the code and pin/verify the library yourself if you need real assurance.
 */

module.exports = (() => {

    const config = {
        name: "DiscordPG",
        version: "1.12.0",
        author: "topklc",
    };

    // OpenPGP.js v5 UMD build. "@5" resolves to the latest v5.x on jsDelivr.
    const OPENPGP_URL = "https://cdn.jsdelivr.net/npm/openpgp@5/dist/openpgp.min.js";

    const path = require("path");
    const fs = require("fs");
    const https = require("https");

    const DEFAULTS = {
        privateKey: "",
        publicKey: "",
        passphrase: "",
        revocationCertificate: "", // armored cert to publish if this key is compromised
        contacts: {},          // { [userId]: { label, publicKey, revoked? } }
        enabledChannels: {},   // { [channelId]: true }
        groups: {},            // { [channelId]: [contactId, ...] } local recipient set per channel
        signMessages: true,
        autoDecrypt: true,
        minimalBadges: false,  // plain 🔓/🔒/🔑 on messages instead of the colored PGP tag
        richContent: false,    // master opt-in: render emojis/links/media in decrypted messages
        renderEmojis: true,    // custom Discord emoji (loads from Discord's CDN); needs richContent
        autoLoadMedia: false,  // auto-fetch image/GIF links (leaks IP to host!); needs richContent
    };

    class DiscordPG {
        getName() { return config.name; }
        getAuthor() { return config.author; }
        getVersion() { return config.version; }
        getDescription() {
            return "PGP encryption for Discord messages. Toggle a channel with /pgp on | off.";
        }

        constructor() {
            this.settings = Object.assign({}, DEFAULTS);
            this.openpgp = null;
            this.myUnlockedKey = null;      // cached unlocked private key object
            this.decryptCache = new Map();  // armoredCiphertext -> { ok: boolean, text: string }
            this.observer = null;
            this._scanScheduled = false;
            this.ready = false;
        }

        // ---------- persistence ----------
        load() {
            let saved = BdApi.Data.load(config.name, "settings");
            if (!saved || !saved.privateKey) {
                // One-time migration from the plugin's old name ("DiscordPGP"),
                // so existing keys/contacts survive the rename.
                const legacy = BdApi.Data.load("DiscordPGP", "settings");
                if (legacy && legacy.privateKey) {
                    saved = legacy;
                    BdApi.Data.save(config.name, "settings", legacy);
                }
            }
            this.settings = Object.assign({}, DEFAULTS, saved || {});
            this.settings.contacts = this.settings.contacts || {};
            this.settings.enabledChannels = this.settings.enabledChannels || {};
            this.settings.groups = this.settings.groups || {};
        }
        save() {
            BdApi.Data.save(config.name, "settings", this.settings);
        }

        // ---------- lifecycle ----------
        start() {
            this.load();
            BdApi.DOM.addStyle(config.name, this._css());
            // Async init so we can download + require OpenPGP before patching.
            this._init().catch((e) => {
                console.error("[DiscordPG] init failed:", e);
                BdApi.UI.showToast("DiscordPG failed to start: " + e.message, { type: "error" });
            });
        }

        stop() {
            this.ready = false;
            this._unregisterCommands();
            BdApi.Patcher.unpatchAll(config.name);
            BdApi.DOM.removeStyle(config.name);
            if (this.observer) { this.observer.disconnect(); this.observer = null; }
            this.myUnlockedKey = null;
        }

        async _init() {
            this.openpgp = await this._loadOpenPGP();

            this.ChannelStore = BdApi.Webpack.getStore("ChannelStore");
            this.MessageStore = BdApi.Webpack.getStore("MessageStore");
            this.UserStore = BdApi.Webpack.getStore("UserStore");
            this.MessageActions = BdApi.Webpack.getModule(
                (m) => m && typeof m.sendMessage === "function" && typeof m.editMessage === "function"
            );

            if (!this.MessageActions) {
                throw new Error("Could not locate Discord's message module (Discord may have updated).");
            }

            this._patchSend();
            this._registerCommands();
            this._startObserver();
            this.ready = true;
            BdApi.UI.showToast("DiscordPG ready", { type: "success" });
        }

        // ---------- OpenPGP loading ----------
        async _loadOpenPGP() {
            const dir = BdApi.Plugins.folder;
            const libPath = path.join(dir, ".openpgp.min.js");
            if (!fs.existsSync(libPath) || fs.statSync(libPath).size < 10000) {
                BdApi.UI.showToast("DiscordPG: downloading OpenPGP.js…", { type: "info" });
                await this._download(OPENPGP_URL, libPath);
                // The self-contained browser build leaves its API in a module-local
                // `var openpgp` that never reaches module.exports when require()'d.
                // Append an export line so a real CommonJS loader can pick it up.
                // Best-effort only; the evaluation fallback below doesn't need it,
                // and some fs shims lack appendFileSync.
                try {
                    fs.appendFileSync(
                        libPath,
                        '\n;if(typeof module!=="undefined"&&module.exports){module.exports=openpgp;}\n'
                    );
                } catch (_) { /* eval path works without it */ }
            }
            let openpgp = null;

            // Attempt 1: CommonJS require (works when a real Node loader is present).
            // BetterDiscord's require shim can't load arbitrary files, so it may return
            // an empty object or throw, so treat failure as non-fatal.
            try {
                if (require.cache && require.resolve) delete require.cache[require.resolve(libPath)];
                openpgp = require(libPath);
            } catch (_) { /* fall through to evaluation */ }

            // Attempt 2: evaluate the bundle text in a function scope and capture
            // its top-level `var openpgp`. This works inside Discord's renderer.
            if (!openpgp || typeof openpgp.encrypt !== "function") {
                const code = fs.readFileSync(libPath, "utf8");
                openpgp = new Function(
                    code + '\n;return (typeof openpgp !== "undefined") ? openpgp : undefined;'
                )();
            }

            if (!openpgp || typeof openpgp.encrypt !== "function") {
                throw new Error("OpenPGP.js loaded but looks invalid.");
            }
            return openpgp;
        }

        async _download(url, dest) {
            const buf = await this._fetchBuffer(url);
            if (!buf || buf.length < 10000) throw new Error("Downloaded file looks too small/empty.");
            fs.writeFileSync(dest, buf);
        }

        // Try several download mechanisms in order of reliability inside Discord's
        // Electron renderer. Some environments return a non-standard object from
        // https.get (no .resume/.on), so we don't depend on any single one.
        async _fetchBuffer(url) {
            const errors = [];

            // 1) BetterDiscord's own networking: Node-backed, bypasses Discord's CSP.
            try {
                if (BdApi.Net && typeof BdApi.Net.fetch === "function") {
                    const res = await BdApi.Net.fetch(url, { redirect: "follow" });
                    if (!res.ok) throw new Error("HTTP " + res.status);
                    return Buffer.from(await res.arrayBuffer());
                }
            } catch (e) { errors.push("BdApi.Net: " + e.message); }

            // 2) Node https (bypasses CSP). Hardened stream handling.
            try {
                return await this._httpsGet(url);
            } catch (e) { errors.push("https: " + e.message); }

            // 3) Browser fetch (may be blocked by Discord's CSP, but worth a try).
            try {
                const res = await fetch(url, { redirect: "follow" });
                if (!res.ok) throw new Error("HTTP " + res.status);
                return Buffer.from(await res.arrayBuffer());
            } catch (e) { errors.push("fetch: " + e.message); }

            throw new Error("all download methods failed [" + errors.join(" | ") + "]");
        }

        _httpsGet(url, redirects = 0) {
            return new Promise((resolve, reject) => {
                if (redirects > 5) return reject(new Error("too many redirects"));
                let req;
                try {
                    req = https.get(url, (res) => {
                        const status = res.statusCode;
                        const drain = () => { if (typeof res.resume === "function") res.resume(); };
                        if (status >= 300 && status < 400 && res.headers && res.headers.location) {
                            drain();
                            const next = new URL(res.headers.location, url).toString();
                            return resolve(this._httpsGet(next, redirects + 1));
                        }
                        if (status !== 200) {
                            drain();
                            return reject(new Error("HTTP " + status));
                        }
                        const chunks = [];
                        res.on("data", (c) => chunks.push(Buffer.from(c)));
                        res.on("end", () => resolve(Buffer.concat(chunks)));
                        res.on("error", reject);
                    });
                } catch (e) { return reject(e); }
                if (req && typeof req.on === "function") req.on("error", reject);
            });
        }

        // ---------- key helpers ----------
        async getMyKey() {
            if (this.myUnlockedKey) return this.myUnlockedKey;
            if (!this.settings.privateKey) throw new Error("No private key set (open plugin settings).");
            let key = await this.openpgp.readPrivateKey({ armoredKey: this.settings.privateKey });
            if (!key.isDecrypted()) {
                key = await this.openpgp.decryptKey({
                    privateKey: key,
                    passphrase: this.settings.passphrase || "",
                });
            }
            this.myUnlockedKey = key;
            return key;
        }

        // Default recipient keys for a channel (before @mention targeting).
        //  - DMs / group DMs: the channel's actual recipients.
        //  - Guild channels: the local group defined for that channel, if any.
        // There is no "encrypt to every contact" fallback: a guild channel with no
        // group yields no recipients, so a plain message there fails closed unless
        // it @mentions specific contacts.
        _recipientPublicKeys(channelId) {
            const ch = this.ChannelStore && this.ChannelStore.getChannel(channelId);
            const ids = (ch && ch.recipients) || [];
            if (ids.length) {
                return ids
                    .map((id) => {
                        // _resolveContactId also matches username-only contacts and
                        // heals their stored ID, so DMs work without a manual ID.
                        const rid = this._resolveContactId(id);
                        const c = rid && this.settings.contacts[rid];
                        return c && !c.revoked && c.publicKey; // never encrypt to a revoked key
                    })
                    .filter(Boolean);
            }
            const group = (this.settings.groups && this.settings.groups[channelId]) || [];
            return group
                .map((id) => { const c = this.settings.contacts[id]; return c && !c.revoked && c.publicKey; })
                .filter(Boolean);
        }

        async encryptForChannel(channelId, text) {
            // @mention targeting: if the message mentions users, encrypt ONLY to
            // those users' saved keys (plus yourself), overriding the channel's
            // normal recipient selection. Two forms are recognised:
            //   1. real Discord mentions: raw content contains <@id> / <@!id>
            //   2. plain-text "@label" matching a saved contact's label, for when
            //      Discord doesn't convert the @ (no autocomplete pick, DMs, etc.)
            const rawMentionIds = [...new Set([...text.matchAll(/<@!?(\d+)>/g)].map((m) => m[1]))];
            // Real mentions must all resolve to saved keys (fail closed): the
            // user explicitly targeted people. _resolveContactId also matches by
            // username and self-heals contacts saved with a wrong User ID.
            const mentionIds = [];
            const missing = [];
            for (const id of rawMentionIds) {
                const rid = this._resolveContactId(id);
                if (rid) mentionIds.push(rid);
                else missing.push(this._describeUser(id));
            }
            if (missing.length) {
                throw new Error("No saved public key for mentioned user(s): " + missing.join(", ")
                    + ". Check the contact's User ID / label in settings.");
            }
            for (const [id, c] of Object.entries(this.settings.contacts)) {
                if (!c.label || !c.publicKey || c.revoked || mentionIds.includes(id)) continue;
                const esc = c.label.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
                // "@label" not immediately preceded/followed by a word character,
                // so "me@bobmail.com" doesn't target the contact "bob".
                if (new RegExp("(^|[^a-z0-9_])@" + esc + "(?![a-z0-9_])", "i").test(text)) {
                    mentionIds.push(id);
                }
            }
            // Fail closed on explicitly targeted contacts whose key is revoked.
            const revokedTargets = mentionIds.filter((id) => this.settings.contacts[id] && this.settings.contacts[id].revoked);
            if (revokedTargets.length) {
                throw new Error("Key revoked for: "
                    + revokedTargets.map((id) => this.settings.contacts[id].label || id).join(", ")
                    + ". Ask them for a new key.");
            }
            let armoredRecips;
            if (mentionIds.length) {
                armoredRecips = mentionIds.map((id) => this.settings.contacts[id].publicKey);
                const names = mentionIds.map((id) => this.settings.contacts[id].label || id).join(", ");
                BdApi.UI.showToast("🔒 Encrypted only for: " + names + " (+ you)", { type: "info" });
            } else {
                armoredRecips = this._recipientPublicKeys(channelId);
            }
            // Fail closed: refuse rather than silently encrypt to ourselves only,
            // which would post a message nobody else could read.
            if (!armoredRecips.length) {
                const ch = this.ChannelStore && this.ChannelStore.getChannel(channelId);
                const isDM = ch && ch.recipients && ch.recipients.length;
                throw new Error(isDM
                    ? "No saved key for this conversation. Save their public key first."
                    : "No recipients for this channel. Use /pgp group add @user, or @mention someone.");
            }
            const encryptionKeys = [];
            for (const a of armoredRecips) {
                try { encryptionKeys.push(await this.openpgp.readKey({ armoredKey: a })); } catch (_) {}
            }
            if (!encryptionKeys.length) {
                throw new Error("No recipient public key. Add a contact key in settings.");
            }
            // Always encrypt to ourselves so we can read our own sent messages.
            if (this.settings.publicKey) {
                try { encryptionKeys.push(await this.openpgp.readKey({ armoredKey: this.settings.publicKey })); } catch (_) {}
            }
            const opts = {
                message: await this.openpgp.createMessage({ text }),
                encryptionKeys,
            };
            if (this.settings.signMessages) opts.signingKeys = await this.getMyKey();
            return await this.openpgp.encrypt(opts);
        }

        async decryptText(armored) {
            const message = await this.openpgp.readMessage({ armoredMessage: armored });
            const key = await this.getMyKey();
            const { data } = await this.openpgp.decrypt({ message, decryptionKeys: key });
            return data;
        }

        // ---------- revocation ----------
        // Return an armored revocation artifact for our own key, generating and
        // caching one if we don't have it yet. Newly generated keys already carry
        // a detached certificate; imported/older keys get the revoked-public-key
        // form instead (OpenPGP.js can't emit a detached cert for an existing key).
        async _makeRevocationCert() {
            if (this.settings.revocationCertificate) return this.settings.revocationCertificate;
            const key = await this.getMyKey(); // unlocked private key
            const { publicKey } = await this.openpgp.revokeKey({ key, format: "armored" });
            this.settings.revocationCertificate = publicKey.trim();
            this.save();
            return this.settings.revocationCertificate;
        }

        async _fprOf(armored) {
            try { return (await this.openpgp.readKey({ armoredKey: armored })).getFingerprint(); }
            catch (_) { return null; }
        }

        // Given a posted revocation artifact, return which of our stored keys it
        // cryptographically revokes: { scope: "self" } or { scope: "contact", id }.
        // The message author is never trusted; only the signature decides. Returns
        // null if the artifact verifies against no key we hold.
        async _matchRevocation(armored) {
            const cands = [];
            if (this.settings.publicKey) cands.push({ scope: "self", key: this.settings.publicKey });
            for (const [id, c] of Object.entries(this.settings.contacts)) {
                if (c.publicKey) cands.push({ scope: "contact", id, key: c.publicKey });
            }

            // Form A: a full key block that is already revoked. isRevoked() has
            // verified the embedded self-signature, so a fingerprint match is safe.
            let parsed = null;
            try { parsed = await this.openpgp.readKey({ armoredKey: armored }); } catch (_) {}
            if (parsed) {
                if (!(await parsed.isRevoked())) return null; // a normal, live key
                const fpr = parsed.getFingerprint();
                for (const cand of cands) {
                    if ((await this._fprOf(cand.key)) === fpr) return cand;
                }
                return null;
            }

            // Form B: a detached revocation certificate. revokeKey() throws unless
            // the certificate's signature matches the candidate key.
            for (const cand of cands) {
                try {
                    const revoked = await this.openpgp.revokeKey({
                        key: await this.openpgp.readKey({ armoredKey: cand.key }),
                        revocationCertificate: armored,
                        format: "armored",
                    });
                    if (await (await this.openpgp.readKey({ armoredKey: revoked.publicKey })).isRevoked()) return cand;
                } catch (_) { /* signature does not match this candidate */ }
            }
            return null;
        }

        // ---------- sending ----------
        // Resolve a mentioned user id to a saved contact id. If the id isn't a
        // saved contact, fall back to matching the mentioned user's username /
        // display name against contact labels (contacts are often saved with a
        // wrong or stale User ID) and self-heal the contact on a unique match.
        _resolveContactId(userId) {
            const direct = this.settings.contacts[userId];
            if (direct && direct.publicKey) return userId;
            const u = this.UserStore && this.UserStore.getUser && this.UserStore.getUser(userId);
            if (!u) return null;
            const names = [u.username, u.globalName].filter(Boolean).map((n) => String(n).toLowerCase());
            const matches = Object.entries(this.settings.contacts).filter(([, c]) =>
                c.publicKey && c.label && names.includes(c.label.toLowerCase()));
            if (matches.length !== 1) return null; // none or ambiguous: don't guess
            const [oldId, contact] = matches[0];
            delete this.settings.contacts[oldId];
            this.settings.contacts[userId] = contact;
            this.save();
            BdApi.UI.showToast('PGP: contact "' + contact.label + '" matched by name, saved ID corrected to ' + userId, { type: "info" });
            return userId;
        }

        _describeUser(userId) {
            const u = this.UserStore && this.UserStore.getUser && this.UserStore.getUser(userId);
            return u && u.username ? "@" + u.username + " (" + userId + ")" : userId;
        }

        _patchSend() {
            const self = this;
            BdApi.Patcher.instead(config.name, this.MessageActions, "sendMessage", (_thisObj, args, original) => {
                // One-shot plaintext post from a native command (see _sendPlain).
                if (self._bypassOnce) { self._bypassOnce = false; return original(...args); }
                const [channelId, message] = args;
                const content = (message && message.content) || "";

                // ".pgp" works alongside "/pgp" because Discord's slash-command
                // picker can swallow unknown /commands before they're sent.
                const lead = content.trimStart();
                if (lead.startsWith("/pgp") || lead.startsWith(".pgp")) {
                    return (async () => {
                        let replacement;
                        try { replacement = await self._handleCommand(channelId, content.trim()); }
                        catch (e) { BdApi.UI.showToast("PGP: " + e.message, { type: "error" }); return {}; }
                        // A command may return replacement content to post as-is
                        // (plaintext, via the unpatched send). Otherwise swallow.
                        if (typeof replacement === "string" && replacement) {
                            if (replacement.length > 2000) {
                                BdApi.UI.showToast("PGP: too long to post (>2000 chars).", { type: "error" });
                                return {};
                            }
                            message.content = replacement;
                            return original(...args);
                        }
                        return {};
                    })();
                }

                // Only encrypt when the channel is explicitly enabled (/pgp on).
                // With PGP off, messages are sent as-is even if they @mention a
                // saved contact; @mention targeting only applies inside an enabled
                // channel.
                if (!self.ready || !self.settings.enabledChannels[channelId]) {
                    return original(...args);
                }

                return (async () => {
                    try {
                        const cipher = await self.encryptForChannel(channelId, content);
                        if (cipher.length > 2000) {
                            BdApi.UI.showToast("PGP: message too long to send encrypted (>2000 chars).", { type: "error" });
                            return {};
                        }
                        message.content = cipher;
                    } catch (e) {
                        // Fail closed: never send plaintext on a channel the user marked encrypted.
                        BdApi.UI.showToast("PGP encrypt failed: " + e.message, { type: "error" });
                        return {};
                    }
                    return original(...args);
                })();
            });
        }

        // Handle a "/pgp <sub> ..." command. Returns a string to post as-is
        // (plaintext) into the channel, or nothing to swallow the command.
        async _handleCommand(channelId, content) {
            const tokens = content.trim().split(/\s+/);
            const sub = (tokens[1] || "").toLowerCase();
            let r;
            if (sub === "group") {
                const action = (tokens[2] || "list").toLowerCase();
                const targets = (action === "add" || action === "remove") ? this._contactsInText(content) : [];
                r = this._runGroupAction(action, targets, channelId);
            } else {
                r = await this._runVerb(sub, tokens.slice(2).join(" "), channelId);
            }
            if (r.reply) BdApi.UI.showToast(r.reply, { type: r.error ? "error" : "info" });
            return r.post; // string here is posted as plaintext via the return-value path
        }

        // Shared command action for both the text and native command paths.
        // Returns { reply?, post?, error? }:
        //   reply: user feedback (toast for text, Clyde bot message natively)
        //   post:  content to send into the channel as plaintext
        async _runVerb(verb, arg, channelId) {
            const s = this.settings;
            switch ((verb || "").toLowerCase()) {
                case "on":
                    s.enabledChannels[channelId] = true; this.save(); this._decorateChannelList();
                    return { reply: "🔒 Encryption ON for this channel." };
                case "off":
                    delete s.enabledChannels[channelId]; this.save(); this._decorateChannelList();
                    return { reply: "🔓 Encryption OFF for this channel." };
                case "status": {
                    const on = !!s.enabledChannels[channelId];
                    const g = (s.groups[channelId] || []).map((id) => (s.contacts[id] && s.contacts[id].label) || id);
                    return { reply: "PGP is " + (on ? "ON" : "OFF") + " here" + (g.length ? ". Group: " + g.join(", ") : "") + "." };
                }
                case "help":
                    return { reply: "Commands: on, off, status, share, revoke, group add/remove/list/clear, debug, help." };
                case "debug":
                    return { reply: "debug: " + this._debugInfo(channelId) };
                case "share":
                    if (!s.publicKey) return { reply: "No key yet. Generate one in settings.", error: true };
                    return { post: s.publicKey, reply: "Shared your public key." };
                case "revoke": {
                    if (!s.privateKey) return { reply: "No key to revoke.", error: true };
                    let cert;
                    try { cert = await this._makeRevocationCert(); }
                    catch (e) { return { reply: "Couldn't make certificate: " + e.message, error: true }; }
                    const ok = await this._confirmAsync(
                        "Revoke and delete this keypair?",
                        "This posts a certificate that revokes your key for everyone who sees it, and removes your keypair from this device. You will no longer be able to read messages encrypted to it. Only do this if the key is compromised or retired.",
                        "Revoke");
                    if (!ok) return { reply: "Revocation cancelled." };
                    s.privateKey = ""; s.publicKey = ""; s.passphrase = ""; s.revocationCertificate = "";
                    this.myUnlockedKey = null; this.save();
                    return { post: cert, reply: "Keypair removed. Revocation posted." };
                }
                default:
                    return { reply: "Unknown command. Try /pgp help.", error: true };
            }
        }

        // Apply a group action to a channel. targetIds are already-resolved
        // contact ids. Returns { reply, error? }.
        _runGroupAction(action, targetIds, channelId) {
            const s = this.settings;
            const label = (id) => (s.contacts[id] && s.contacts[id].label) || id;
            const current = s.groups[channelId] || [];
            if (action === "list") {
                return { reply: current.length ? "Group here: " + current.map(label).join(", ") : "No group set here. Add with /pgp group add." };
            }
            if (action === "clear") {
                delete s.groups[channelId]; this.save();
                return { reply: "Group cleared for this channel." };
            }
            if (action === "add" || action === "remove") {
                if (!targetIds.length) return { reply: "No saved contact matched. Save their key first.", error: true };
                const set = new Set(current);
                if (action === "add") targetIds.forEach((id) => set.add(id));
                else targetIds.forEach((id) => set.delete(id));
                const next = [...set];
                if (next.length) s.groups[channelId] = next; else delete s.groups[channelId];
                if (action === "add") { s.enabledChannels[channelId] = true; this._decorateChannelList(); }
                this.save();
                return { reply: (action === "add" ? "Added to" : "Removed from") + " group: " + targetIds.map(label).join(", ")
                    + (action === "add" ? ". Encryption is ON here." : "") };
            }
            return { reply: "Usage: group add | remove | list | clear", error: true };
        }

        _debugInfo(channelId) {
            const s = this.settings;
            const info = "ready=" + this.ready + " | openpgp=" + !!this.openpgp
                + " | hasKey=" + !!(s.privateKey && s.publicKey)
                + " | contacts=" + Object.keys(s.contacts).length
                + " | thisChannelEnabled=" + !!s.enabledChannels[channelId]
                + " | groupHere=" + ((s.groups[channelId] || []).length)
                + " | nativeCommands=" + !!this.commandsNative;
            console.log("[DiscordPG] debug:", info, "| contact ids:", Object.keys(s.contacts),
                "| labels:", Object.values(s.contacts).map((c) => c.label));
            return info;
        }

        _confirmAsync(title, text, confirmText) {
            return new Promise((resolve) => {
                let done = false;
                const guard = setTimeout(() => finish(false), 120000);
                function finish(v) { if (!done) { done = true; clearTimeout(guard); resolve(v); } }
                this._confirm(title, text, confirmText, () => finish(true), "Cancel", () => finish(false));
            });
        }

        // Resolve saved contacts referenced in text, by <@id> mention or @label.
        _contactsInText(text) {
            const ids = new Set();
            for (const m of text.matchAll(/<@!?(\d+)>/g)) {
                const rid = this._resolveContactId(m[1]);
                if (rid) ids.add(rid);
            }
            for (const [id, c] of Object.entries(this.settings.contacts)) {
                if (!c.label || !c.publicKey) continue;
                const esc = c.label.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
                if (new RegExp("(^|[^a-z0-9_])@" + esc + "(?![a-z0-9_])", "i").test(text)) ids.add(id);
            }
            return [...ids];
        }

        // Post plaintext into a channel, bypassing encryption for this one send.
        // Used by native slash commands (share/revoke) where there is no typed
        // message to rewrite. The text path posts via the send-patch return value
        // instead, reusing Discord's own message object.
        _sendPlain(channelId, text) {
            this._bypassOnce = true;
            try {
                this.MessageActions.sendMessage(channelId, { content: text, tts: false, invalidEmojis: [], validNonShortcutEmojis: [] });
            } catch (e) {
                this._bypassOnce = false;
                BdApi.UI.showToast("Couldn't post: " + e.message, { type: "error" });
            }
        }

        // ---------- native slash commands (BetterDiscord >= ~1.13) ----------
        // Each verb is its own command (pgp-on, pgp-share, ...). BetterDiscord
        // injects commands into Discord's command index WITHOUT the server-side
        // subcommand expansion real app commands get, so SUB_COMMAND options
        // render as fillable inputs ("value required") instead of subcommands.
        // Separate flat commands are the only shape that works; typing /pgp
        // still lists them all together.
        _registerCommands() {
            const C = BdApi.Commands;
            if (!C || typeof C.register !== "function") return; // older BD: text/.pgp commands only
            const O = (C.Types && C.Types.OptionTypes) || { STRING: 3 };
            const self = this;
            const userOpt = { name: "user", description: "Mention or contact label, e.g. @bob", type: O.STRING, required: true };
            const defs = [
                { verb: "on", desc: "Enable encryption for this channel" },
                { verb: "off", desc: "Disable encryption for this channel" },
                { verb: "status", desc: "Show encryption status here" },
                { verb: "share", desc: "Post your public key into this channel" },
                { verb: "revoke", desc: "Revoke and delete your keypair" },
                { verb: "help", desc: "List DiscordPG commands" },
                { verb: "debug", desc: "Show plugin state" },
                { verb: "group-add", desc: "Add a contact to this channel's group", options: [userOpt], group: "add" },
                { verb: "group-remove", desc: "Remove a contact from this channel's group", options: [userOpt], group: "remove" },
                { verb: "group-list", desc: "List this channel's group members", group: "list" },
                { verb: "group-clear", desc: "Clear this channel's group", group: "clear" },
            ];
            this._unregisterCmds = [];
            for (const d of defs) {
                const cmd = {
                    id: "pgp-" + d.verb,
                    name: "pgp-" + d.verb,
                    description: d.desc,
                    execute: async (opts, props) => {
                        try {
                            const channelId = props && props.channel && props.channel.id;
                            let r;
                            if (d.group) {
                                const u = Array.isArray(opts) && opts.find((o) => o.name === "user");
                                const text = u && u.value != null ? String(u.value) : "";
                                r = self._runGroupAction(d.group, text ? self._contactsFromInput(text) : [], channelId);
                            } else {
                                r = await self._runVerb(d.verb, "", channelId);
                            }
                            if (r.post) self._sendPlain(channelId, r.post);
                            return { content: r.reply || "Done." };
                        } catch (e) {
                            return { content: "DiscordPG error: " + e.message };
                        }
                    },
                };
                if (d.options) cmd.options = d.options;
                try {
                    const un = C.register(config.name, cmd);
                    if (typeof un === "function") this._unregisterCmds.push(un);
                } catch (e) {
                    console.error("[DiscordPG] command registration failed:", cmd.id, e);
                }
            }
            this.commandsNative = this._unregisterCmds.length > 0;
        }

        _unregisterCommands() {
            try {
                if (Array.isArray(this._unregisterCmds)) this._unregisterCmds.forEach((un) => { try { un(); } catch (_) {} });
                else if (BdApi.Commands && BdApi.Commands.unregisterAll) BdApi.Commands.unregisterAll(config.name);
            } catch (_) {}
            this._unregisterCmds = [];
            this.commandsNative = false;
        }

        // Resolve contacts from a free-text command option: real mentions,
        // "@label", or a bare label without the @.
        _contactsFromInput(text) {
            let ids = this._contactsInText(text);
            if (!ids.length) {
                const lower = text.trim().replace(/^@/, "").toLowerCase();
                ids = Object.entries(this.settings.contacts)
                    .filter(([, c]) => c.publicKey && c.label && c.label.toLowerCase() === lower)
                    .map(([id]) => id);
            }
            return ids;
        }

        // ---------- receiving / decryption ----------
        _startObserver() {
            const app = document.querySelector("#app-mount") || document.body;
            this.observer = new MutationObserver(() => this._scheduleScan());
            this.observer.observe(app, { childList: true, subtree: true });
            this._scheduleScan();
        }

        _scheduleScan() {
            if (this._scanScheduled) return;
            this._scanScheduled = true;
            setTimeout(() => { this._scanScheduled = false; this._scan(); }, 120);
        }

        _scan() {
            if (this.settings.autoDecrypt) {
                const nodes = document.querySelectorAll('[id^="message-content-"]:not([data-pgp-done])');
                nodes.forEach((el) => this._processMessage(el));
            }
            this._decorateChannelList();
        }

        // Add a small ✓ next to channels/DMs in the sidebar that have PGP enabled.
        // Sidebar links look like /channels/@me/<id> (DMs) or /channels/<guild>/<id>.
        _decorateChannelList() {
            if (typeof document === "undefined" || !document.querySelectorAll) return;
            const links = document.querySelectorAll('nav a[href*="/channels/"]');
            links.forEach((a) => {
                const id = (a.getAttribute("href") || "").split("/").pop();
                const enabled = !!this.settings.enabledChannels[id];
                const existing = a.querySelector(".pgp-chan-badge");
                const cls = "pgp-chan-badge" + (this.settings.minimalBadges ? " pgp-min" : "");
                if (enabled && !existing) {
                    const b = document.createElement("span");
                    b.className = cls;
                    b.textContent = "🔒";
                    b.title = "PGP encryption enabled";
                    // Prefer sitting right after the channel name; fall back to the link.
                    const name = a.querySelector('[class*="name"]');
                    (name || a).appendChild(b);
                } else if (enabled && existing) {
                    existing.className = cls; // keep in sync with the minimal setting
                } else if (!enabled && existing) {
                    existing.remove();
                }
            });
        }

        _processMessage(el) {
            const messageId = el.id.replace("message-content-", "");
            // The <li> ancestor carries id="chat-messages-<channelId>-<messageId>".
            const li = el.closest('li[id^="chat-messages-"]');
            let channelId = null;
            if (li) {
                const m = li.id.match(/^chat-messages-(\d+)-\d+$/);
                if (m) channelId = m[1];
            }

            let raw = "";
            if (channelId && this.MessageStore) {
                const msg = this.MessageStore.getMessage(channelId, messageId);
                raw = (msg && msg.content) || "";
            }
            if (!raw) raw = el.textContent || "";

            const block = raw.match(/-----BEGIN PGP MESSAGE-----[\s\S]*?-----END PGP MESSAGE-----/);
            if (!block) {
                // Pasted public key? Offer to save the sender as a contact.
                const pubBlock = raw.match(/-----BEGIN PGP PUBLIC KEY BLOCK-----[\s\S]*?-----END PGP PUBLIC KEY BLOCK-----/);
                el.dataset.pgpDone = "1"; // either way, processed; skip forever
                if (pubBlock) this._handleKeyBlock(el, pubBlock[0], channelId, messageId);
                return;
            }
            const armored = block[0];

            const cached = this.decryptCache.get(armored);
            if (cached) {
                el.dataset.pgpDone = "1";
                this._render(el, cached, armored);
                return;
            }

            // Mark in-flight so we don't fire duplicate decrypts for the same element.
            el.dataset.pgpDone = "pending";
            this.decryptText(armored)
                .then((text) => {
                    const result = { ok: true, text };
                    this.decryptCache.set(armored, result);
                    el.dataset.pgpDone = "1";
                    this._render(el, result, armored);
                })
                .catch(() => {
                    const result = { ok: false, text: "" };
                    this.decryptCache.set(armored, result);
                    el.dataset.pgpDone = "1";
                    this._render(el, result, armored);
                });
        }

        _render(el, result, armored) {
            el.innerHTML = "";
            const min = this.settings.minimalBadges;
            const badge = document.createElement("span");
            badge.className = "pgp-badge " + (result.ok ? "pgp-ok" : "pgp-fail") + (min ? " pgp-min" : "");
            badge.textContent = min
                ? (result.ok ? "🔓" : "🔒")
                : (result.ok ? "🔓 PGP" : "🔒 PGP (can't decrypt)");
            badge.title = (result.ok ? "" : "Couldn't decrypt. ") + "Click to show the raw PGP message";
            el.appendChild(badge);
            if (result.ok) {
                const body = document.createElement("span");
                body.className = "pgp-body";
                if (this.settings.richContent) {
                    this._renderBody(body, result.text); // element-built, no HTML injection
                } else {
                    body.textContent = result.text; // plain text, nothing fetched
                }
                el.appendChild(body);
            }
            // Expandable viewer for the actual armored ciphertext.
            const raw = document.createElement("div");
            raw.className = "pgp-raw";
            raw.style.display = "none";
            const bar = document.createElement("div");
            bar.className = "pgp-raw-bar";
            const title = document.createElement("span");
            title.textContent = "Encrypted payload · " + (armored ? armored.length : 0) + " chars";
            bar.appendChild(title);
            const copy = document.createElement("span");
            copy.className = "pgp-raw-copy";
            copy.textContent = "Copy";
            copy.onclick = (e) => { e.stopPropagation(); this._copy(armored || "", "PGP message"); };
            bar.appendChild(copy);
            raw.appendChild(bar);
            const pre = document.createElement("pre");
            pre.textContent = armored || "";
            raw.appendChild(pre);
            el.appendChild(raw);
            badge.onclick = () => { raw.style.display = raw.style.display === "none" ? "" : "none"; };
        }

        // Build the decrypted-message body: plain text, custom Discord emojis
        // (<:name:id> → CDN image), links, and image/GIF URLs. Media is
        // click-to-load unless autoLoadMedia is on, since auto-fetching remote URLs
        // from an E2E message would leak the reader's IP to the host.
        _renderBody(container, text) {
            const parts = String(text).split(/(<a?:\w+:\d+>|https?:\/\/\S+)/g);
            for (const part of parts) {
                if (!part) continue;
                const em = part.match(/^<(a?):(\w+):(\d+)>$/);
                if (em && this.settings.renderEmojis) {
                    const img = document.createElement("img");
                    img.className = "pgp-emoji";
                    img.src = "https://cdn.discordapp.com/emojis/" + em[3] + "." + (em[1] ? "gif" : "png") + "?size=48&quality=lossless";
                    img.alt = img.title = ":" + em[2] + ":";
                    // If the CDN load fails, fall back to the text form.
                    img.onerror = () => {
                        const t = document.createElement("span");
                        t.textContent = ":" + em[2] + ":";
                        img.replaceWith(t);
                    };
                    container.appendChild(img);
                    continue;
                }
                const isUrl = /^https?:\/\//i.test(part);
                const isMedia = isUrl && /\.(gif|png|jpe?g|webp)(\?\S*)?$/i.test(part);
                if (isMedia) {
                    container.appendChild(this._mediaNode(part));
                    continue;
                }
                if (isUrl) {
                    const a = document.createElement("a");
                    a.className = "pgp-link";
                    a.href = part;
                    a.textContent = part;
                    a.target = "_blank";
                    a.rel = "noreferrer noopener";
                    container.appendChild(a);
                    continue;
                }
                const span = document.createElement("span");
                span.textContent = part;
                container.appendChild(span);
            }
        }

        _mediaNode(url) {
            const wrap = document.createElement("div");
            wrap.className = "pgp-media";
            let host = "";
            try { host = new URL(url).hostname; } catch (_) {}
            const showImage = () => {
                wrap.innerHTML = "";
                const img = document.createElement("img");
                img.className = "pgp-media-img";
                img.src = url;
                img.alt = url;
                img.onerror = () => {
                    // Blocked by CSP or dead link: degrade to a plain link.
                    wrap.innerHTML = "";
                    const a = document.createElement("a");
                    a.className = "pgp-link";
                    a.href = url; a.textContent = url;
                    a.target = "_blank"; a.rel = "noreferrer noopener";
                    wrap.appendChild(a);
                };
                wrap.appendChild(img);
            };
            if (this.settings.autoLoadMedia) {
                showImage();
                return wrap;
            }
            const load = document.createElement("button");
            load.className = "pgp-media-load";
            load.textContent = "🖼 Load media" + (host ? " (reveals your IP to " + host + ")" : "");
            load.onclick = showImage;
            wrap.appendChild(load);
            return wrap;
        }

        // A posted "PUBLIC KEY BLOCK" is either a live public key (save-contact
        // offer) or a revocation artifact (detached cert, or a revoked full key).
        async _handleKeyBlock(el, armored, channelId, messageId) {
            if (!this.openpgp) return this._renderKeyOffer(el, armored, channelId, messageId);
            let parsed = null, revoked = false;
            try { parsed = await this.openpgp.readKey({ armoredKey: armored }); revoked = await parsed.isRevoked(); } catch (_) {}
            if (parsed && !revoked) return this._renderKeyOffer(el, armored, channelId, messageId);
            const match = await this._matchRevocation(armored);
            this._renderRevocation(el, armored, match);
        }

        // Render a verified revocation. For a matched contact this auto-marks their
        // key revoked (encryption to them now fails closed). For our own key it
        // prompts before wiping the compromised identity.
        _renderRevocation(el, armored, match) {
            el.innerHTML = "";
            const min = this.settings.minimalBadges;
            const badge = document.createElement("span");
            badge.className = "pgp-badge pgp-revoke-badge" + (min ? " pgp-min" : "");
            badge.textContent = min ? "🚫" : "🚫 PGP key revoked";
            badge.title = "PGP revocation certificate. Click to show the raw block";
            el.appendChild(badge);

            const info = document.createElement("span");
            info.className = "pgp-keyoffer-info";
            if (match && match.scope === "contact") {
                const c = this.settings.contacts[match.id];
                const name = (c && c.label) || match.id;
                if (c && !c.revoked) {
                    c.revoked = true;
                    this.save();
                    this._decorateChannelList();
                    BdApi.UI.showToast('PGP: "' + name + '" revoked their key. Marked revoked; ask them for a new one.', { type: "error", timeout: 8000 });
                }
                info.textContent = "Verified: " + name + "'s key is revoked. Encryption to them is blocked until they send a new key.";
            } else if (match && match.scope === "self") {
                info.textContent = "This is a valid revocation certificate for YOUR key.";
                this._confirm(
                    "Revoke your own key?",
                    "A valid revocation certificate for your own key was posted. If your key is compromised, remove it here and generate a new keypair. This clears your keys and passphrase from this machine.",
                    "Remove my keypair",
                    () => {
                        this.settings.privateKey = ""; this.settings.publicKey = "";
                        this.settings.passphrase = ""; this.settings.revocationCertificate = "";
                        this.myUnlockedKey = null;
                        this.save();
                        BdApi.UI.showToast("Your keypair was removed. Generate a new one in settings.", { type: "info" });
                    }
                );
            } else {
                info.textContent = "Revocation certificate (no matching saved key).";
            }
            el.appendChild(info);

            const raw = document.createElement("div");
            raw.className = "pgp-raw";
            raw.style.display = "none";
            const bar = document.createElement("div");
            bar.className = "pgp-raw-bar";
            const barLabel = document.createElement("span");
            barLabel.textContent = "Revocation certificate · " + armored.length + " chars";
            bar.appendChild(barLabel);
            const copy = document.createElement("span");
            copy.className = "pgp-raw-copy";
            copy.textContent = "Copy";
            copy.onclick = (e) => { e.stopPropagation(); this._copy(armored, "Revocation certificate"); };
            bar.appendChild(copy);
            raw.appendChild(bar);
            const pre = document.createElement("pre");
            pre.textContent = armored;
            raw.appendChild(pre);
            el.appendChild(raw);
            badge.onclick = () => { raw.style.display = raw.style.display === "none" ? "" : "none"; };
        }

        // Render an inline "save contact" offer for a pasted public key.
        _renderKeyOffer(el, armored, channelId, messageId) {
            el.innerHTML = "";
            const badge = document.createElement("span");
            badge.className = "pgp-badge pgp-key-badge" + (this.settings.minimalBadges ? " pgp-min" : "");
            badge.textContent = this.settings.minimalBadges ? "🔑" : "🔑 PGP public key";
            badge.title = "PGP public key. Click to show the raw key";
            el.appendChild(badge);

            const info = document.createElement("span");
            info.className = "pgp-keyoffer-info";
            info.textContent = "…";
            el.appendChild(info);
            if (this.openpgp) {
                this._keyInfo(armored)
                    .then((i) => { info.textContent = i.algo + " · " + i.fingerprint; })
                    .catch(() => { info.textContent = "⚠ couldn't parse this key"; });
            }

            const offer = document.createElement("div");
            offer.className = "pgp-keyoffer";
            const msg = channelId && this.MessageStore ? this.MessageStore.getMessage(channelId, messageId) : null;
            const author = msg && msg.author ? msg.author : null;
            const me = this.UserStore && this.UserStore.getCurrentUser && this.UserStore.getCurrentUser();
            if (author && me && String(author.id) === String(me.id)) {
                const mine = document.createElement("span");
                mine.className = "pgp-keyoffer-saved";
                mine.textContent = "your key";
                offer.appendChild(mine);
            } else if (author) {
                const name = author.username || author.globalName || String(author.id);
                const existing = this.settings.contacts[author.id];
                const sameKey = existing && existing.publicKey &&
                    existing.publicKey.replace(/\s+/g, "") === armored.replace(/\s+/g, "");
                if (sameKey) {
                    const saved = document.createElement("span");
                    saved.className = "pgp-keyoffer-saved";
                    saved.textContent = "✓ saved contact" + (existing.label ? " · " + existing.label : "");
                    offer.appendChild(saved);
                } else {
                    const save = document.createElement("button");
                    save.className = "pgp-keyoffer-btn";
                    save.textContent = existing
                        ? "Update key for " + (existing.label || name)
                        : "Save contact: " + name;
                    save.onclick = () => {
                        const label = (existing && existing.label) || name;
                        this.settings.contacts[String(author.id)] = { label, publicKey: armored };
                        this.save();
                        BdApi.UI.showToast('PGP contact "' + label + '" saved', { type: "success" });
                        offer.innerHTML = "";
                        const done = document.createElement("span");
                        done.className = "pgp-keyoffer-saved";
                        done.textContent = "✓ saved";
                        offer.appendChild(done);
                    };
                    offer.appendChild(save);
                }
            }
            el.appendChild(offer);

            // Expandable raw key (same pattern as encrypted payloads).
            const raw = document.createElement("div");
            raw.className = "pgp-raw";
            raw.style.display = "none";
            const bar = document.createElement("div");
            bar.className = "pgp-raw-bar";
            const t = document.createElement("span");
            t.textContent = "Public key · " + armored.length + " chars";
            bar.appendChild(t);
            const copy = document.createElement("span");
            copy.className = "pgp-raw-copy";
            copy.textContent = "Copy";
            copy.onclick = (e) => { e.stopPropagation(); this._copy(armored, "Public key"); };
            bar.appendChild(copy);
            raw.appendChild(bar);
            const pre = document.createElement("pre");
            pre.textContent = armored;
            raw.appendChild(pre);
            el.appendChild(raw);
            badge.onclick = () => { raw.style.display = raw.style.display === "none" ? "" : "none"; };
        }

        _css() {
            return `
                /* ===== in-chat ===== */
                .pgp-badge {
                    display: inline-block;
                    font-size: 11px;
                    font-weight: 600;
                    padding: 1px 6px;
                    margin-right: 6px;
                    border-radius: 8px;
                    vertical-align: middle;
                    cursor: pointer;
                    user-select: none;
                }
                .pgp-ok { background: rgba(59,165,92,.2); color: #3ba55c; }
                .pgp-fail { background: rgba(237,66,69,.2); color: #ed4245; }
                .pgp-body { white-space: pre-wrap; }
                .pgp-raw {
                    margin-top: 6px;
                    border: 1px solid var(--background-modifier-accent, rgba(255,255,255,.08));
                    border-radius: 8px;
                    background: var(--background-secondary, rgba(0,0,0,.25));
                    overflow: hidden;
                    max-width: 640px;
                }
                .pgp-raw-bar {
                    display: flex; align-items: center; justify-content: space-between;
                    padding: 5px 10px; font-size: 11px; font-weight: 600;
                    color: var(--text-muted, #949ba4);
                    border-bottom: 1px solid var(--background-modifier-accent, rgba(255,255,255,.06));
                }
                .pgp-raw-copy { cursor: pointer; color: var(--text-link, #00a8fc); }
                .pgp-raw-copy:hover { text-decoration: underline; }
                .pgp-raw pre {
                    margin: 0; padding: 8px 10px; font-size: 10px; line-height: 1.35;
                    font-family: var(--font-code, ui-monospace, "Cascadia Code", monospace);
                    white-space: pre; overflow: auto; max-height: 220px;
                    color: var(--text-normal, #dbdee1);
                }
                .pgp-chan-badge {
                    display: inline-block; margin-left: 5px; font-size: 9px; font-weight: 600;
                    padding: 1px 5px; border-radius: 6px; vertical-align: middle; line-height: 1.5;
                    background: rgba(59,165,92,.2); color: #3ba55c;
                }
                .pgp-chan-badge.pgp-min { background: none; padding: 0; font-size: 10px; font-weight: 400; }
                .pgp-key-badge { background: rgba(88,101,242,.2); color: #7983f5; }
                .pgp-revoke-badge { background: rgba(237,66,69,.2); color: #ed4245; }
                .pgp-badge.pgp-min { background: none; color: inherit; padding: 0; font-weight: 400; }
                .dpgp-contact.dpgp-revoked { opacity: .6; }
                .dpgp-revoked-tag { margin-left: 6px; font-size: 9px; font-weight: 700; letter-spacing: .04em; color: #ed4245; border: 1px solid rgba(237,66,69,.5); border-radius: 3px; padding: 0 4px; vertical-align: middle; }
                .pgp-keyoffer { margin-top: 4px; display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
                .pgp-keyoffer-info { font-size: 11px; color: var(--text-muted, #949ba4); }
                .pgp-keyoffer-btn {
                    border: none; border-radius: 5px; padding: 4px 10px; font-size: 12px; font-weight: 600;
                    cursor: pointer; background: var(--brand-experiment, #5865f2); color: #fff;
                }
                .pgp-keyoffer-btn:hover { filter: brightness(1.1); }
                .pgp-keyoffer-saved { font-size: 12px; color: #3ba55c; font-weight: 600; }
                .pgp-emoji { width: 22px; height: 22px; vertical-align: -5px; margin: 0 1px; }
                .pgp-link { color: var(--text-link, #00a8fc); }
                .pgp-link:hover { text-decoration: underline; }
                .pgp-media { margin-top: 4px; }
                .pgp-media-img { display: block; max-width: 300px; max-height: 300px; border-radius: 8px; }
                .pgp-media-load {
                    border: 1px solid var(--background-modifier-accent, rgba(255,255,255,.12));
                    border-radius: 6px; padding: 5px 10px; font-size: 12px; cursor: pointer;
                    background: var(--background-secondary, rgba(0,0,0,.2)); color: var(--text-muted, #949ba4);
                }
                .pgp-media-load:hover { color: var(--text-normal, #dbdee1); }

                /* ===== settings panel ===== */
                .dpgp-panel { color: var(--text-normal, #dbdee1); font-size: 14px; display: flex; flex-direction: column; gap: 10px; padding: 2px 2px 10px; }
                .dpgp-panel .mono { font-family: var(--font-code, ui-monospace, "Cascadia Code", monospace); }

                .dpgp-head {
                    display: flex; align-items: center; gap: 10px; padding: 8px 2px;
                    border-bottom: 1px solid var(--background-modifier-accent, rgba(255,255,255,.08));
                }
                .dpgp-head-title { font-weight: 600; font-size: 16px; color: var(--header-primary, #fff); }
                .dpgp-head-sub { font-size: 12px; color: var(--text-muted, #949ba4); }
                .dpgp-head .dpgp-pill { margin-left: auto; }
                .dpgp-pill { font-size: 11px; font-weight: 600; padding: 2px 8px; border-radius: 999px; white-space: nowrap; }
                .dpgp-pill.ok { color: #3ba55c; border: 1px solid rgba(59,165,92,.4); }
                .dpgp-pill.warn { color: #f0b232; border: 1px solid rgba(240,178,50,.4); }

                .dpgp-sec {
                    border: 1px solid var(--background-modifier-accent, rgba(255,255,255,.07));
                    border-radius: 6px; overflow: hidden;
                }
                .dpgp-sum { list-style: none; display: flex; align-items: center; gap: 8px; padding: 10px 12px; cursor: pointer; user-select: none; }
                .dpgp-sum::-webkit-details-marker { display: none; }
                .dpgp-sum:hover { background: var(--background-modifier-hover, rgba(255,255,255,.03)); }
                .dpgp-sum-title { font-weight: 500; font-size: 14px; color: var(--header-primary, #f2f3f5); }
                .dpgp-sum-sub { font-size: 12px; color: var(--text-muted, #949ba4); }
                .dpgp-chev { margin-left: auto; color: var(--text-muted, #949ba4); font-size: 16px; transition: transform .15s ease; }
                .dpgp-sec[open] > .dpgp-sum .dpgp-chev { transform: rotate(90deg); }
                .dpgp-sec-body {
                    display: flex; flex-direction: column; gap: 9px; padding: 12px;
                    border-top: 1px solid var(--background-modifier-accent, rgba(255,255,255,.05));
                }

                .dpgp-field { display: flex; flex-direction: column; gap: 4px; }
                .dpgp-stack { display: flex; flex-direction: column; gap: 8px; }
                .dpgp-label { font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: .02em; color: var(--header-secondary, #b5bac1); }
                .dpgp-input {
                    width: 100%; box-sizing: border-box; background: var(--input-background, rgba(0,0,0,.3));
                    color: var(--text-normal, #dbdee1); border: 1px solid var(--background-tertiary, rgba(0,0,0,.3));
                    border-radius: 4px; padding: 7px 9px; font-size: 13px; outline: none; transition: border-color .12s;
                }
                .dpgp-input:focus { border-color: var(--brand-experiment, #5865f2); }
                textarea.dpgp-input { min-height: 80px; resize: vertical; font-size: 12px; }
                select.dpgp-input { cursor: pointer; }

                .dpgp-row { display: flex; flex-wrap: wrap; gap: 6px; align-items: center; }
                .dpgp-grid2 { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; }
                .dpgp-passrow { display: flex; gap: 5px; }
                .dpgp-passrow .dpgp-input { flex: 1; }

                .dpgp-btn {
                    border: none; border-radius: 4px; padding: 6px 12px; font-size: 13px; font-weight: 500; cursor: pointer;
                    background: var(--brand-experiment, #5865f2); color: #fff; transition: filter .12s, background .12s;
                }
                .dpgp-btn:hover { filter: brightness(1.1); }
                .dpgp-btn:disabled { opacity: .5; cursor: default; }
                .dpgp-btn.secondary { background: var(--background-modifier-accent, rgba(255,255,255,.09)); color: var(--text-normal, #dbdee1); }
                .dpgp-btn.danger { background: transparent; color: var(--text-danger, #fa777c); border: 1px solid rgba(237,66,69,.5); }
                .dpgp-btn.danger:hover { background: #ed4245; color: #fff; filter: none; }
                .dpgp-btn.eye { padding: 6px 9px; flex: none; font-size: 12px; }

                .dpgp-kv {
                    display: grid; grid-template-columns: auto 1fr; gap: 4px 12px; padding: 8px 10px;
                    border-radius: 4px; background: var(--background-tertiary, rgba(0,0,0,.2));
                }
                .dpgp-kv-k { font-size: 12px; color: var(--text-muted, #949ba4); font-weight: 600; }
                .dpgp-kv-v { font-size: 13px; word-break: break-all; }

                .dpgp-seg { display: inline-flex; gap: 2px; background: var(--background-tertiary, rgba(0,0,0,.25)); border-radius: 4px; padding: 2px; width: max-content; }
                .dpgp-seg > button {
                    border: none; background: transparent; color: var(--text-muted, #949ba4);
                    font-size: 13px; font-weight: 500; padding: 5px 16px; border-radius: 3px; cursor: pointer; transition: background .12s, color .12s;
                }
                .dpgp-seg > button.active { background: var(--brand-experiment, #5865f2); color: #fff; }

                .dpgp-contact { display: flex; align-items: center; gap: 8px; padding: 8px 10px; border-radius: 4px; background: var(--background-tertiary, rgba(0,0,0,.18)); }
                .dpgp-avatar { display: none; }
                .dpgp-contact-info { min-width: 0; flex: 1; }
                .dpgp-contact-name { font-weight: 500; font-size: 13px; }
                .dpgp-contact-meta { font-size: 11px; color: var(--text-muted, #949ba4); word-break: break-all; }

                .dpgp-status { font-size: 12px; min-height: 14px; word-break: break-all; }
                .dpgp-status.ok { color: #3ba55c; }
                .dpgp-status.err { color: #ed4245; }

                .dpgp-chanrow { display: flex; align-items: center; gap: 8px; padding: 7px 10px; border-radius: 4px; background: var(--background-tertiary, rgba(0,0,0,.18)); }
                .dpgp-chanrow .name { flex: 1; word-break: break-all; font-size: 13px; }

                .dpgp-opt { display: flex; align-items: center; justify-content: space-between; gap: 10px; padding: 2px 0; }
                .dpgp-opt-title { font-weight: 500; font-size: 13px; }
                .dpgp-opt-sub { font-size: 12px; color: var(--text-muted, #949ba4); }
                .dpgp-switch { position: relative; width: 36px; height: 20px; flex: none; }
                .dpgp-switch input { opacity: 0; width: 0; height: 0; position: absolute; }
                .dpgp-slider { position: absolute; inset: 0; border-radius: 999px; background: #80848e; transition: background .15s; cursor: pointer; }
                .dpgp-slider::before {
                    content: ""; position: absolute; width: 16px; height: 16px; border-radius: 50%;
                    background: #fff; top: 2px; left: 2px; transition: transform .15s;
                }
                .dpgp-switch input:checked + .dpgp-slider { background: #3ba55c; }
                .dpgp-switch input:checked + .dpgp-slider::before { transform: translateX(16px); }

                .dpgp-muted { font-size: 12px; color: var(--text-muted, #949ba4); line-height: 1.4; }
                .dpgp-foot { font-size: 11px; color: var(--text-muted, #949ba4); text-align: center; padding-top: 2px; }
            `;
        }

        // ---------- settings UI ----------
        getSettingsPanel() {
            const panel = document.createElement("div");
            panel.className = "dpgp-panel";
            this._buildPanel(panel);
            return panel;
        }

        _copy(text, what) {
            try { require("electron").clipboard.writeText(text); }
            catch (_) { try { navigator.clipboard.writeText(text); } catch (_2) {} }
            BdApi.UI.showToast(what + " copied", { type: "success" });
        }

        _confirm(title, text, confirmText, onConfirm, cancelText, onCancel) {
            if (BdApi.UI && typeof BdApi.UI.showConfirmationModal === "function") {
                const opts = { danger: true, confirmText, onConfirm };
                if (cancelText) opts.cancelText = cancelText;
                if (onCancel) opts.onCancel = onCancel;
                BdApi.UI.showConfirmationModal(title, text, opts);
            } else if (window.confirm(title + "\n\n" + text)) {
                onConfirm();
            } else if (onCancel) {
                onCancel();
            }
        }

        async _keyInfo(armored) {
            const key = await this.openpgp.readKey({ armoredKey: armored });
            const a = key.getAlgorithmInfo();
            const algo = a.curve ? "ECC · " + a.curve : a.bits ? "RSA · " + a.bits + "-bit" : a.algorithm;
            return {
                algo,
                fingerprint: key.getFingerprint().toUpperCase().replace(/(.{4})/g, "$1 ").trim(),
                user: key.getUserIDs()[0] || "(none)",
                created: key.getCreationTime().toLocaleDateString(),
            };
        }

        _buildPanel(panel) {
            panel.innerHTML = "";
            const s = this.settings;
            const hasKey = !!(s.privateKey && s.publicKey);

            const el = (tag, cls, props = {}) => {
                const n = document.createElement(tag);
                if (cls) n.className = cls;
                Object.assign(n, props);
                return n;
            };
            const btn = (text, cls, onClick) => {
                const b = el("button", "dpgp-btn" + (cls ? " " + cls : ""), { type: "button", textContent: text });
                b.onclick = onClick;
                return b;
            };
            const labeled = (labelText, node) => {
                const w = el("div", "dpgp-field");
                w.appendChild(el("label", "dpgp-label", { textContent: labelText }));
                w.appendChild(node);
                return w;
            };
            const section = (title, sub) => {
                // All sections start collapsed when settings open.
                const d = el("details", "dpgp-sec");
                const sum = el("summary", "dpgp-sum");
                const tw = el("div", "dpgp-sum-text");
                tw.appendChild(el("div", "dpgp-sum-title", { textContent: title }));
                if (sub) tw.appendChild(el("div", "dpgp-sum-sub", { textContent: sub }));
                sum.appendChild(tw);
                sum.appendChild(el("span", "dpgp-chev", { textContent: "›" }));
                d.appendChild(sum);
                const body = el("div", "dpgp-sec-body");
                d.appendChild(body);
                panel.appendChild(d);
                return body;
            };
            const passInput = (placeholder, value) => {
                const row = el("div", "dpgp-passrow");
                const input = el("input", "dpgp-input", { type: "password", value: value || "", placeholder });
                const eye = btn("show", "secondary eye", () => {
                    const hidden = input.type === "password";
                    input.type = hidden ? "text" : "password";
                    eye.textContent = hidden ? "hide" : "show";
                });
                row.appendChild(input);
                row.appendChild(eye);
                return { row, input };
            };

            // ===== header =====
            const head = el("div", "dpgp-head");
            const ht = el("div", "dpgp-head-text");
            ht.appendChild(el("div", "dpgp-head-title", { textContent: "DiscordPG" }));
            ht.appendChild(el("div", "dpgp-head-sub", { textContent: "end-to-end PGP · v" + config.version }));
            head.appendChild(ht);
            head.appendChild(el("span", "dpgp-pill " + (hasKey ? "ok" : "warn"), { textContent: hasKey ? "Key configured" : "No key yet" }));
            panel.appendChild(head);

            // ===== my identity =====
            const idBody = section("My identity",
                hasKey ? "Your keypair. Share the public half" : "Generate a key below, or import an existing one",
                true);

            const rawWrap = el("div", "dpgp-stack");
            if (hasKey) {
                const grid = el("div", "dpgp-kv");
                const kv = (k, mono) => {
                    grid.appendChild(el("div", "dpgp-kv-k", { textContent: k }));
                    const v = el("div", "dpgp-kv-v" + (mono ? " mono" : ""), { textContent: "…" });
                    grid.appendChild(v);
                    return v;
                };
                const vAlgo = kv("Algorithm"), vFpr = kv("Fingerprint", true), vUid = kv("User ID"), vDate = kv("Created");
                idBody.appendChild(grid);
                if (this.openpgp) {
                    this._keyInfo(s.publicKey).then((i) => {
                        vAlgo.textContent = i.algo;
                        vFpr.textContent = i.fingerprint;
                        vUid.textContent = i.user;
                        vDate.textContent = i.created;
                    }).catch(() => {
                        vAlgo.textContent = vFpr.textContent = vUid.textContent = vDate.textContent = "couldn't parse key";
                    });
                }
                rawWrap.style.display = "none";
            }

            const idRow = el("div", "dpgp-row");
            const copyBtn = btn("Copy public key", "", () => this._copy(s.publicKey, "Public key"));
            if (!s.publicKey) copyBtn.disabled = true;
            idRow.appendChild(copyBtn);
            if (hasKey) {
                idRow.appendChild(btn("Edit / import keys", "secondary", () => {
                    rawWrap.style.display = rawWrap.style.display === "none" ? "" : "none";
                }));
                // Delete the keypair now. The "Delete without revoking" choice in
                // the modal below is itself the confirmation, so this does not open
                // a second dialog.
                const doDelete = () => {
                    s.publicKey = ""; s.privateKey = ""; s.passphrase = ""; s.revocationCertificate = "";
                    this.myUnlockedKey = null;
                    this.save();
                    this._buildPanel(panel);
                };
                // Nudge the user to publish a revocation certificate first, but let
                // them bypass straight to deletion.
                idRow.appendChild(btn("Delete keypair", "danger", () => this._confirm(
                    "Revoke before deleting?",
                    "If this key might be compromised, copy your revocation certificate and post it to your contacts so their clients stop using this key. Copying does not delete your keys; you can delete afterwards.",
                    "Copy revocation certificate",
                    async () => {
                        try {
                            const cert = await this._makeRevocationCert();
                            this._copy(cert, "Revocation certificate");
                            BdApi.UI.showToast("Post it to your contacts, then delete your keypair.", { type: "info", timeout: 8000 });
                            this._buildPanel(panel);
                        } catch (e) {
                            BdApi.UI.showToast("Couldn't make certificate: " + e.message, { type: "error" });
                        }
                    },
                    "Delete without revoking",
                    doDelete
                )));
            }
            idBody.appendChild(idRow);

            const pub = el("textarea", "dpgp-input mono", { value: s.publicKey, spellcheck: false, placeholder: "-----BEGIN PGP PUBLIC KEY BLOCK-----" });
            const priv = el("textarea", "dpgp-input mono", { value: s.privateKey, spellcheck: false, placeholder: "-----BEGIN PGP PRIVATE KEY BLOCK-----" });
            const myPass = passInput("Passphrase that unlocks your private key", s.passphrase);
            rawWrap.appendChild(labeled("Public key (armored)", pub));
            rawWrap.appendChild(labeled("Private key (armored)", priv));
            rawWrap.appendChild(labeled("Passphrase", myPass.row));
            // Revocation certificate: shown below the private key. Publish this if
            // your key is ever compromised so contacts stop encrypting to it.
            const revField = el("div", "dpgp-field");
            revField.appendChild(el("label", "dpgp-label", { textContent: "Revocation certificate" }));
            const revArea = el("textarea", "dpgp-input mono", { value: s.revocationCertificate, spellcheck: false, readOnly: true, placeholder: "Generate below, then keep it somewhere safe." });
            revField.appendChild(revArea);
            const revRow = el("div", "dpgp-row");
            if (s.revocationCertificate) {
                revRow.appendChild(btn("Copy revocation certificate", "secondary", () => this._copy(s.revocationCertificate, "Revocation certificate")));
            } else if (hasKey) {
                const genRevBtn = btn("Generate revocation certificate", "secondary", async () => {
                    genRevBtn.disabled = true; genRevBtn.textContent = "Generating…";
                    try { await this._makeRevocationCert(); this._buildPanel(panel); }
                    catch (e) { BdApi.UI.showToast("Failed: " + e.message, { type: "error" }); genRevBtn.disabled = false; genRevBtn.textContent = "Generate revocation certificate"; }
                });
                revRow.appendChild(genRevBtn);
            }
            revField.appendChild(revRow);
            revField.appendChild(el("div", "dpgp-muted", { textContent: "Posting this certificate revokes your key for everyone running the plugin. Keep it private until then." }));
            rawWrap.appendChild(revField);

            const saveRow = el("div", "dpgp-row");
            saveRow.appendChild(btn("Save keys", "", () => {
                const newPriv = priv.value.trim();
                // A pasted/changed private key invalidates any cached revocation cert.
                if (newPriv !== s.privateKey) s.revocationCertificate = "";
                s.publicKey = pub.value.trim();
                s.privateKey = newPriv;
                s.passphrase = myPass.input.value;
                this.myUnlockedKey = null;
                this.save();
                BdApi.UI.showToast("Keys saved", { type: "success" });
                this._buildPanel(panel);
            }));
            rawWrap.appendChild(saveRow);
            idBody.appendChild(rawWrap);

            // ===== generate =====
            const genBody = section("Generate a new keypair", "ECC (recommended) or RSA; output is armored", !hasKey);

            const nameGrid = el("div", "dpgp-grid2");
            const genName = el("input", "dpgp-input", { type: "text", placeholder: "Alice (optional)" });
            const genEmail = el("input", "dpgp-input", { type: "text", placeholder: "alice@example.com (optional)" });
            nameGrid.appendChild(labeled("Name", genName));
            nameGrid.appendChild(labeled("Email", genEmail));
            genBody.appendChild(nameGrid);

            const genPass = passInput("Recommended; protects the private key at rest", "");
            genBody.appendChild(labeled("Passphrase for the new key", genPass.row));

            const seg = el("div", "dpgp-seg");
            const bEcc = el("button", "active", { type: "button", textContent: "ECC" });
            const bRsa = el("button", "", { type: "button", textContent: "RSA" });
            seg.appendChild(bEcc);
            seg.appendChild(bRsa);
            genBody.appendChild(labeled("Algorithm", seg));

            const genCurve = el("select", "dpgp-input");
            for (const c of ["curve25519", "ed25519", "nistP256", "nistP384", "nistP521",
                             "brainpoolP256r1", "brainpoolP384r1", "brainpoolP512r1", "secp256k1"]) {
                genCurve.appendChild(el("option", null, { value: c, textContent: c + (c === "curve25519" ? "  (recommended)" : "") }));
            }
            const curveField = labeled("Curve", genCurve);
            const genRsa = el("select", "dpgp-input");
            for (const b of [2048, 3072, 4096]) {
                genRsa.appendChild(el("option", null, { value: String(b), textContent: b + " bits" + (b === 4096 ? "  (recommended)" : "") }));
            }
            genRsa.value = "4096";
            const rsaField = labeled("Key size", genRsa);
            genBody.appendChild(curveField);
            genBody.appendChild(rsaField);

            let algoType = "ecc";
            const setAlgo = (t) => {
                algoType = t;
                bEcc.className = t === "ecc" ? "active" : "";
                bRsa.className = t === "rsa" ? "active" : "";
                curveField.style.display = t === "ecc" ? "" : "none";
                rsaField.style.display = t === "rsa" ? "" : "none";
            };
            bEcc.onclick = () => setAlgo("ecc");
            bRsa.onclick = () => setAlgo("rsa");
            setAlgo("ecc");

            const genBtn = btn("Generate keypair", "", async () => {
                if (!this.openpgp) return BdApi.UI.showToast("OpenPGP not loaded yet", { type: "error" });
                genBtn.disabled = true;
                genBtn.textContent = algoType === "rsa" ? "Generating… (RSA can take a moment)" : "Generating…";
                try {
                    // Build the user ID conditionally: OpenPGP rejects malformed
                    // emails (e.g. a domain with no dot), so only include fields
                    // the user actually provided.
                    const uid = {};
                    const nm = genName.value.trim();
                    const em = genEmail.value.trim();
                    if (nm) uid.name = nm;
                    if (em) uid.email = em;
                    if (!nm && !em) uid.name = "Discord User";
                    const genOpts = { userIDs: [uid], passphrase: genPass.input.value || "", format: "armored" };
                    if (algoType === "rsa") {
                        genOpts.type = "rsa";
                        genOpts.rsaBits = parseInt(genRsa.value, 10);
                    } else {
                        genOpts.type = "ecc";
                        genOpts.curve = genCurve.value;
                    }
                    const { privateKey, publicKey, revocationCertificate } = await this.openpgp.generateKey(genOpts);
                    s.publicKey = publicKey.trim();
                    s.privateKey = privateKey.trim();
                    s.passphrase = genPass.input.value || "";
                    s.revocationCertificate = (revocationCertificate || "").trim();
                    this.myUnlockedKey = null;
                    this.save();
                    BdApi.UI.showToast("New keypair generated & saved", { type: "success" });
                    this._buildPanel(panel);
                } catch (e) {
                    BdApi.UI.showToast("Generate failed: " + e.message, { type: "error" });
                    genBtn.disabled = false;
                    genBtn.textContent = "Generate keypair";
                }
            });
            genBody.appendChild(genBtn);

            // ===== contacts =====
            const contactIds = Object.keys(s.contacts);
            const conBody = section("Contacts",
                contactIds.length ? contactIds.length + " public key" + (contactIds.length === 1 ? "" : "s") + " stored" : "Add your friends' public keys",
                hasKey && !contactIds.length);

            // Add/edit form elements are created up front so per-card Edit
            // buttons can reference them; they are appended below the cards.
            let editingId = null; // contact key currently being edited, or null
            const cLabel = el("input", "dpgp-input", { type: "text", placeholder: "their Discord username, e.g. bob" });
            const cId = el("input", "dpgp-input mono", { type: "text", placeholder: "blank = resolve from username" });
            const cKey = el("textarea", "dpgp-input mono", { spellcheck: false, placeholder: "-----BEGIN PGP PUBLIC KEY BLOCK-----" });
            const status = el("div", "dpgp-status");
            const addBtn = btn("Add contact", "", async () => {
                let id = cId.value.trim();
                const label = cLabel.value.trim();
                const key = cKey.value.trim();
                if (!key) return BdApi.UI.showToast("Public key is required", { type: "error" });
                if (!id && !label) return BdApi.UI.showToast("Enter a label (their username) or a User ID", { type: "error" });
                if (this.openpgp) {
                    try { await this.openpgp.readKey({ armoredKey: key }); }
                    catch (e) { return BdApi.UI.showToast("Invalid public key: " + e.message, { type: "error" }); }
                }
                if (!id) {
                    // Resolve the ID from Discord's cached users by username /
                    // display name; otherwise store a name-keyed contact that
                    // self-heals to the real ID on first mention or DM.
                    const users = this.UserStore && this.UserStore.getUsers ? this.UserStore.getUsers() : null;
                    if (users) {
                        const lower = label.toLowerCase();
                        const hit = Object.values(users).find((u) =>
                            (u.username && u.username.toLowerCase() === lower) ||
                            (u.globalName && String(u.globalName).toLowerCase() === lower));
                        if (hit) id = String(hit.id);
                    }
                    if (!id) id = "name:" + label.toLowerCase();
                }
                // When editing, replace the original entry even if its key changed.
                if (editingId && editingId !== id) delete s.contacts[editingId];
                s.contacts[id] = { label, publicKey: key };
                this.save();
                BdApi.UI.showToast(
                    (editingId ? "Contact updated" : "Contact saved")
                    + (id.startsWith("name:") ? ". ID will resolve on first mention/DM" : " (ID " + id + ")"),
                    { type: "success" });
                this._buildPanel(panel);
            });
            const cancelBtn = btn("Cancel", "secondary", () => {
                editingId = null;
                cLabel.value = cId.value = cKey.value = "";
                status.textContent = "";
                status.className = "dpgp-status";
                addBtn.textContent = "Add contact";
                cancelBtn.style.display = "none";
            });
            cancelBtn.style.display = "none";

            if (!contactIds.length) {
                conBody.appendChild(el("div", "dpgp-muted", { textContent:
                    "No contacts yet. Paste a friend's public key below. Easiest: set the label to their exact Discord username and leave the User ID blank; the plugin resolves the ID itself. (Manual ID: Developer Mode → right-click user → Copy User ID.)" }));
            }
            for (const id of contactIds) {
                const c = s.contacts[id];
                const card = el("div", "dpgp-contact" + (c.revoked ? " dpgp-revoked" : ""));
                const info = el("div", "dpgp-contact-info");
                const nameEl = el("div", "dpgp-contact-name", { textContent: c.label || "Unnamed contact" });
                if (c.revoked) nameEl.appendChild(el("span", "dpgp-revoked-tag", { textContent: "REVOKED" }));
                info.appendChild(nameEl);
                const idText = id.startsWith("name:") ? "ID pending, matches by username" : "ID " + id;
                const meta = el("div", "dpgp-contact-meta mono", { textContent: idText });
                info.appendChild(meta);
                card.appendChild(info);
                if (this.openpgp) {
                    this._keyInfo(c.publicKey)
                        .then((i) => { meta.textContent = idText + "  ·  " + i.algo + "  ·  " + i.fingerprint; })
                        .catch(() => { meta.textContent = idText + "  ·  ⚠ unreadable key"; });
                }
                if (c.revoked) {
                    card.appendChild(btn("Clear flag", "secondary eye", () => {
                        delete c.revoked; this.save(); this._buildPanel(panel);
                    }));
                }
                card.appendChild(btn("Edit", "secondary eye", () => {
                    editingId = id;
                    cLabel.value = c.label || "";
                    cId.value = id.startsWith("name:") ? "" : id;
                    cKey.value = c.publicKey || "";
                    cKey.oninput(); // refresh the live key-validation line
                    addBtn.textContent = "Save changes";
                    cancelBtn.style.display = "";
                    if (cLabel.scrollIntoView) cLabel.scrollIntoView({ behavior: "smooth", block: "center" });
                }));
                card.appendChild(btn("Copy", "secondary eye", () => this._copy(c.publicKey, "Contact's public key")));
                card.appendChild(btn("Remove", "danger", () => {
                    delete s.contacts[id];
                    this.save();
                    this._buildPanel(panel);
                }));
                conBody.appendChild(card);
            }

            const addGrid = el("div", "dpgp-grid2");
            addGrid.appendChild(labeled("Label / username", cLabel));
            addGrid.appendChild(labeled("User ID (optional)", cId));
            conBody.appendChild(addGrid);
            conBody.appendChild(labeled("Their public key (armored)", cKey));
            conBody.appendChild(status);
            let vTimer = null;
            cKey.oninput = () => {
                clearTimeout(vTimer);
                const v = cKey.value.trim();
                if (!v) { status.textContent = ""; status.className = "dpgp-status"; return; }
                vTimer = setTimeout(() => {
                    if (!this.openpgp) return;
                    this._keyInfo(v)
                        .then((i) => { status.textContent = "✓ Valid key: " + i.algo + " · " + i.fingerprint; status.className = "dpgp-status ok"; })
                        .catch(() => { status.textContent = "✗ Not a valid public key"; status.className = "dpgp-status err"; });
                }, 300);
            };

            const formRow = el("div", "dpgp-row");
            formRow.appendChild(addBtn);
            formRow.appendChild(cancelBtn);
            conBody.appendChild(formRow);

            // ===== encrypted channels =====
            const chanIds = Object.keys(s.enabledChannels);
            const chBody = section("Encrypted channels", chanIds.length ? chanIds.length + " enabled" : "None enabled", false);
            if (!chanIds.length) {
                chBody.appendChild(el("div", "dpgp-muted", { textContent:
                    "Type  /pgp on  in any channel to start encrypting it. It will show up here." }));
            }
            for (const id of chanIds) {
                const ch = this.ChannelStore && this.ChannelStore.getChannel(id);
                const name = ch ? (ch.name ? "#" + ch.name : "Direct message · " + id) : "Channel " + id;
                const row = el("div", "dpgp-chanrow");
                row.appendChild(el("div", "name", { textContent: name }));
                row.appendChild(btn("Disable", "secondary", () => {
                    delete s.enabledChannels[id];
                    this.save();
                    this._decorateChannelList();
                    this._buildPanel(panel);
                }));
                chBody.appendChild(row);
            }

            // ===== options =====
            const mkSwitch = (parent, key, title, sub) => {
                const row = el("div", "dpgp-opt");
                const tw = el("div");
                tw.appendChild(el("div", "dpgp-opt-title", { textContent: title }));
                tw.appendChild(el("div", "dpgp-opt-sub", { textContent: sub }));
                row.appendChild(tw);
                const lab = el("label", "dpgp-switch");
                const cb = el("input", null, { type: "checkbox", checked: !!s[key] });
                cb.onchange = () => { s[key] = cb.checked; this.save(); };
                lab.appendChild(cb);
                lab.appendChild(el("span", "dpgp-slider"));
                row.appendChild(lab);
                parent.appendChild(row);
            };

            const encBody = section("Encryption", "Signing and decryption", false);
            mkSwitch(encBody, "signMessages", "Sign outgoing messages", "Lets recipients holding your public key verify it was really you");
            mkSwitch(encBody, "autoDecrypt", "Auto-decrypt incoming messages", "Replaces PGP blocks in chat with the decrypted text and a badge");

            const miscBody = section("Miscellaneous", "Badges and rich content", false);
            mkSwitch(miscBody, "minimalBadges", "Minimal encryption signs", "Just a plain lock icon on messages, no color or PGP text");
            mkSwitch(miscBody, "richContent", "Rich content in decrypted messages (opt-in)", "Render emojis, clickable links, and media in decrypted text. Off = plain text only, nothing is ever fetched");
            mkSwitch(miscBody, "renderEmojis", "Render custom emojis", "Shows <:emoji:> images, fetched from Discord's CDN. Needs rich content on");
            mkSwitch(miscBody, "autoLoadMedia", "Auto-load images & GIFs (opsec risk)", "Fetches linked media without asking, revealing your IP and read-time to the host. Off = click-to-load button. Needs rich content on");

            panel.appendChild(el("div", "dpgp-foot", { textContent:
                "Commands: /pgp on · /pgp off · /pgp status. Keys are stored unencrypted on this machine." }));
        }
    }

    return DiscordPG;
})();
