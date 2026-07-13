/**
 * @name DiscordPG
 * @author topklc
 * @authorId 0
 * @version 1.7.4
 * @description End-to-end PGP encryption for Discord messages using OpenPGP.js. Generate/import keys, encrypt to your contacts, and auto-decrypt incoming PGP blocks inline. Use "/pgp on" or "/pgp off" in a channel to toggle encryption.
 * @website https://github.com/
 * @source https://github.com/
 */

/*
 * SECURITY NOTES — read before trusting this with anything serious:
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
        version: "1.7.4",
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
        contacts: {},          // { [userId]: { label, publicKey } }
        enabledChannels: {},   // { [channelId]: true }
        signMessages: true,
        autoDecrypt: true,
        minimalBadges: false,  // plain 🔓/🔒/🔑 on messages instead of the colored PGP tag
        richContent: false,    // master opt-in: render emojis/links/media in decrypted messages
        renderEmojis: true,    // custom Discord emoji (loads from Discord's CDN) — needs richContent
        autoLoadMedia: false,  // auto-fetch image/GIF links (leaks IP to host!) — needs richContent
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
                // Best-effort only — the evaluation fallback below doesn't need it,
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
            // BetterDiscord's require shim can't load arbitrary files — it may return
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

            // 1) BetterDiscord's own networking — Node-backed, bypasses Discord's CSP.
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

        _recipientPublicKeys(channelId) {
            const ch = this.ChannelStore && this.ChannelStore.getChannel(channelId);
            const ids = (ch && ch.recipients) || [];
            let keys = ids
                .map((id) => {
                    // _resolveContactId also matches username-only contacts and
                    // heals their stored ID, so DMs work without a manual ID.
                    const rid = this._resolveContactId(id);
                    const c = rid && this.settings.contacts[rid];
                    return c && c.publicKey;
                })
                .filter(Boolean);
            // Fallback (e.g. guild channels have no recipients list): encrypt to every known contact.
            if (!keys.length) {
                keys = Object.values(this.settings.contacts).map((c) => c.publicKey).filter(Boolean);
            }
            return keys;
        }

        async encryptForChannel(channelId, text) {
            // @mention targeting: if the message mentions users, encrypt ONLY to
            // those users' saved keys (plus yourself), overriding the channel's
            // normal recipient selection. Two forms are recognised:
            //   1. real Discord mentions — raw content contains <@id> / <@!id>
            //   2. plain-text "@label" matching a saved contact's label, for when
            //      Discord doesn't convert the @ (no autocomplete pick, DMs, etc.)
            const rawMentionIds = [...new Set([...text.matchAll(/<@!?(\d+)>/g)].map((m) => m[1]))];
            // Real mentions must all resolve to saved keys — fail closed, the
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
                if (!c.label || !c.publicKey || mentionIds.includes(id)) continue;
                const esc = c.label.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
                // "@label" not immediately preceded/followed by a word character,
                // so "me@bobmail.com" doesn't target the contact "bob".
                if (new RegExp("(^|[^a-z0-9_])@" + esc + "(?![a-z0-9_])", "i").test(text)) {
                    mentionIds.push(id);
                }
            }
            let armoredRecips;
            if (mentionIds.length) {
                armoredRecips = mentionIds.map((id) => this.settings.contacts[id].publicKey);
                const names = mentionIds.map((id) => this.settings.contacts[id].label || id).join(", ");
                BdApi.UI.showToast("🔒 Encrypted only for: " + names + " (+ you)", { type: "info" });
            } else {
                armoredRecips = this._recipientPublicKeys(channelId);
            }
            const encryptionKeys = [];
            for (const a of armoredRecips) {
                try { encryptionKeys.push(await this.openpgp.readKey({ armoredKey: a })); } catch (_) {}
            }
            // Always encrypt to ourselves so we can read our own sent messages.
            if (this.settings.publicKey) {
                try { encryptionKeys.push(await this.openpgp.readKey({ armoredKey: this.settings.publicKey })); } catch (_) {}
            }
            if (!encryptionKeys.length) {
                throw new Error("No recipient public key. Add a contact key in settings.");
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
            if (matches.length !== 1) return null; // none or ambiguous — don't guess
            const [oldId, contact] = matches[0];
            delete this.settings.contacts[oldId];
            this.settings.contacts[userId] = contact;
            this.save();
            BdApi.UI.showToast('PGP: contact "' + contact.label + '" matched by name — saved ID corrected to ' + userId, { type: "info" });
            return userId;
        }

        _describeUser(userId) {
            const u = this.UserStore && this.UserStore.getUser && this.UserStore.getUser(userId);
            return u && u.username ? "@" + u.username + " (" + userId + ")" : userId;
        }

        // If the message BEGINS with a mention (or @label) of a saved contact,
        // return that contact's id — used to trigger targeted encryption even
        // in channels where PGP isn't enabled.
        _leadingTarget(text) {
            const t = (text || "").trimStart();
            const m = t.match(/^<@!?(\d+)>/);
            if (m) {
                return this._resolveContactId(m[1]); // null for non-contacts → normal send
            }
            for (const [id, c] of Object.entries(this.settings.contacts)) {
                if (!c.label || !c.publicKey) continue;
                const esc = c.label.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
                if (new RegExp("^@" + esc + "(?![a-z0-9_])", "i").test(t)) return id;
            }
            return null;
        }

        _patchSend() {
            const self = this;
            BdApi.Patcher.instead(config.name, this.MessageActions, "sendMessage", (_thisObj, args, original) => {
                const [channelId, message] = args;
                const content = (message && message.content) || "";

                // ".pgp" works alongside "/pgp" because Discord's slash-command
                // picker can swallow unknown /commands before they're sent.
                const lead = content.trimStart();
                if (lead.startsWith("/pgp") || lead.startsWith(".pgp")) {
                    self._handleCommand(channelId, content.trim());
                    return Promise.resolve({}); // swallow the command; don't send it
                }

                // Encrypt when the channel is enabled, OR when the message leads
                // with @<saved contact> (explicit one-off targeted encryption).
                const encryptHere = self.ready &&
                    (self.settings.enabledChannels[channelId] || self._leadingTarget(content));
                if (!encryptHere) {
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

        _handleCommand(channelId, content) {
            const sub = (content.split(/\s+/)[1] || "").toLowerCase();
            if (sub === "on") {
                this.settings.enabledChannels[channelId] = true; this.save();
                this._decorateChannelList();
                BdApi.UI.showToast("🔒 PGP encryption ON for this channel", { type: "success" });
            } else if (sub === "off") {
                delete this.settings.enabledChannels[channelId]; this.save();
                this._decorateChannelList();
                BdApi.UI.showToast("🔓 PGP encryption OFF for this channel", { type: "info" });
            } else if (sub === "status") {
                const on = !!this.settings.enabledChannels[channelId];
                BdApi.UI.showToast("PGP is " + (on ? "ON" : "OFF") + " here", { type: "info" });
            } else if (sub === "debug") {
                const s = this.settings;
                const info = "ready=" + this.ready
                    + " | openpgp=" + !!this.openpgp
                    + " | hasKey=" + !!(s.privateKey && s.publicKey)
                    + " | contacts=" + Object.keys(s.contacts).length
                    + " | thisChannelEnabled=" + !!s.enabledChannels[channelId]
                    + " | enabledChannels=" + Object.keys(s.enabledChannels).length;
                BdApi.UI.showToast("PGP debug: " + info, { type: "info", timeout: 10000 });
                console.log("[DiscordPG] debug:", info, "| contact ids:", Object.keys(s.contacts),
                    "| labels:", Object.values(s.contacts).map((c) => c.label));
            } else {
                BdApi.UI.showToast("Commands: /pgp on | off | status | debug  (also works as .pgp)", { type: "info" });
            }
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
                if (enabled && !existing) {
                    const b = document.createElement("span");
                    b.className = "pgp-chan-badge";
                    b.textContent = "🔒";
                    b.title = "PGP encryption enabled";
                    // Prefer sitting right after the channel name; fall back to the link.
                    const name = a.querySelector('[class*="name"]');
                    (name || a).appendChild(b);
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
                el.dataset.pgpDone = "1"; // either way, processed — skip forever
                if (pubBlock) this._renderKeyOffer(el, pubBlock[0], channelId, messageId);
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
                : (result.ok ? "🔓 PGP" : "🔒 PGP — can't decrypt");
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
        // click-to-load unless autoLoadMedia is on — auto-fetching remote URLs
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
                    // Blocked by CSP or dead link — degrade to a plain link.
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
            load.textContent = "🖼 Load media" + (host ? " — reveals your IP to " + host : "");
            load.onclick = showImage;
            wrap.appendChild(load);
            return wrap;
        }

        // Render an inline "save contact" offer for a pasted public key.
        _renderKeyOffer(el, armored, channelId, messageId) {
            el.innerHTML = "";
            const badge = document.createElement("span");
            badge.className = "pgp-badge pgp-key-badge" + (this.settings.minimalBadges ? " pgp-min" : "");
            badge.textContent = this.settings.minimalBadges ? "🔑" : "🔑 PGP public key";
            badge.title = "PGP public key — click to show the raw key";
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
                    display: inline-block; margin-left: 5px; font-size: 10px;
                    vertical-align: middle; line-height: 1; opacity: .85;
                }
                .pgp-key-badge { background: rgba(88,101,242,.2); color: #7983f5; }
                .pgp-badge.pgp-min { background: none; color: inherit; padding: 0; font-weight: 400; }
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

        _confirm(title, text, confirmText, onConfirm) {
            if (BdApi.UI && typeof BdApi.UI.showConfirmationModal === "function") {
                BdApi.UI.showConfirmationModal(title, text, { danger: true, confirmText, onConfirm });
            } else if (window.confirm(title + "\n\n" + text)) {
                onConfirm();
            }
        }

        async _keyInfo(armored) {
            const key = await this.openpgp.readKey({ armoredKey: armored });
            const a = key.getAlgorithmInfo();
            const algo = a.curve ? "ECC · " + a.curve : a.bits ? "RSA · " + a.bits + "-bit" : a.algorithm;
            return {
                algo,
                fingerprint: key.getFingerprint().toUpperCase().replace(/(.{4})/g, "$1 ").trim(),
                user: key.getUserIDs()[0] || "—",
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
            const section = (title, sub, open) => {
                const d = el("details", "dpgp-sec");
                if (open) d.open = true;
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
                hasKey ? "Your keypair — share the public half" : "Generate a key below, or import an existing one",
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
                idRow.appendChild(btn("Delete keypair", "danger", () => this._confirm(
                    "Delete keypair?",
                    "This removes your keys and passphrase from this machine. Messages encrypted to this key become unreadable unless you have a backup.",
                    "Delete",
                    () => {
                        s.publicKey = ""; s.privateKey = ""; s.passphrase = "";
                        this.myUnlockedKey = null;
                        this.save();
                        this._buildPanel(panel);
                    }
                )));
            }
            idBody.appendChild(idRow);

            const pub = el("textarea", "dpgp-input mono", { value: s.publicKey, spellcheck: false, placeholder: "-----BEGIN PGP PUBLIC KEY BLOCK-----" });
            const priv = el("textarea", "dpgp-input mono", { value: s.privateKey, spellcheck: false, placeholder: "-----BEGIN PGP PRIVATE KEY BLOCK-----" });
            const myPass = passInput("Passphrase that unlocks your private key", s.passphrase);
            rawWrap.appendChild(labeled("Public key (armored)", pub));
            rawWrap.appendChild(labeled("Private key (armored)", priv));
            rawWrap.appendChild(labeled("Passphrase", myPass.row));
            const saveRow = el("div", "dpgp-row");
            saveRow.appendChild(btn("Save keys", "", () => {
                s.publicKey = pub.value.trim();
                s.privateKey = priv.value.trim();
                s.passphrase = myPass.input.value;
                this.myUnlockedKey = null;
                this.save();
                BdApi.UI.showToast("Keys saved", { type: "success" });
                this._buildPanel(panel);
            }));
            rawWrap.appendChild(saveRow);
            idBody.appendChild(rawWrap);

            // ===== generate =====
            const genBody = section("Generate a new keypair", "ECC (recommended) or RSA — output is armored", !hasKey);

            const nameGrid = el("div", "dpgp-grid2");
            const genName = el("input", "dpgp-input", { type: "text", placeholder: "Alice (optional)" });
            const genEmail = el("input", "dpgp-input", { type: "text", placeholder: "alice@example.com (optional)" });
            nameGrid.appendChild(labeled("Name", genName));
            nameGrid.appendChild(labeled("Email", genEmail));
            genBody.appendChild(nameGrid);

            const genPass = passInput("Recommended — protects the private key at rest", "");
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
                    const { privateKey, publicKey } = await this.openpgp.generateKey(genOpts);
                    s.publicKey = publicKey.trim();
                    s.privateKey = privateKey.trim();
                    s.passphrase = genPass.input.value || "";
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
                    + (id.startsWith("name:") ? " — ID will resolve on first mention/DM" : " (ID " + id + ")"),
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
                    "No contacts yet — paste a friend's public key below. Easiest: set the label to their exact Discord username and leave the User ID blank; the plugin resolves the ID itself. (Manual ID: Developer Mode → right-click user → Copy User ID.)" }));
            }
            for (const id of contactIds) {
                const c = s.contacts[id];
                const card = el("div", "dpgp-contact");
                const info = el("div", "dpgp-contact-info");
                info.appendChild(el("div", "dpgp-contact-name", { textContent: c.label || "Unnamed contact" }));
                const idText = id.startsWith("name:") ? "ID pending — matches by username" : "ID " + id;
                const meta = el("div", "dpgp-contact-meta mono", { textContent: idText });
                info.appendChild(meta);
                card.appendChild(info);
                if (this.openpgp) {
                    this._keyInfo(c.publicKey)
                        .then((i) => { meta.textContent = idText + "  ·  " + i.algo + "  ·  " + i.fingerprint; })
                        .catch(() => { meta.textContent = idText + "  ·  ⚠ unreadable key"; });
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
                        .then((i) => { status.textContent = "✓ Valid key — " + i.algo + " · " + i.fingerprint; status.className = "dpgp-status ok"; })
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
            const optBody = section("Options", "Signing & decryption behaviour", false);
            const mkSwitch = (key, title, sub) => {
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
                optBody.appendChild(row);
            };
            mkSwitch("signMessages", "Sign outgoing messages", "Lets recipients holding your public key verify it was really you");
            mkSwitch("autoDecrypt", "Auto-decrypt incoming messages", "Replaces PGP blocks in chat with the decrypted text and a badge");
            mkSwitch("minimalBadges", "Minimal encryption signs", "Just a plain lock icon on messages — no color, no PGP text");
            mkSwitch("richContent", "Rich content in decrypted messages (opt-in)", "Render emojis, clickable links, and media in decrypted text. Off = plain text only, nothing is ever fetched");
            mkSwitch("renderEmojis", "└ Render custom emojis", "Shows <:emoji:> images — fetched from Discord's CDN. Needs rich content on");
            mkSwitch("autoLoadMedia", "└ Auto-load images & GIFs (opsec risk)", "Fetches linked media without asking — reveals your IP and read-time to the host. Off = click-to-load button. Needs rich content on");

            panel.appendChild(el("div", "dpgp-foot", { textContent:
                "Commands: /pgp on · /pgp off · /pgp status — keys are stored unencrypted on this machine." }));
        }
    }

    return DiscordPG;
})();
