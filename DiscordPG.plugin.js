/**
 * @name DiscordPG
 * @author topklc
 * @authorId 0
 * @version 1.25.0
 * @description End-to-end PGP encryption for Discord, built on OpenPGP.js. Generate ECC or RSA keys, encrypt to per-channel groups or specific @mentioned contacts, and auto-decrypt and signature-verify incoming messages inline. Includes a contact keyring, key revocation, and /pgp slash commands.
 * @website https://github.com/topklc/DiscordPG
 * @source https://github.com/topklc/DiscordPG/blob/main/DiscordPG.plugin.js
 * @updateUrl https://raw.githubusercontent.com/topklc/DiscordPG/main/DiscordPG.plugin.js
 */

/*
 * DiscordPG - end-to-end PGP encryption for Discord, built on OpenPGP.js v5.
 *
 * Overview
 *   Sending    A patch on MessageActions.sendMessage / editMessage encrypts
 *              outgoing text on channels the user has enabled. It fails closed:
 *              if encryption cannot complete, nothing is sent.
 *   Receiving  A MutationObserver scans rendered messages, decrypts armored PGP
 *              blocks in place, verifies signatures against the message author's
 *              saved key, and offers to save public keys / apply revocations.
 *   Identity   Keys and contacts live in this.settings, persisted via BdApi.Data.
 *   Commands   /pgp-* native slash commands (BetterDiscord 1.13+) and a typed
 *              ".pgp <sub>" fallback share one dispatcher (_runVerb).
 *
 * Security: message content is end-to-end encrypted. The private key is
 * protected at rest by its passphrase, which is held in memory only (unlock
 * once per session) unless "Remember on this device" is enabled; a key with no
 * passphrase is stored unprotected. Metadata is not hidden, and trust is TOFU
 * (verify fingerprints out of band). See the README for details.
 */

module.exports = (() => {

    const config = {
        name: "DiscordPG",
        version: "1.25.0",
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
        passphrase: "",            // only persisted when rememberPassphrase is on
        rememberPassphrase: false, // opt-in: store the passphrase on disk (less secure)
        revocationCertificate: "", // armored cert to publish if this key is compromised
        contacts: {},          // { [userId]: { label, publicKey, revoked? } }
        enabledChannels: {},   // { [channelId]: true }
        groups: {},            // { [channelId]: [contactId, ...] } local recipient set per channel
        signMessages: true,
        autoDecrypt: true,
        clydeReplies: true,    // native /pgp-... commands reply with a private bot message; off = small toast
        richContent: false,    // master opt-in: render emojis/links/media in decrypted messages
        renderEmojis: true,    // custom Discord emoji (loads from Discord's CDN); needs richContent
        autoLoadMedia: false,  // auto-fetch image/GIF links (leaks IP to host!); needs richContent
    };

    class DiscordPG {
        getName() { return config.name; }
        getAuthor() { return config.author; }
        getVersion() { return config.version; }
        getDescription() {
            return "End-to-end PGP encryption for Discord: encrypt to contacts and groups, "
                + "auto-decrypt and verify incoming messages, manage keys, and revoke.";
        }

        constructor() {
            // Own copies of the nested objects so they are never shared with the
            // module-level DEFAULTS (a shallow Object.assign would alias them).
            this.settings = Object.assign({}, DEFAULTS, { contacts: {}, enabledChannels: {}, groups: {} });
            this.openpgp = null;
            this.decryptCache = new Map();  // armoredCiphertext -> { ok: boolean, text: string }
            this.myUnlockedKey = null;      // cached unlocked private key object (memory only)
            this.sessionPassphrase = null;  // passphrase held for this session, never written to disk
            this._unlockPromise = null;     // in-flight passphrase prompt (serializes concurrent unlocks)
            this._unlockDismissed = false;  // user cancelled the unlock prompt this session
            this._closeUnlockModal = null;  // closes the open unlock modal, if any
            this.observer = null;
            this._scanScheduled = false;
            this.ready = false;
        }

        // ---------- persistence ----------
        load() {
            let saved = BdApi.Data.load(config.name, "settings");
            // Migrate from the old plugin name ONLY when nothing is saved under
            // the current name yet. Keying on privateKey re-ran this every time
            // the key was empty (after /pgp revoke or Delete keypair), which
            // resurrected the deleted key and clobbered newer settings.
            if (saved == null) {
                const legacy = BdApi.Data.load("DiscordPGP", "settings");
                if (legacy) {
                    saved = legacy;
                    BdApi.Data.save(config.name, "settings", legacy);
                }
            }
            saved = saved || {};
            const next = Object.assign({}, DEFAULTS, saved);
            // Fresh copies of nested maps (never alias DEFAULTS or the stored blob).
            next.contacts = Object.assign({}, saved.contacts || {});
            next.enabledChannels = Object.assign({}, saved.enabledChannels || {});
            next.groups = Object.assign({}, saved.groups || {});
            // Mutate the existing settings object in place so a panel opened
            // before a reload keeps pointing at the live settings.
            for (const k of Object.keys(this.settings)) delete this.settings[k];
            Object.assign(this.settings, next);
            // Security migration: a passphrase stored by an older version (or with
            // "remember" off) is moved into memory for this session and wiped from
            // disk, so the private key is no longer decryptable at rest. The user
            // is prompted to unlock again next session.
            if (this.settings.passphrase && !this.settings.rememberPassphrase) {
                this.sessionPassphrase = this.settings.passphrase;
                this.settings.passphrase = "";
                this.save();
            }
        }
        save() {
            BdApi.Data.save(config.name, "settings", this.settings);
        }

        // ---------- lifecycle ----------
        start() {
            this._running = true;
            this.load();
            BdApi.DOM.addStyle(config.name, this._css());
            // Async init so we can download + require OpenPGP before patching.
            this._init().catch((e) => {
                console.error("[DiscordPG] init failed:", e);
                BdApi.UI.showToast("DiscordPG failed to start: " + e.message, { type: "error" });
            });
        }

        stop() {
            this._running = false;
            this.ready = false;
            this._unregisterCommands();
            BdApi.Patcher.unpatchAll(config.name);
            this._sendPatched = false;
            BdApi.DOM.removeStyle(config.name);
            if (this.observer) { this.observer.disconnect(); this.observer = null; }
            clearTimeout(this._scanTimer); this._scanScheduled = false;
            this._teardownDecorations();
            if (this._closeUnlockModal) this._closeUnlockModal();
            this.myUnlockedKey = null; this.sessionPassphrase = null;
            this._unlockPromise = null; this._unlockDismissed = false;
            this.decryptCache.clear();
        }

        async _init() {
            // Guard against a stop() (or reload) landing while we await the
            // OpenPGP download: a stale _init must not re-patch/re-register.
            const gen = (this._initGen = (this._initGen || 0) + 1);

            this.ChannelStore = BdApi.Webpack.getStore("ChannelStore");
            this.MessageStore = BdApi.Webpack.getStore("MessageStore");
            this.UserStore = BdApi.Webpack.getStore("UserStore");
            this.MessageActions = BdApi.Webpack.getModule(
                (m) => m && typeof m.sendMessage === "function" && typeof m.editMessage === "function"
            );

            if (!this.MessageActions) {
                throw new Error("Could not locate Discord's message module (Discord may have updated).");
            }

            // Patch the send/edit paths BEFORE the async OpenPGP load. Until
            // this.ready flips true, the patch fails closed on enabled channels,
            // so a message typed during the load window can never leak as
            // plaintext (the old order left sendMessage unpatched during load).
            this._patchSend();

            this.openpgp = await this._loadOpenPGP();
            if (!this._running || this._initGen !== gen) return;

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
            // A truncated/HTML/otherwise-corrupt cache passes the size gate above
            // but makes new Function throw a SyntaxError, so catch it here.
            if (!openpgp || typeof openpgp.encrypt !== "function") {
                try {
                    const code = fs.readFileSync(libPath, "utf8");
                    openpgp = new Function(
                        code + '\n;return (typeof openpgp !== "undefined") ? openpgp : undefined;'
                    )();
                } catch (_) { openpgp = null; }
            }

            if (!openpgp || typeof openpgp.encrypt !== "function") {
                // Delete the bad cache so the NEXT start re-downloads instead of
                // being permanently bricked by a corrupt >10KB file.
                try { fs.unlinkSync(libPath); } catch (_) {}
                throw new Error("OpenPGP.js cache was invalid; deleted it. Reload the plugin to re-download.");
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
        // Drop all in-memory unlock state (unlocked key + session passphrase).
        // Called whenever the keypair is deleted or replaced.
        _forgetUnlock() {
            if (this._closeUnlockModal) this._closeUnlockModal();
            this.myUnlockedKey = null;
            this.sessionPassphrase = null;
            this._unlockPromise = null;
            this._unlockDismissed = false;
        }

        // Remove decorations we injected into Discord's DOM. Called on stop() so
        // decrypted plaintext and lock badges don't linger on screen after the
        // plugin is disabled; Discord repaints the original content on its next
        // render. Only nodes we actually took over (those holding a .pgp-badge) are
        // cleared, so ordinary messages marked "done" keep their content.
        _teardownDecorations() {
            if (typeof document === "undefined" || !document.querySelectorAll) return;
            document.querySelectorAll('[id^="message-content-"][data-pgp-done]').forEach((el) => {
                if (el.querySelector && el.querySelector(".pgp-badge")) el.innerHTML = "";
                if (el.dataset) delete el.dataset.pgpDone;
            });
            document.querySelectorAll(".pgp-chan-badge").forEach((b) => { try { b.remove(); } catch (_) {} });
        }

        // Called when the key transitions to unlocked: re-process any messages that
        // failed to decrypt while it was locked (marked data-pgp-done="locked"),
        // so they refresh immediately instead of on the next Discord repaint.
        _onUnlocked() {
            if (typeof document === "undefined" || !document.querySelectorAll) return;
            let cleared = 0;
            document.querySelectorAll('[id^="message-content-"][data-pgp-done="locked"]').forEach((el) => {
                if (el.dataset && el.dataset.pgpDone === "locked") { delete el.dataset.pgpDone; cleared++; }
            });
            if (cleared) this._scheduleScan();
        }

        // Describes the private key's at-rest protection for the settings UI.
        //   readable   - the key parses (false for e.g. GnuPG 2.4 AEAD keys)
        //   encrypted  - the key is passphrase-protected (encrypted on disk)
        //   unlocked   - the held passphrase actually opens the key (verified)
        //   remembered - the passphrase is stored on this device
        async _keyLockState() {
            if (!this.settings.privateKey) return { hasKey: false };
            let readable = true, encrypted = false, base = null;
            try {
                base = await this.openpgp.readPrivateKey({ armoredKey: this.settings.privateKey });
                encrypted = !base.isDecrypted();
            } catch (_) { readable = false; }
            let unlocked = !!this.myUnlockedKey;
            // Verify the held passphrase truly opens the key, rather than claiming
            // "unlocked" just because some string is stored. Never prompts; caches
            // the unlocked key on success (same non-interactive path as getMyKey).
            if (readable && encrypted && !unlocked) {
                const known = this.sessionPassphrase != null ? this.sessionPassphrase
                    : (this.settings.passphrase ? this.settings.passphrase : null);
                if (known != null) {
                    try { this.myUnlockedKey = await this._decryptMyKey(base, known); unlocked = true; this._onUnlocked(); }
                    catch (_) { unlocked = false; }
                }
            }
            return { hasKey: true, readable, encrypted, unlocked, remembered: !!this.settings.rememberPassphrase };
        }

        // Returns the unlocked private key. The passphrase is never persisted
        // (unless "Remember on this device" is on); it lives in memory for the
        // session, and if we don't have it yet the user is prompted to unlock.
        async getMyKey() {
            if (this.myUnlockedKey) return this.myUnlockedKey;
            if (!this.settings.privateKey) throw new Error("No private key set (open plugin settings).");
            const base = await this.openpgp.readPrivateKey({ armoredKey: this.settings.privateKey });
            // A key with no passphrase is already decrypted at rest; nothing to unlock.
            if (base.isDecrypted()) { this.myUnlockedKey = base; return base; }
            // Try a passphrase we already hold: this session's, or a remembered one.
            const known = this.sessionPassphrase != null ? this.sessionPassphrase
                : (this.settings.passphrase ? this.settings.passphrase : null);
            if (known != null) {
                try {
                    const key = await this._decryptMyKey(base, known);
                    this.myUnlockedKey = key; this.sessionPassphrase = known;
                    // Honor the remember invariant: if the user opted in but the
                    // passphrase isn't on disk yet (e.g. toggled on while locked),
                    // persist it now.
                    if (this.settings.rememberPassphrase && !this.settings.passphrase) {
                        this.settings.passphrase = known; this.save();
                    }
                    this._onUnlocked();
                    return key;
                } catch (e) {
                    // A wrong passphrase falls through to an interactive prompt;
                    // an unreadable-format error is fatal and re-surfaced.
                    if (!/incorrect key passphrase/i.test((e && e.message) || "")) throw e;
                }
            }
            // No usable passphrase in hand. Prompt once; if the user dismissed the
            // unlock earlier this session, stay quiet until they retry from settings.
            if (this._unlockDismissed) throw new Error("Your key is locked. Open plugin settings to unlock it.");
            const ok = await this._ensureUnlocked();
            if (!ok || !this.myUnlockedKey) throw new Error("Your key is locked (passphrase not entered).");
            return this.myUnlockedKey;
        }

        // Decrypt the private key with a passphrase, translating OpenPGP's opaque
        // errors. The wrong-passphrase case is rethrown verbatim ("Incorrect key
        // passphrase") so callers can tell it apart from a fatal format error.
        async _decryptMyKey(base, passphrase) {
            try {
                return await this.openpgp.decryptKey({ privateKey: base, passphrase: passphrase || "" });
            } catch (e) {
                const m = (e && e.message) || "";
                // GnuPG 2.4+ protects exported secret keys with AEAD/OCB, which
                // OpenPGP.js v5 cannot parse; no passphrase will help.
                if (/unsupported s2k|cipher algo/i.test(m)) {
                    throw new Error("Your private key uses a protection format this plugin can't read"
                        + " (typical for keys exported from GnuPG 2.4+)."
                        + " Fix: clear the key's passphrase in GnuPG (gpg --edit-key <id>, passwd, empty),"
                        + " re-export it, paste it here, or generate a fresh key in settings.");
                }
                throw e;
            }
        }

        // Interactive unlock, serialized so concurrent callers (several messages
        // decrypting at once) share a single prompt. Resolves true once the key is
        // unlocked in memory, false if the user cancels or the key is unreadable.
        _ensureUnlocked() {
            if (this._unlockPromise) return this._unlockPromise;
            // Snapshot the key we're unlocking. If it is deleted or replaced while
            // the modal is open (e.g. an auto-triggered own-key revocation confirm),
            // this attempt's results must be dropped so we never install a key for a
            // keypair that no longer exists, or re-persist a passphrase for it.
            const keySnapshot = this.settings.privateKey;
            const p = (async () => {
                const base = await this.openpgp.readPrivateKey({ armoredKey: keySnapshot });
                let error = null;
                for (;;) {
                    const res = await this._promptPassphrase(error);
                    if (this.settings.privateKey !== keySnapshot) return false; // key changed under us
                    if (!res) { this._unlockDismissed = true; return false; }
                    let key;
                    try {
                        key = await this._decryptMyKey(base, res.passphrase);
                    } catch (e) {
                        const m = (e && e.message) || "";
                        if (/incorrect key passphrase/i.test(m)) { error = "Wrong passphrase. Try again."; continue; }
                        BdApi.UI.showToast(m, { type: "error", timeout: 9000 });
                        return false;
                    }
                    if (this.settings.privateKey !== keySnapshot) return false; // key changed during decrypt
                    this.myUnlockedKey = key;
                    this.sessionPassphrase = res.passphrase;
                    this._unlockDismissed = false;
                    if (res.remember || this.settings.rememberPassphrase) {
                        this.settings.rememberPassphrase = true;
                        this.settings.passphrase = res.passphrase;
                        this.save();
                    }
                    this._onUnlocked();
                    return true;
                }
            })();
            this._unlockPromise = p;
            // Only clear the handle if this attempt still owns it: a concurrent
            // _forgetUnlock() may have already nulled or replaced it.
            p.finally(() => { if (this._unlockPromise === p) this._unlockPromise = null; });
            return p;
        }

        // Modal passphrase prompt. Resolves { passphrase, remember } or null on
        // cancel. No-op (null) in a headless context (tests) so unlock fails closed.
        _promptPassphrase(error) {
            return new Promise((resolve) => {
                if (typeof document === "undefined" || !document.body) return resolve(null);
                const el = (tag, cls, props) => { const n = document.createElement(tag); if (cls) n.className = cls; if (props) Object.assign(n, props); return n; };
                const back = el("div", "dpgp-modal-back");
                const box = el("div", "dpgp-modal");
                box.appendChild(el("div", "dpgp-modal-title", { textContent: "Unlock your PGP key" }));
                box.appendChild(el("div", "dpgp-modal-text", { textContent: "Enter your passphrase to decrypt and sign messages this session. It is not stored." }));
                const errBox = el("div", "dpgp-modal-err", { textContent: error || "" });
                errBox.style.display = error ? "block" : "none";
                box.appendChild(errBox);
                const input = el("input", "dpgp-input", { type: "password", placeholder: "Passphrase" });
                box.appendChild(input);
                const remWrap = el("label", "dpgp-modal-remember");
                const rem = el("input", null, { type: "checkbox" });
                remWrap.appendChild(rem);
                remWrap.appendChild(el("span", null, { textContent: "Remember on this device (less secure)" }));
                box.appendChild(remWrap);
                const btns = el("div", "dpgp-modal-btns");
                const cancel = el("button", "dpgp-btn secondary", { type: "button", textContent: "Cancel" });
                const unlock = el("button", "dpgp-btn", { type: "button", textContent: "Unlock" });
                btns.appendChild(cancel); btns.appendChild(unlock);
                box.appendChild(btns);
                back.appendChild(box);
                let done = false;
                const close = (val) => {
                    if (done) return; done = true;
                    this._closeUnlockModal = null;
                    document.removeEventListener("keydown", onKey, true);
                    try { document.body.removeChild(back); } catch (_) {}
                    resolve(val);
                };
                // Lets _forgetUnlock()/stop() dismiss the modal if the key changes.
                this._closeUnlockModal = () => close(null);
                const submit = () => close({ passphrase: input.value, remember: !!rem.checked });
                unlock.onclick = submit;
                cancel.onclick = () => close(null);
                back.onclick = (e) => { if (e.target === back) close(null); };
                const onKey = (e) => {
                    // Consume Enter/Escape fully so Discord's global shortcuts behind
                    // the modal don't also act on them.
                    if (e.key === "Enter") { e.preventDefault(); e.stopImmediatePropagation(); submit(); }
                    else if (e.key === "Escape") { e.preventDefault(); e.stopImmediatePropagation(); close(null); }
                };
                document.addEventListener("keydown", onKey, true);
                document.body.appendChild(back);
                setTimeout(() => { try { input.focus(); } catch (_) {} }, 0);
            });
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
            const me = this.UserStore && this.UserStore.getCurrentUser && this.UserStore.getCurrentUser();
            const myId = me && String(me.id);
            const rawMentionIds = [...new Set([...text.matchAll(/<@!?(\d+)>/g)].map((m) => m[1]))];
            // A mention that resolves to a saved contact narrows the recipients to
            // that contact. A mention of yourself, or of someone you have no key
            // for, is treated as an ordinary Discord mention (not a target) rather
            // than blocking the send; the "Encrypted only for" toast below shows
            // exactly who the message went to, and an empty recipient set still
            // fails closed further down.
            const mentionIds = [];
            for (const id of rawMentionIds) {
                if (myId && id === myId) continue; // self is always a recipient anyway
                const rid = this._resolveContactId(id);
                if (rid) mentionIds.push(rid);
            }
            for (const [id, c] of Object.entries(this.settings.contacts)) {
                // Include revoked contacts here so the revoked-target check below
                // fires (mirrors the real-mention path), instead of silently
                // dropping an @label target and encrypting to the wrong set.
                if (!c.label || !c.publicKey || mentionIds.includes(id)) continue;
                // "@label" bounded so it is not part of a larger token: "@bob.smith",
                // "email@bobmail.com", "@bob-jones" must NOT target contact "bob".
                // "." "@" "-" all count as part of the surrounding token, not a break.
                if (this._labelMentioned(text, c.label)) mentionIds.push(id);
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
            // Best-effort signing: a user with only imported contact keys (no own
            // private key) should still be able to send, just unsigned. Signing
            // failure must not block an otherwise-valid encrypted message.
            if (this.settings.signMessages && this.settings.privateKey) {
                try { opts.signingKeys = await this.getMyKey(); }
                catch (e) { BdApi.UI.showToast("PGP: sending unsigned (" + e.message + ")", { type: "warning" }); }
            }
            return await this.openpgp.encrypt(opts);
        }

        // authorBinding (from _processMessage) = { signerKey } binds signature
        // verification to the MESSAGE AUTHOR's key: "verified" then means the
        // displayed author actually signed it, defeating a replay where an
        // attacker reposts someone else's validly-signed block under their name.
        // When omitted (direct/test callers), verify against all saved keys.
        async decryptText(armored, authorBinding) {
            const message = await this.openpgp.readMessage({ armoredMessage: armored });
            const key = await this.getMyKey();
            let verificationKeys;
            if (authorBinding === undefined) {
                verificationKeys = await this._verificationKeys();
            } else {
                verificationKeys = [];
                if (authorBinding && authorBinding.signerKey) {
                    try { verificationKeys.push(await this.openpgp.readKey({ armoredKey: authorBinding.signerKey })); } catch (_) {}
                }
            }
            const opts = { message, decryptionKeys: key };
            if (verificationKeys.length) opts.verificationKeys = verificationKeys;
            const { data, signatures } = await this.openpgp.decrypt(opts);
            // "unsigned" (no signature), "verified" (signed by a verifying key we
            // supplied), or "unknown" (signed by a key we don't hold / can't match).
            let sig = "unsigned";
            if (signatures && signatures.length) {
                // Await every signature (with a catch each) so a later rejection
                // can't surface as an unhandled promise rejection after we decide.
                const verdicts = await Promise.all(signatures.map((s) => s.verified.then(() => true, () => false)));
                sig = verdicts.some(Boolean) ? "verified" : "unknown";
            }
            return { text: data, sig };
        }

        // The non-revoked public key of the message author (a saved contact, or
        // self), used to confirm a signature really came from the author. Null if
        // we have no key for them.
        _authorKey(authorId) {
            if (!authorId) return null;
            const me = this.UserStore && this.UserStore.getCurrentUser && this.UserStore.getCurrentUser();
            if (me && String(me.id) === String(authorId)) return this.settings.publicKey || null;
            const c = this.settings.contacts[String(authorId)];
            return (c && !c.revoked && c.publicKey) ? c.publicKey : null;
        }

        // Public keys to verify incoming signatures against: non-revoked saved
        // contacts + self. A revoked contact's key must NOT vouch for a signature
        // (their key is compromised), so it falls through to "unknown".
        async _verificationKeys() {
            const out = [];
            const add = async (armored) => {
                if (!armored) return;
                try { out.push(await this.openpgp.readKey({ armoredKey: armored })); } catch (_) {}
            };
            for (const c of Object.values(this.settings.contacts)) { if (!c.revoked) await add(c.publicKey); }
            await add(this.settings.publicKey);
            return out;
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

        // Given a posted revocation artifact, return EVERY stored key it
        // cryptographically revokes: { self: bool, contacts: [ids] }, or null if
        // it verifies against nothing we hold. All matches are returned so a key
        // saved under multiple contacts is fully revoked, not just the first.
        // The message author is never trusted; only the signature decides.
        async _matchRevocation(armored) {
            const cands = [];
            if (this.settings.publicKey) cands.push({ self: true, key: this.settings.publicKey });
            for (const [id, c] of Object.entries(this.settings.contacts)) {
                if (c.publicKey) cands.push({ id, key: c.publicKey });
            }

            const matched = [];
            // Form A: a full key block that is already revoked. isRevoked() has
            // verified the embedded self-signature, so a fingerprint match is safe.
            let parsed = null;
            try { parsed = await this.openpgp.readKey({ armoredKey: armored }); } catch (_) {}
            if (parsed) {
                if (!(await parsed.isRevoked())) return null; // a normal, live key
                const fpr = parsed.getFingerprint();
                for (const cand of cands) {
                    if ((await this._fprOf(cand.key)) === fpr) matched.push(cand);
                }
            } else {
                // Form B: a detached revocation certificate. revokeKey() throws
                // unless the certificate's signature matches the candidate key.
                for (const cand of cands) {
                    try {
                        const revoked = await this.openpgp.revokeKey({
                            key: await this.openpgp.readKey({ armoredKey: cand.key }),
                            revocationCertificate: armored,
                            format: "armored",
                        });
                        if (await (await this.openpgp.readKey({ armoredKey: revoked.publicKey })).isRevoked()) matched.push(cand);
                    } catch (_) { /* signature does not match this candidate */ }
                }
            }
            if (!matched.length) return null;
            return {
                self: matched.some((m) => m.self),
                contacts: matched.filter((m) => m.id).map((m) => m.id),
            };
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
            // Match by USERNAME only (unique on Discord). Display names are not
            // unique, so matching globalName could re-key a contact onto an
            // unrelated stranger who shares a display name.
            const uname = u.username ? String(u.username).toLowerCase() : null;
            if (!uname) return null;
            // Only heal contacts saved WITHOUT a real id ("name:label"): a contact
            // already stored under a numeric Discord id must never be re-keyed.
            const matches = Object.entries(this.settings.contacts).filter(([id, c]) =>
                id.startsWith("name:") && c.publicKey && c.label && c.label.toLowerCase() === uname);
            if (matches.length !== 1) return null; // none or ambiguous: don't guess
            const [oldId, contact] = matches[0];
            delete this.settings.contacts[oldId];
            this.settings.contacts[userId] = contact;
            this._rekeyGroups(oldId, userId);
            this.save();
            BdApi.UI.showToast('PGP: contact "' + contact.label + '" linked to user ID ' + userId, { type: "info" });
            return userId;
        }

        // Keep channel groups consistent when a contact id changes or is removed.
        // newId null => remove oldId from every group.
        _rekeyGroups(oldId, newId) {
            for (const chan of Object.keys(this.settings.groups)) {
                const arr = this.settings.groups[chan];
                const i = arr.indexOf(oldId);
                if (i === -1) continue;
                // Renaming onto an id already present would duplicate it: drop
                // the old slot instead.
                if (newId && !arr.includes(newId)) arr[i] = newId;
                else arr.splice(i, 1);
                if (!arr.length) delete this.settings.groups[chan];
            }
        }

        _describeUser(userId) {
            const u = this.UserStore && this.UserStore.getUser && this.UserStore.getUser(userId);
            return u && u.username ? "@" + u.username + " (" + userId + ")" : userId;
        }

        _patchSend() {
            if (this._sendPatched) return; // idempotent: never stack a duplicate patch
            this._sendPatched = true;
            const self = this;
            BdApi.Patcher.instead(config.name, this.MessageActions, "sendMessage", (_thisObj, args, original) => {
                const [channelId, message] = args;
                // Plaintext post from a native command (see _sendPlain): strip the
                // marker and send as-is. Per-message, so it can't get stuck.
                if (message && message.__dpgpPlain) { delete message.__dpgpPlain; return original(...args); }
                const content = (message && message.content) || "";

                // ".pgp" works alongside "/pgp" because Discord's slash-command
                // picker can swallow unknown /commands before they're sent. Must
                // be the exact token: "/pgpsomething" is a normal message.
                const lead = content.trimStart();
                // Only intercept as a command when the verb is recognized and the
                // line isn't just prose that happens to start with "/pgp ...".
                // Bare "/pgp" -> help; "group" carries args; every other verb takes
                // none, so trailing words mean it's a normal message (send as-is).
                const cmdToks = /^[./]pgp(?:\s|$)/i.test(lead) ? lead.split(/\s+/) : null;
                const cmdVerb = cmdToks ? (cmdToks[1] || "").toLowerCase() : "";
                const isPgpCommand = cmdToks && (
                    cmdToks.length === 1 ||
                    cmdVerb === "group" ||
                    (cmdToks.length === 2 && /^(on|off|status|help|debug|share|fingerprint|revoke)$/.test(cmdVerb))
                );
                if (isPgpCommand) {
                    return (async () => {
                        let replacement;
                        try { replacement = await self._handleCommand(channelId, content.trim()); }
                        catch (e) { BdApi.UI.showToast("PGP: " + e.message, { type: "error" }); return {}; }
                        // A command may return replacement content to post as-is
                        // (plaintext, via the unpatched send). Otherwise swallow.
                        if (typeof replacement === "string" && replacement) {
                            if (replacement.length > 2000) {
                                BdApi.UI.showToast("PGP: too long to post (>2000 chars)", { type: "error" });
                                return {};
                            }
                            message.content = replacement;
                            return original(...args);
                        }
                        return {};
                    })();
                }

                // Fail closed if the channel is marked encrypted but the plugin
                // hasn't finished loading yet: block rather than leak plaintext.
                if (self.settings.enabledChannels[channelId] && !self.ready) {
                    BdApi.UI.showToast("PGP: still starting up, message not sent. Try again in a moment.", { type: "error" });
                    return Promise.resolve({});
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
                            BdApi.UI.showToast("PGP: message too long to send encrypted (>2000 chars)", { type: "error" });
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

            // Edits must be encrypted too, or editing a message on an enabled
            // channel would send the new text as plaintext. Signature is
            // editMessage(channelId, messageId, message).
            BdApi.Patcher.instead(config.name, this.MessageActions, "editMessage", (_thisObj, args, original) => {
                const [channelId, , message] = args;
                const content = (message && message.content) || "";
                if (!self.settings.enabledChannels[channelId]) return original(...args);
                if (self.settings.enabledChannels[channelId] && !self.ready) {
                    BdApi.UI.showToast("PGP: still starting up, edit not sent. Try again in a moment.", { type: "error" });
                    return Promise.resolve({});
                }
                // The edit box is pre-filled with the stored ciphertext. Pass it
                // through unchanged ONLY when the content is exactly that block and
                // nothing else. If the user added any surrounding text, fall through
                // and re-encrypt the whole edit; otherwise that plaintext would leak.
                if (/^\s*-----BEGIN PGP MESSAGE-----[\s\S]*-----END PGP MESSAGE-----\s*$/.test(content)) return original(...args);
                return (async () => {
                    try {
                        const cipher = await self.encryptForChannel(channelId, content);
                        if (cipher.length > 2000) {
                            BdApi.UI.showToast("PGP: edited message too long to encrypt (>2000 chars)", { type: "error" });
                            return {};
                        }
                        message.content = cipher;
                    } catch (e) {
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
                    return { reply: "🔒 Encryption ON for this channel" };
                case "off":
                    delete s.enabledChannels[channelId]; this.save(); this._decorateChannelList();
                    return { reply: "🔓 Encryption OFF for this channel" };
                case "status": {
                    const on = !!s.enabledChannels[channelId];
                    const g = (s.groups[channelId] || []).map((id) => (s.contacts[id] && s.contacts[id].label) || id);
                    return { reply: "PGP is " + (on ? "ON" : "OFF") + " here" + (g.length ? ". Group: " + g.join(", ") : "") };
                }
                case "help":
                    return { reply: "Commands: on, off, status, share, fingerprint, revoke, group add/remove/list/clear, debug, help" };
                case "debug":
                    return { reply: "debug: " + this._debugInfo(channelId) };
                case "share":
                    if (!s.publicKey) return { reply: "No key yet. Generate one in settings.", error: true };
                    return { post: s.publicKey, reply: "Shared your public key" };
                case "fingerprint": {
                    if (!s.publicKey) return { reply: "No key yet. Generate one in settings.", error: true };
                    let fpr;
                    try { fpr = (await this._keyInfo(s.publicKey)).fingerprint; }
                    catch (e) { return { reply: "Couldn't read your key: " + e.message, error: true }; }
                    // Post the bare fingerprint; recipients' clients verify it
                    // against your saved key and show a match badge.
                    return { post: fpr, reply: "Fingerprint posted" };
                }
                case "revoke": {
                    if (!s.privateKey) return { reply: "No key to revoke", error: true };
                    let cert;
                    try { cert = await this._makeRevocationCert(); }
                    catch (e) { return { reply: "Couldn't make certificate: " + e.message, error: true }; }
                    const ok = await this._confirmAsync(
                        "Revoke and delete this keypair?",
                        "This posts a certificate that revokes your key for everyone who sees it, and removes your keypair from this device. You will no longer be able to read messages encrypted to it. Only do this if the key is compromised or retired.",
                        "Revoke");
                    if (!ok) return { reply: "Revocation cancelled" };
                    // Clipboard safety net: the keypair is wiped before the post
                    // goes out, so if posting fails the certificate must survive
                    // somewhere the user can reach.
                    this._copy(cert, "Revocation certificate");
                    s.privateKey = ""; s.publicKey = ""; s.passphrase = ""; s.rememberPassphrase = false; s.revocationCertificate = "";
                    this._forgetUnlock(); this.decryptCache.clear(); this.save();
                    // Discord caps messages at 2000 chars; RSA certs can exceed it.
                    // Don't claim it was posted when it can't be.
                    if (cert.length > 2000) {
                        return { reply: "Keypair removed. Certificate copied to clipboard; paste it manually (too long to auto-post)." };
                    }
                    return { post: cert, reply: "Keypair removed. Revocation posted (certificate also copied to clipboard)." };
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
                return { reply: "Group cleared for this channel" };
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
                // Warn when an added member has a revoked key: they stay in the
                // group but are skipped at encryption time.
                const revokedAdds = action === "add"
                    ? targetIds.filter((id) => s.contacts[id] && s.contacts[id].revoked) : [];
                return { reply: (action === "add" ? "Added to" : "Removed from") + " group: " + targetIds.map(label).join(", ")
                    + (action === "add" ? ". Encryption is ON here." : "")
                    + (revokedAdds.length ? " Warning: revoked key, will be skipped: " + revokedAdds.map(label).join(", ") : "") };
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
                + " | unlocked=" + (!!this.myUnlockedKey || this.sessionPassphrase != null || !!s.passphrase)
                + " | remember=" + !!s.rememberPassphrase
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
                if (this._labelMentioned(text, c.label)) ids.add(id);
            }
            return [...ids];
        }

        // True if "@<label>" appears as a standalone token in text. "." "@" "-"
        // count as part of the surrounding token so "@bob.smith" / "e@bobmail.com"
        // do not match contact "bob".
        _labelMentioned(text, label) {
            const esc = label.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
            // Unicode-aware boundaries: any letter/number (not just ASCII) counts
            // as part of the surrounding token, so "@bobñ" / "café@bob" don't match
            // contact "bob".
            return new RegExp("(^|[^\\p{L}\\p{N}_.@-])@" + esc + "(?![\\p{L}\\p{N}_.@-])", "iu").test(text);
        }

        // Post plaintext into a channel, bypassing encryption for this one send.
        // Used by native slash commands (share/revoke) where there is no typed
        // message to rewrite. The text path posts via the send-patch return value
        // instead, reusing Discord's own message object. Returns true on success.
        async _sendPlain(channelId, text) {
            // Per-message marker instead of an instance flag: the patch strips it
            // and posts as-is. A dropped/deferred patch can't leave a stale flag
            // that later leaks a real message as plaintext.
            const msg = { content: text, tts: false, invalidEmojis: [], validNonShortcutEmojis: [], __dpgpPlain: true };
            try {
                // Current Discord needs the trailing (promise, options) arguments;
                // a 2-argument call silently posts nothing.
                const r = this.MessageActions.sendMessage(channelId, msg, undefined, {});
                if (r && typeof r.then === "function") await r;
                return true;
            } catch (e) {
                console.error("[DiscordPG] plaintext post failed:", e);
                BdApi.UI.showToast("Couldn't post: " + ((e && e.message) || e), { type: "error" });
                return false;
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
            // Clear any prior registration (e.g. a reload that re-ran _init)
            // before building a new one, so commands never stack up.
            this._unregisterCommands();
            const O = (C.Types && C.Types.OptionTypes) || { STRING: 3 };
            const self = this;
            const userOpt = { name: "user", description: "Mention or contact label, e.g. @bob", type: O.STRING, required: true };
            const defs = [
                { verb: "on", desc: "Enable encryption for this channel" },
                { verb: "off", desc: "Disable encryption for this channel" },
                { verb: "status", desc: "Show encryption status here" },
                { verb: "share", desc: "Post your public key into this channel" },
                { verb: "fingerprint", desc: "Post your key's fingerprint for verification" },
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
                            if (r.post) {
                                const sent = await self._sendPlain(channelId, r.post);
                                if (!sent) return self._cmdReply("Posting failed. Check the console (Ctrl+Shift+I) for details.");
                            }
                            return self._cmdReply(r.reply || "Done.", r.error);
                        } catch (e) {
                            return self._cmdReply("DiscordPG error: " + e.message, true);
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

        // Deliver command feedback: a private Clyde bot message (returned to the
        // command system) when clydeReplies is on, otherwise a small toast.
        _cmdReply(text, isError) {
            if (this.settings.clydeReplies) return { content: text };
            BdApi.UI.showToast(text, { type: isError ? "error" : "info" });
            return undefined; // no bot message
        }

        _unregisterCommands() {
            // Call the collected unregister fns AND unregisterAll: on BD builds
            // where register() returns nothing, the array is empty and only the
            // sweep removes them.
            try {
                if (Array.isArray(this._unregisterCmds)) this._unregisterCmds.forEach((un) => { try { un(); } catch (_) {} });
            } catch (_) {}
            try {
                if (BdApi.Commands && typeof BdApi.Commands.unregisterAll === "function") BdApi.Commands.unregisterAll(config.name);
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
            if (this.observer) this.observer.disconnect(); // never leak a prior observer
            const app = document.querySelector("#app-mount") || document.body;
            this.observer = new MutationObserver(() => this._scheduleScan());
            this.observer.observe(app, { childList: true, subtree: true });
            this._scheduleScan();
        }

        _scheduleScan() {
            if (this._scanScheduled) return;
            this._scanScheduled = true;
            this._scanTimer = setTimeout(() => { this._scanScheduled = false; this._scan(); }, 120);
        }

        _scan() {
            // Always scan: key-save offers and revocation processing must work
            // even with auto-decrypt off (that gate lives in _processMessage).
            const nodes = document.querySelectorAll('[id^="message-content-"]:not([data-pgp-done])');
            // Isolate per-message failures so one throw can't skip the rest of the
            // batch or the channel-list decoration.
            nodes.forEach((el) => { try { this._processMessage(el); } catch (e) { console.error("[DiscordPG] scan:", e); } });
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
                const cls = "pgp-chan-badge pgp-min";
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
                // id = "chat-messages-<channelId>-<messageId>". Split off the known
                // messageId from the end so a channelId with any shape is handled
                // (threads/forums/search can produce ids the old \d+-\d+ regex
                // rejected, which then fell into the lossy textContent path).
                const rest = li.id.slice("chat-messages-".length);
                if (rest.endsWith("-" + messageId)) channelId = rest.slice(0, -(messageId.length + 1));
                else { const m = li.id.match(/^chat-messages-(\d+)-\d+$/); if (m) channelId = m[1]; }
            }

            let raw = "";
            let authorId = null;
            if (channelId && this.MessageStore) {
                const msg = this.MessageStore.getMessage(channelId, messageId);
                raw = (msg && msg.content) || "";
                authorId = msg && msg.author && String(msg.author.id);
            }
            // Fallback: innerText preserves the armored block's line breaks;
            // textContent collapses them and yields "Misformed armored text".
            if (!raw) raw = el.innerText || el.textContent || "";

            const block = raw.match(/-----BEGIN PGP MESSAGE-----[\s\S]*?-----END PGP MESSAGE-----/);
            if (!block) {
                el.dataset.pgpDone = "1"; // either way, processed; skip forever
                // Pasted public key or revocation? Offer to save / apply.
                const pubBlock = raw.match(/-----BEGIN PGP PUBLIC KEY BLOCK-----[\s\S]*?-----END PGP PUBLIC KEY BLOCK-----/);
                if (pubBlock) { this._handleKeyBlock(el, pubBlock[0], channelId, messageId); return; }
                // A bare fingerprint (from /pgp-fingerprint): verify it against the
                // sender's saved key and show a compact result badge.
                const fpr = this._matchFingerprint(raw);
                if (fpr) this._renderFingerprint(el, fpr, authorId);
                return;
            }
            const armored = block[0];

            // Auto-decrypt off: leave the raw PGP block untouched. Marked done
            // per-element, so turning the setting on decrypts on the next render.
            if (!this.settings.autoDecrypt) {
                el.dataset.pgpDone = "1";
                return;
            }

            // Signature verdict depends on the author, so cache per (author, block).
            const cacheKey = (authorId || "") + " " + armored;
            const cached = this.decryptCache.get(cacheKey);
            if (cached) {
                el.dataset.pgpDone = "1";
                this._render(el, cached, armored);
                return;
            }

            // Mark in-flight so we don't fire duplicate decrypts for the same element.
            el.dataset.pgpDone = "pending";
            this.decryptText(armored, { signerKey: this._authorKey(authorId) })
                .then((res) => {
                    // Drop the result if the plugin stopped or the node was detached
                    // (e.g. channel switch) while decrypting; Discord may have reused
                    // the node id for a different message.
                    if (!this._running || el.isConnected === false) return;
                    const result = { ok: true, text: res.text, sig: res.sig };
                    this._cacheDecrypt(cacheKey, result);
                    el.dataset.pgpDone = "1";
                    this._render(el, result, armored);
                })
                .catch((err) => {
                    if (!this._running || el.isConnected === false) return;
                    // Do NOT cache failures: the user may paste/fix their key
                    // later, and the message must re-decrypt on the next render.
                    const result = { ok: false, text: "" };
                    // A failure caused by a locked key is marked distinctly so it can
                    // be retried the moment the key is unlocked (see _onUnlocked),
                    // instead of staying "couldn't decrypt" until Discord repaints.
                    el.dataset.pgpDone = /locked/i.test((err && err.message) || "") ? "locked" : "1";
                    this._render(el, result, armored);
                });
        }

        // Bounded decrypt cache: evict the oldest entries so a long session
        // doesn't hold every ciphertext ever seen in memory.
        _cacheDecrypt(armored, result) {
            this.decryptCache.set(armored, result);
            while (this.decryptCache.size > 200) {
                this.decryptCache.delete(this.decryptCache.keys().next().value);
            }
        }

        _render(el, result, armored) {
            el.innerHTML = "";
            const badge = document.createElement("span");
            badge.className = "pgp-badge pgp-min " + (result.ok ? "pgp-ok" : "pgp-fail");
            badge.textContent = result.ok ? "🔓" : "🔒";
            badge.title = (result.ok ? "" : "Couldn't decrypt. ") + "Click to show the raw PGP message";
            el.appendChild(badge);
            // Signature status: confirm a verified signer, or warn on a signature
            // we can't verify. Unsigned messages get no marker (common, not alarming).
            if (result.ok && result.sig && result.sig !== "unsigned") {
                const verified = result.sig === "verified";
                const sg = document.createElement("span");
                sg.className = "pgp-sig " + (verified ? "pgp-sig-ok" : "pgp-sig-bad");
                sg.textContent = verified ? " ✓" : " ⚠";
                sg.title = verified
                    ? "Signature verified: this message really is from its author's key."
                    : "Signed, but not by this author's saved key (or key unknown). Sender not confirmed.";
                el.appendChild(sg);
            }
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
                if (isUrl) {
                    // Trailing sentence punctuation is not part of the URL
                    // ("see https://x.com/cat.gif," should still embed).
                    let url = part, trail = "";
                    const tm = part.match(/^([\s\S]*?)([).,!?;:]+)$/);
                    if (tm) { url = tm[1]; trail = tm[2]; }
                    const media = this._mediaUrl(url);
                    if (media) {
                        container.appendChild(this._mediaNode(media));
                    } else {
                        const a = document.createElement("a");
                        a.className = "pgp-link";
                        a.href = url;
                        a.textContent = url;
                        a.target = "_blank";
                        a.rel = "noreferrer noopener";
                        container.appendChild(a);
                    }
                    if (trail) {
                        const t = document.createElement("span");
                        t.textContent = trail;
                        container.appendChild(t);
                    }
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
            const degradeToLink = () => {
                // Blocked / dead / unfetchable: fall back to a plain link.
                wrap.innerHTML = "";
                const a = document.createElement("a");
                a.className = "pgp-link";
                a.href = url; a.textContent = url;
                a.target = "_blank"; a.rel = "noreferrer noopener";
                wrap.appendChild(a);
            };
            const showImage = () => {
                wrap.innerHTML = "";
                const img = document.createElement("img");
                img.className = "pgp-media-img";
                img.alt = url;
                img.onerror = () => degradeToLink();
                wrap.appendChild(img);
                if (this._isDiscordHost(host)) {
                    // Discord's own CDN is allowed by the renderer's CSP: load direct.
                    img.src = url;
                } else {
                    // Discord's img-src CSP blocks remote images, so a direct <img
                    // src> to a third-party host just fails. Fetch the bytes over
                    // Node (bypasses CSP, same mechanism as the library download) and
                    // embed them as a data: URL, which the CSP permits. Fall back to a
                    // direct load, then a link, if the fetch fails.
                    this._fetchDataUrl(url)
                        .then((dataUrl) => { img.src = dataUrl; })
                        .catch(() => { img.src = url; });
                }
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

        _isDiscordHost(host) {
            return /(^|\.)(discordapp\.com|discord\.com|discordapp\.net)$/i.test(host || "");
        }

        // Recognize an embeddable media URL, converting common GIF share links to a
        // direct media URL. Returns the media URL, or null for a non-media link.
        // Note: Tenor "view" links (tenor.com/view/...), which Discord's GIF picker
        // inserts, have no derivable media URL without the Tenor API, so they stay
        // plain links; paste a direct .gif URL to embed one.
        _mediaUrl(url) {
            // Direct image by extension (query/fragment allowed after it). Imgur's
            // .gifv is an HTML5 video wrapper whose .gif twin is the real image.
            if (/\.(gif|gifv|png|jpe?g|webp|apng|avif|bmp)(?:[?#]\S*)?$/i.test(url)) {
                return url.replace(/\.gifv(?=[?#]|$)/i, ".gif");
            }
            let u;
            try { u = new URL(url); } catch (_) { return null; }
            const host = u.hostname.replace(/^www\./, "");
            // Giphy page link -> direct GIF (the id is the trailing "-" segment).
            if (host === "giphy.com" && /^\/gifs\//.test(u.pathname)) {
                const id = u.pathname.replace(/\/+$/, "").split("-").pop();
                if (id && /^[A-Za-z0-9]{6,}$/.test(id)) return "https://media.giphy.com/media/" + id + "/giphy.gif";
            }
            // Hosts that serve raw media even without a recognized extension.
            if (/^(media\d*\.tenor\.com|c\.tenor\.com|media\d*\.giphy\.com|i\.giphy\.com|i\.imgur\.com|media\.discordapp\.net|cdn\.discordapp\.com)$/.test(host)) {
                return url;
            }
            return null;
        }

        // Fetch remote media over Node and return it as a data: URL, bypassing the
        // renderer's img-src CSP. Sniffs the type from magic bytes; caps size.
        async _fetchDataUrl(url) {
            const buf = await this._httpsGet(url);
            if (!buf || !buf.length) throw new Error("empty response");
            if (buf.length > 26214400) throw new Error("media too large (>25 MB)");
            const mime = this._sniffMime(buf);
            if (!mime) throw new Error("not a recognized image");
            return "data:" + mime + ";base64," + buf.toString("base64");
        }

        _sniffMime(b) {
            if (b.length >= 3 && b[0] === 0x47 && b[1] === 0x49 && b[2] === 0x46) return "image/gif";  // GIF8
            if (b.length >= 8 && b[0] === 0x89 && b[1] === 0x50 && b[2] === 0x4e && b[3] === 0x47) return "image/png";
            if (b.length >= 3 && b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff) return "image/jpeg";
            if (b.length >= 12 && b[0] === 0x52 && b[1] === 0x49 && b[2] === 0x46 && b[3] === 0x46
                && b[8] === 0x57 && b[9] === 0x45 && b[10] === 0x42 && b[11] === 0x50) return "image/webp"; // RIFF....WEBP
            return null;
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
            const badge = document.createElement("span");
            badge.className = "pgp-badge pgp-min pgp-revoke-badge";
            badge.textContent = "🚫";
            badge.title = "PGP revocation certificate. Click to show the raw block";
            el.appendChild(badge);

            const info = document.createElement("span");
            info.className = "pgp-keyoffer-info";
            const contactIds = (match && match.contacts) || [];
            if (contactIds.length) {
                // Mark EVERY contact that holds this revoked key (a key saved
                // under several contacts must all be flagged).
                const names = [];
                let changed = false;
                for (const cid of contactIds) {
                    const c = this.settings.contacts[cid];
                    if (!c) continue;
                    names.push(c.label || cid);
                    if (!c.revoked) { c.revoked = true; changed = true; }
                }
                if (changed) { this.save(); this.decryptCache.clear(); this._decorateChannelList(); }
                const who = names.join(", ");
                BdApi.UI.showToast('PGP: "' + who + '" revoked their key. Marked revoked; ask them for a new one.', { type: "error", timeout: 8000 });
                info.textContent = "✓ " + who + "'s key is revoked. Encryption to them is blocked until they send a new key.";
            } else if (match && match.self) {
                // Only prompt to wipe your own key when the cert is for YOUR key
                // alone (not a contact who happens to share it).
                info.textContent = "Valid revocation certificate for your key";
                if (!this._revokePromptSeen) this._revokePromptSeen = new Set();
                if (!this._revokePromptSeen.has(armored)) {
                    this._revokePromptSeen.add(armored);
                    this._confirm(
                        "Revoke your own key?",
                        "A valid revocation certificate for your own key was posted. If your key is compromised, remove it here and generate a new keypair. This clears your keys and passphrase from this machine.",
                        "Remove my keypair",
                        () => {
                            this.settings.privateKey = ""; this.settings.publicKey = "";
                            this.settings.passphrase = ""; this.settings.rememberPassphrase = false; this.settings.revocationCertificate = "";
                            this._forgetUnlock(); this.decryptCache.clear();
                            this.save();
                            BdApi.UI.showToast("Your keypair was removed. Generate a new one in settings.", { type: "info" });
                        }
                    );
                }
            } else {
                info.textContent = "Revocation certificate for a key you don't have";
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

        // A message that is exactly a PGP fingerprint (10 groups of 4 hex, as
        // posted by /pgp-fingerprint). Returns the normalized uppercase value.
        _matchFingerprint(raw) {
            const m = String(raw).trim().match(/^((?:[0-9A-Fa-f]{4} ){9}[0-9A-Fa-f]{4})$/);
            return m ? m[1].toUpperCase() : null;
        }

        // Render a posted fingerprint with a badge that verifies it against the
        // sender's saved key: matches, does not match, or no key to compare.
        _renderFingerprint(el, fpr, authorId) {
            el.innerHTML = "";
            const badge = document.createElement("span");
            badge.className = "pgp-badge pgp-min pgp-fpr-badge";
            badge.textContent = "✍️";
            badge.title = "PGP key fingerprint";
            el.appendChild(badge);

            const value = document.createElement("span");
            value.className = "pgp-fpr-value";
            value.textContent = fpr;
            el.appendChild(value);

            const info = document.createElement("span");
            info.className = "pgp-fpr-note";
            info.textContent = " …";
            el.appendChild(info);

            const set = (cls, text, title) => { info.className = "pgp-fpr-note " + cls; info.textContent = " " + text; info.title = title || ""; };
            const authorKey = this._authorKey(authorId);
            if (!this.openpgp) { set("", "", ""); return; }
            if (!authorKey) {
                set("", "No saved key for this sender", "Save this sender's public key to verify their fingerprint.");
                return;
            }
            this._keyInfo(authorKey)
                .then((i) => {
                    if (i.fingerprint.toUpperCase() === fpr) {
                        const self = (() => { const me = this.UserStore && this.UserStore.getCurrentUser && this.UserStore.getCurrentUser(); return me && String(me.id) === String(authorId); })();
                        set("pgp-sig-ok", self ? "✓ Your key's fingerprint" : "✓ Matches this sender's saved key", "This fingerprint matches the key you have saved for this sender.");
                    } else {
                        set("pgp-sig-bad", "⚠ Does not match this sender's saved key", "This fingerprint does not match the key you have saved for this sender. The key may have changed, or this may be an impersonation.");
                    }
                })
                .catch(() => set("pgp-sig-bad", "⚠ Couldn't read the saved key"));
        }

        // Render an inline "save contact" offer for a pasted public key.
        _renderKeyOffer(el, armored, channelId, messageId) {
            el.innerHTML = "";
            const badge = document.createElement("span");
            badge.className = "pgp-badge pgp-min pgp-key-badge";
            badge.textContent = "🔑";
            badge.title = "PGP public key. Click to show the raw key";
            el.appendChild(badge);

            const info = document.createElement("span");
            info.className = "pgp-keyoffer-info";
            info.textContent = "…";
            el.appendChild(info);
            if (this.openpgp) {
                this._keyInfo(armored)
                    .then((i) => { info.textContent = i.fingerprint + " · " + i.algo; })
                    .catch(() => { info.textContent = "⚠ Couldn't read this key"; });
            }

            const offer = document.createElement("span");
            offer.className = "pgp-keyoffer";
            const msg = channelId && this.MessageStore ? this.MessageStore.getMessage(channelId, messageId) : null;
            const author = msg && msg.author ? msg.author : null;
            const me = this.UserStore && this.UserStore.getCurrentUser && this.UserStore.getCurrentUser();
            if (author && me && String(author.id) === String(me.id)) {
                const mine = document.createElement("span");
                mine.className = "pgp-keyoffer-saved";
                mine.textContent = "✓ Your public key";
                offer.appendChild(mine);
            } else if (author) {
                const name = author.username || author.globalName || String(author.id);
                const existing = this.settings.contacts[author.id];
                const sameKey = existing && existing.publicKey &&
                    existing.publicKey.replace(/\s+/g, "") === armored.replace(/\s+/g, "");
                if (sameKey) {
                    const saved = document.createElement("span");
                    saved.className = "pgp-keyoffer-saved";
                    saved.textContent = "✓ Saved contact" + (existing.label ? " · " + existing.label : "");
                    offer.appendChild(saved);
                } else {
                    const save = document.createElement("button");
                    save.className = "pgp-keyoffer-btn";
                    save.textContent = existing
                        ? "Update key for " + (existing.label || name)
                        : "Save contact: " + name;
                    save.onclick = () => {
                        const label = (existing && existing.label) || name;
                        const realId = String(author.id);
                        // Drop any id-pending duplicate for this person (same as the
                        // settings form does) so there aren't two entries, one stale.
                        const lower = label.toLowerCase();
                        for (const [oid, oc] of Object.entries(this.settings.contacts)) {
                            if (oid !== realId && oid.startsWith("name:") && oc.label && oc.label.toLowerCase() === lower) {
                                this._rekeyGroups(oid, realId); delete this.settings.contacts[oid];
                            }
                        }
                        // Preserve the original add date when updating an existing
                        // contact's key; only a brand-new contact gets a fresh date.
                        const addedAt = (existing && existing.addedAt) ? existing.addedAt : Date.now();
                        this.settings.contacts[realId] = { label, publicKey: armored, addedAt };
                        this.save();
                        this.decryptCache.clear();
                        BdApi.UI.showToast('PGP contact "' + label + '" saved', { type: "success" });
                        offer.innerHTML = "";
                        const done = document.createElement("span");
                        done.className = "pgp-keyoffer-saved";
                        done.textContent = "✓ Saved";
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
                .pgp-sig { font-weight: 600; margin-right: 6px; vertical-align: middle; }
                .pgp-sig-ok { color: #3ba55c; }
                .pgp-sig-bad { color: #faa61a; }
                .pgp-revoke-badge { background: rgba(237,66,69,.2); color: #ed4245; }
                /* Card text is normal message size and font; only the emoji
                   badges are small. */
                .pgp-fpr-value { margin-right: 6px; color: var(--text-normal, #dbdee1); }
                .pgp-fpr-note { font-weight: 600; }
                .pgp-badge.pgp-min { background: none; color: inherit; padding: 0; font-weight: 400; }
                .dpgp-contact.dpgp-revoked { opacity: .6; }
                .dpgp-revoked-tag { margin-left: 6px; font-size: 9px; font-weight: 700; letter-spacing: .04em; color: #ed4245; border: 1px solid rgba(237,66,69,.5); border-radius: 3px; padding: 0 4px; vertical-align: middle; }
                .pgp-keyoffer { display: inline; margin-left: 6px; }
                .pgp-keyoffer-info { margin-right: 6px; color: var(--text-normal, #dbdee1); }
                .pgp-keyoffer-btn {
                    border: none; border-radius: 5px; padding: 4px 10px; font-size: 12px; font-weight: 600;
                    cursor: pointer; background: var(--brand-experiment, #5865f2); color: #fff;
                }
                .pgp-keyoffer-btn:hover { filter: brightness(1.1); }
                .pgp-keyoffer-saved { color: #3ba55c; font-weight: 600; }
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
                .dpgp-subhead {
                    font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: .02em;
                    color: var(--header-secondary, #b5bac1); margin-top: 6px; padding-top: 10px;
                    border-top: 1px solid var(--background-modifier-accent, rgba(255,255,255,.07));
                }
                .dpgp-foot { font-size: 11px; color: var(--text-muted, #949ba4); text-align: center; padding-top: 2px; }

                .dpgp-lock-line { display: flex; align-items: center; gap: 8px; font-size: 13px; color: var(--text-normal, #dbdee1); margin: 2px 0 4px; }
                .dpgp-lock-line.warn { color: var(--text-warning, #f0b232); }
                .dpgp-lock-badge { font-size: 11px; flex: none; }
                .dpgp-lock-line .dpgp-btn { margin-left: auto; }

                .dpgp-modal-back {
                    position: fixed; inset: 0; z-index: 100000;
                    display: flex; align-items: center; justify-content: center;
                    background: rgba(0,0,0,.6);
                }
                .dpgp-modal {
                    width: 420px; max-width: calc(100vw - 32px);
                    background: var(--modal-background, #313338); color: var(--text-normal, #dbdee1);
                    border-radius: 8px; padding: 20px; box-shadow: 0 8px 24px rgba(0,0,0,.4);
                    display: flex; flex-direction: column; gap: 12px;
                }
                .dpgp-modal-title { font-size: 18px; font-weight: 700; }
                .dpgp-modal-text { font-size: 13px; color: var(--text-muted, #949ba4); line-height: 1.4; }
                .dpgp-modal-err { font-size: 12px; color: var(--text-danger, #f23f43); }
                .dpgp-modal-remember { display: flex; align-items: center; gap: 8px; font-size: 12px; color: var(--text-muted, #949ba4); cursor: pointer; }
                .dpgp-modal-remember input { width: 15px; height: 15px; }
                .dpgp-modal-btns { display: flex; justify-content: flex-end; gap: 8px; margin-top: 4px; }
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
            let ok = false;
            try { require("electron").clipboard.writeText(text); ok = true; }
            catch (_) { try { navigator.clipboard.writeText(text); ok = true; } catch (_2) {} }
            BdApi.UI.showToast(ok ? what + " copied" : "Couldn't copy " + what, { type: ok ? "success" : "error" });
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
            // Rebuilds (after add/remove/save/...) must not collapse the section
            // the user is working in: remember which sections are open and
            // restore them. A fresh settings open has none, so all start closed.
            const openSections = new Set();
            if (typeof panel.querySelectorAll === "function") {
                panel.querySelectorAll("details.dpgp-sec").forEach((d) => {
                    if (!d.open) return;
                    const t = d.querySelector(".dpgp-sum-title");
                    if (t) openSections.add(t.textContent);
                });
            }
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
                // Collapsed on a fresh open; kept open across rebuilds.
                const d = el("details", "dpgp-sec");
                if (openSections.has(title)) d.open = true;
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
                const eye = btn("Show", "secondary eye", () => {
                    const hidden = input.type === "password";
                    input.type = hidden ? "text" : "password";
                    eye.textContent = hidden ? "Hide" : "Show";
                });
                row.appendChild(input);
                row.appendChild(eye);
                return { row, input };
            };

            // ===== header =====
            const head = el("div", "dpgp-head");
            const ht = el("div", "dpgp-head-text");
            ht.appendChild(el("div", "dpgp-head-title", { textContent: "DiscordPG" }));
            ht.appendChild(el("div", "dpgp-head-sub", { textContent: "End-to-end PGP · v" + config.version }));
            head.appendChild(ht);
            head.appendChild(el("span", "dpgp-pill " + (hasKey ? "ok" : "warn"), { textContent: hasKey ? "Key configured" : "No key yet" }));
            panel.appendChild(head);

            // ===== your keypair (identity + generation) =====
            const idBody = section("Your keypair", hasKey ? "Manage or export your key" : "Create or import a key to begin");

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
                        vAlgo.textContent = vFpr.textContent = vUid.textContent = vDate.textContent = "Unreadable key";
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
                const doDelete = () => {
                    s.publicKey = ""; s.privateKey = ""; s.passphrase = ""; s.rememberPassphrase = false; s.revocationCertificate = "";
                    this._forgetUnlock(); this.decryptCache.clear();
                    this.save();
                    this._buildPanel(panel);
                };
                // Deletion happens ONLY on the explicit confirm button. Cancel and
                // dismiss (Escape / backdrop) must be safe no-ops, so the
                // destructive action is never on the "never mind" path. The nudge
                // to revoke first points at the "Copy revocation certificate"
                // button above.
                idRow.appendChild(btn("Delete keypair", "danger", () => this._confirm(
                    "Delete keypair?",
                    "This permanently removes your keys and passphrase from this device and cannot be undone. If the key may be compromised, cancel and use \"Copy revocation certificate\" above first so your contacts stop using it.",
                    "Delete keypair",
                    doDelete
                )));
            }
            idBody.appendChild(idRow);

            // At-rest protection status, hydrated async (reading the key is async).
            if (hasKey && this.openpgp) {
                const lockRow = el("div", "dpgp-lock");
                idBody.appendChild(lockRow);
                this._keyLockState().then((st) => {
                    lockRow.innerHTML = "";
                    if (!st.hasKey) { lockRow.style.display = "none"; return; }
                    const line = el("div", "dpgp-lock-line");
                    if (!st.readable) {
                        line.className = "dpgp-lock-line warn";
                        line.appendChild(el("span", "dpgp-lock-badge", { textContent: "⚠" }));
                        line.appendChild(el("span", null, { textContent: "Couldn't read this key. See the key details above." }));
                        lockRow.appendChild(line);
                        return;
                    }
                    if (!st.encrypted) {
                        line.className = "dpgp-lock-line warn";
                        line.appendChild(el("span", "dpgp-lock-badge", { textContent: "⚠" }));
                        line.appendChild(el("span", null, { textContent: "No passphrase: your private key is stored unencrypted. Add one below to protect it at rest." }));
                        lockRow.appendChild(line);
                        return;
                    }
                    if (st.unlocked) {
                        line.appendChild(el("span", "dpgp-lock-badge", { textContent: "🔓" }));
                        line.appendChild(el("span", null, { textContent: st.remembered
                            ? "Unlocked · passphrase remembered on this device"
                            : "Unlocked for this session" }));
                        lockRow.appendChild(line);
                    } else {
                        line.appendChild(el("span", "dpgp-lock-badge", { textContent: "🔒" }));
                        line.appendChild(el("span", null, { textContent: "Locked. Enter your passphrase to decrypt and sign." }));
                        const unlockBtn = btn("Unlock", "", async () => {
                            this._unlockDismissed = false;
                            try { await this.getMyKey(); this._scheduleScan(); this._buildPanel(panel); }
                            catch (e) { BdApi.UI.showToast(e.message, { type: "error" }); }
                        });
                        line.appendChild(unlockBtn);
                        lockRow.appendChild(line);
                    }
                }).catch(() => { lockRow.style.display = "none"; });
            }

            const pub = el("textarea", "dpgp-input mono", { value: s.publicKey, spellcheck: false, placeholder: "-----BEGIN PGP PUBLIC KEY BLOCK-----" });
            const priv = el("textarea", "dpgp-input mono", { value: s.privateKey, spellcheck: false, placeholder: "-----BEGIN PGP PRIVATE KEY BLOCK-----" });
            const myPass = passInput("Optional", s.rememberPassphrase ? s.passphrase : (this.sessionPassphrase || ""));
            rawWrap.appendChild(labeled("Public key", pub));
            rawWrap.appendChild(labeled("Private key", priv));
            // Revocation certificate sits between the private key and passphrase.
            const revField = el("div", "dpgp-field");
            revField.appendChild(el("label", "dpgp-label", { textContent: "Revocation certificate" }));
            const revArea = el("textarea", "dpgp-input mono", { value: s.revocationCertificate, spellcheck: false, readOnly: true, placeholder: "Not generated yet." });
            revField.appendChild(revArea);
            const revRow = el("div", "dpgp-row");
            if (s.revocationCertificate) {
                revRow.appendChild(btn("Copy revocation certificate", "secondary", () => this._copy(s.revocationCertificate, "Revocation certificate")));
            } else if (hasKey) {
                const genRevBtn = btn("Generate revocation certificate", "secondary", async () => {
                    genRevBtn.disabled = true; genRevBtn.textContent = "Generating…";
                    try { await this._makeRevocationCert(); this._buildPanel(panel); }
                    catch (e) { BdApi.UI.showToast("Couldn't generate certificate: " + e.message, { type: "error" }); genRevBtn.disabled = false; genRevBtn.textContent = "Generate revocation certificate"; }
                });
                revRow.appendChild(genRevBtn);
            }
            revField.appendChild(revRow);
            revField.appendChild(el("div", "dpgp-muted", { textContent: "Posting this revokes your key." }));
            rawWrap.appendChild(revField);
            rawWrap.appendChild(labeled("Passphrase", myPass.row));

            // Opt-in: persist the passphrase on this device. Off (default) keeps it
            // in memory only, so the key stays encrypted at rest.
            const remOpt = el("div", "dpgp-opt");
            const remText = el("div");
            remText.appendChild(el("div", "dpgp-opt-title", { textContent: "Remember passphrase on this device" }));
            remText.appendChild(el("div", "dpgp-opt-sub", { textContent: "Less secure. Off means you unlock once per session." }));
            remOpt.appendChild(remText);
            const remLab = el("label", "dpgp-switch");
            const remCb = el("input", null, { type: "checkbox", checked: !!s.rememberPassphrase });
            remCb.onchange = () => {
                s.rememberPassphrase = remCb.checked;
                if (remCb.checked) {
                    // Persist whatever passphrase we currently hold (typed here, or
                    // this session's). If we have none yet, it's stored on next unlock.
                    const pass = myPass.input.value || this.sessionPassphrase || s.passphrase || "";
                    s.passphrase = pass;
                    if (pass) this.sessionPassphrase = pass;
                } else {
                    // Keep it in memory for this session, wipe it from disk.
                    if (s.passphrase && this.sessionPassphrase == null) this.sessionPassphrase = s.passphrase;
                    s.passphrase = "";
                }
                this.save();
            };
            remLab.appendChild(remCb);
            remLab.appendChild(el("span", "dpgp-slider"));
            remOpt.appendChild(remLab);
            rawWrap.appendChild(remOpt);

            const saveRow = el("div", "dpgp-row");
            saveRow.appendChild(btn("Save keys", "", () => {
                const newPriv = priv.value.trim();
                // A pasted/changed private key invalidates any cached revocation cert.
                if (newPriv !== s.privateKey) s.revocationCertificate = "";
                s.publicKey = pub.value.trim();
                s.privateKey = newPriv;
                const pass = myPass.input.value;
                // Reset unlock state for the new key, then keep the passphrase in
                // memory (or on disk only if "remember" is on).
                this._forgetUnlock();
                if (s.rememberPassphrase) { s.passphrase = pass; }
                else { s.passphrase = ""; this.sessionPassphrase = pass ? pass : null; }
                this.decryptCache.clear();
                this.save();
                BdApi.UI.showToast("Keys saved", { type: "success" });
                this._buildPanel(panel);
            }));
            rawWrap.appendChild(saveRow);
            idBody.appendChild(rawWrap);

            // Generation is folded into the keypair section (both concern your
            // own key), separated by a labeled divider.
            idBody.appendChild(el("div", "dpgp-subhead", { textContent: "Generate a new keypair" }));
            const genBody = idBody;

            // Algorithm choice first, then identity fields, then passphrase.
            const seg = el("div", "dpgp-seg");
            const bEcc = el("button", "active", { type: "button", textContent: "ECC" });
            const bRsa = el("button", "", { type: "button", textContent: "RSA" });
            seg.appendChild(bEcc);
            seg.appendChild(bRsa);
            genBody.appendChild(labeled("Algorithm", seg));

            const genCurve = el("select", "dpgp-input");
            for (const c of ["curve25519", "ed25519", "nistP256", "nistP384", "nistP521",
                             "brainpoolP256r1", "brainpoolP384r1", "brainpoolP512r1", "secp256k1"]) {
                genCurve.appendChild(el("option", null, { value: c, textContent: c }));
            }
            const curveField = labeled("Curve", genCurve);
            const genRsa = el("select", "dpgp-input");
            for (const b of [2048, 3072, 4096]) {
                genRsa.appendChild(el("option", null, { value: String(b), textContent: b + " bits" }));
            }
            genRsa.value = "4096";
            const rsaField = labeled("Key size", genRsa);
            genBody.appendChild(curveField);
            genBody.appendChild(rsaField);

            const nameGrid = el("div", "dpgp-grid2");
            const genName = el("input", "dpgp-input", { type: "text", placeholder: "Alice (optional)" });
            const genEmail = el("input", "dpgp-input", { type: "text", placeholder: "alice@example.com (optional)" });
            nameGrid.appendChild(labeled("Name", genName));
            nameGrid.appendChild(labeled("Email", genEmail));
            genBody.appendChild(nameGrid);

            const genPass = passInput("Optional", "");
            genBody.appendChild(labeled("Passphrase", genPass.row));

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
                if (!this.openpgp) return BdApi.UI.showToast("OpenPGP is still loading. Try again in a moment.", { type: "error" });
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
                    const pass = genPass.input.value || "";
                    // Fresh key: forget any prior unlock, then hold this passphrase
                    // in memory for the session (on disk only if "remember" is on).
                    this._forgetUnlock();
                    if (s.rememberPassphrase) { s.passphrase = pass; }
                    else { s.passphrase = ""; this.sessionPassphrase = pass ? pass : null; }
                    s.revocationCertificate = (revocationCertificate || "").trim();
                    this.decryptCache.clear();
                    this.save();
                    BdApi.UI.showToast("New keypair generated and saved", { type: "success" });
                    this._buildPanel(panel);
                } catch (e) {
                    BdApi.UI.showToast("Couldn't generate keypair: " + e.message, { type: "error" });
                    genBtn.disabled = false;
                    genBtn.textContent = "Generate keypair";
                }
            });
            genBody.appendChild(genBtn);

            // ===== contacts =====
            const contactIds = Object.keys(s.contacts);
            const conBody = section("Contacts",
                contactIds.length ? contactIds.length + " public key" + (contactIds.length === 1 ? "" : "s") + " stored" : "People you can message");

            // Add/edit form elements are created up front so per-card Edit
            // buttons can reference them; they are appended below the cards.
            let editingId = null; // contact key currently being edited, or null
            const cLabel = el("input", "dpgp-input", { type: "text", placeholder: "Their Discord username (e.g. bob)" });
            const cId = el("input", "dpgp-input mono", { type: "text", placeholder: "Leave blank to resolve from username" });
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
                // Guard against silently clobbering a different contact: if this save
                // resolves onto an existing entry that isn't the one being edited and
                // holds a different key, confirm before replacing it.
                if (s.contacts[id] && id !== editingId && s.contacts[id].publicKey !== key) {
                    const who = s.contacts[id].label || id;
                    const okReplace = await this._confirmAsync(
                        "Replace existing contact key?",
                        "A contact for " + who + " (ID " + id + ") already exists with a different key. Saving replaces that key. Continue?",
                        "Replace");
                    if (!okReplace) return;
                }
                // When editing, replace the original entry even if its key changed.
                const prev = editingId ? s.contacts[editingId] : s.contacts[id];
                const sameKey = prev && prev.publicKey === key;
                const entry = { label, publicKey: key, addedAt: (sameKey && prev.addedAt) ? prev.addedAt : Date.now() };
                // Preserve a verified revocation across an unrelated (label-only)
                // edit; only a new key clears it.
                if (sameKey && prev.revoked) entry.revoked = true;
                if (editingId && editingId !== id) { this._rekeyGroups(editingId, id); delete s.contacts[editingId]; }
                // Drop any id-pending duplicate for the same person once we have a
                // real id, so there aren't two entries (one with a stale key).
                if (!id.startsWith("name:")) {
                    const lower = label.toLowerCase();
                    for (const [oid, oc] of Object.entries(s.contacts)) {
                        if (oid !== id && oid.startsWith("name:") && oc.label && oc.label.toLowerCase() === lower) {
                            this._rekeyGroups(oid, id); delete s.contacts[oid];
                        }
                    }
                }
                s.contacts[id] = entry;
                this.save();
                this.decryptCache.clear(); // signature verdicts depend on contact keys
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
                    "Paste a public key below. Leave the User ID blank to resolve it from the username." }));
            }
            for (const id of contactIds) {
                const c = s.contacts[id];
                const card = el("div", "dpgp-contact" + (c.revoked ? " dpgp-revoked" : ""));
                const info = el("div", "dpgp-contact-info");
                const nameEl = el("div", "dpgp-contact-name", { textContent: c.label || "Unnamed contact" });
                if (c.revoked) nameEl.appendChild(el("span", "dpgp-revoked-tag", { textContent: "REVOKED" }));
                info.appendChild(nameEl);
                const idText = id.startsWith("name:") ? "ID pending, matches by username" : "ID " + id;
                const addedText = c.addedAt ? "  ·  added " + new Date(c.addedAt).toLocaleDateString() : "";
                const meta = el("div", "dpgp-contact-meta mono", { textContent: idText + addedText });
                info.appendChild(meta);
                card.appendChild(info);
                if (this.openpgp) {
                    this._keyInfo(c.publicKey)
                        .then((i) => { meta.textContent = idText + "  ·  " + i.algo + "  ·  " + i.fingerprint + addedText; })
                        .catch(() => { meta.textContent = idText + "  ·  ⚠ unreadable key" + addedText; });
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
                if (c.revoked) {
                    card.appendChild(btn("Clear flag", "secondary eye", () => {
                        delete c.revoked; this.save(); this.decryptCache.clear(); this._buildPanel(panel);
                    }));
                }
                card.appendChild(btn("Remove", "danger", () => {
                    delete s.contacts[id];
                    this._rekeyGroups(id, null); // drop from any channel groups
                    this.save();
                    this.decryptCache.clear(); // signature verdicts depend on contact keys
                    this._buildPanel(panel);
                }));
                conBody.appendChild(card);
            }

            const addGrid = el("div", "dpgp-grid2");
            addGrid.appendChild(labeled("Label / username", cLabel));
            addGrid.appendChild(labeled("User ID (optional)", cId));
            conBody.appendChild(addGrid);
            conBody.appendChild(labeled("Their public key", cKey));
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
            const chBody = section("Encrypted channels", chanIds.length ? chanIds.length + " enabled" : "Where encryption is enabled");
            if (!chanIds.length) {
                chBody.appendChild(el("div", "dpgp-muted", { textContent:
                    "No channels enabled yet. Use /pgp-on in a channel to enable it." }));
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

            const encBody = section("Encryption", "How messages are signed and read");
            mkSwitch(encBody, "signMessages", "Sign outgoing messages", "Recipients can verify the sender");
            mkSwitch(encBody, "autoDecrypt", "Auto-decrypt incoming messages", "Show PGP blocks as readable text");

            const miscBody = section("Display", "Message rendering and command replies");
            mkSwitch(miscBody, "richContent", "Rich content in decrypted messages", "Emojis, links, and media");
            mkSwitch(miscBody, "renderEmojis", "Render custom emojis", "Needs rich content");
            mkSwitch(miscBody, "autoLoadMedia", "Auto-load images & GIFs (opsec risk)", "Reveals your IP to media hosts. Needs rich content");
            mkSwitch(miscBody, "clydeReplies", "Command replies as bot message", "Off = small toast");

            panel.appendChild(el("div", "dpgp-foot", { textContent:
                "Your passphrase is never written to disk unless you enable Remember." }));
        }
    }

    return DiscordPG;
})();
