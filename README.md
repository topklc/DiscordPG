# DiscordPG — Discord Privacy Guard

**DiscordPG (Discord Privacy Guard)** is a [BetterDiscord](https://betterdiscord.app/) plugin that provides end-to-end PGP encryption for Discord messages, built on [OpenPGP.js](https://openpgpjs.org/). All keys and messages use standard ASCII-armored OpenPGP formats and are fully interoperable with GnuPG and any other OpenPGP implementation.

> This is a community project, not a professionally audited security product.
> Read the [Security](#security) section before relying on it. Your private key
> is protected at rest by its passphrase (held in memory, not written to disk
> unless you opt in), and trust is trust-on-first-use.

**Contents:** [Features](#features) · [Installation](#installation) · [Getting started](#getting-started) · [Usage](#usage) · [Security](#security) · [Limitations](#limitations)

## Features

**Key management**
- In-app key generation: ECC (Curve25519, Ed25519, NIST P-256/384/521, Brainpool, secp256k1) or RSA (2048, 3072, or 4096 bit), with optional passphrase protection.
- Passphrase-protected keys are kept encrypted at rest: the passphrase is held in memory only and you unlock once per session, with an optional "remember on this device" for convenience.
- Import and export of armored keypairs.
- Contact keyring: store the public keys of the people you message. Contacts can be added by Discord username alone; the plugin resolves and pins the numeric user ID automatically.
- Automatic contact capture: when someone posts a public key in chat, the plugin renders a compact card with the key's algorithm and fingerprint and a one-click "Save contact" action attributed to the message author.
- Contacts are editable in place (label, user ID, key) and self-heal if saved under an incorrect ID, by matching the sender's username.
- Key revocation: every keypair has a revocation certificate, shown beneath the private key. Deleting your keypair prompts you to copy and publish it first, with an option to bypass. When a valid certificate is posted in chat, every client verifies its signature against the stored key and marks the matching contact revoked; encryption to a revoked key is then blocked until the contact sends a new one. The message author is never trusted, only the signature.

**Encryption**
- Per-channel encryption toggle. With the toggle on, outgoing messages are encrypted to the channel's recipients (detected automatically in direct messages) and to your own key, and optionally signed.
- Recipient targeting via mentions: within an encrypted channel, mentioning a saved contact restricts encryption to that contact only, instead of the channel's group. Encryption only ever happens when the channel toggle is on; a message in a channel with PGP off is always sent as-is, even if it mentions a contact.
- Fail-closed behavior throughout: if encryption cannot be completed for any reason, the message is not sent. Plaintext is never transmitted on an encrypted channel.

**Decryption and display**
- Incoming PGP message blocks are decrypted automatically and rendered inline with a status badge. The badge expands to show the raw armored payload with a copy action.
- Signature verification: a signed message is marked verified only when the signature was made by the message author's saved key, so a valid block replayed under another account is flagged as unverified.
- Optional rich content rendering (disabled by default): custom Discord emoji, clickable links, and inline images. Remote media is click-to-load unless explicitly set to load automatically. See Security considerations.
- Direct image and GIF links embed inline, including Giphy and Imgur pages; remote media is fetched and inlined so Discord's content policy does not block it. Tenor "view" links from Discord's GIF picker have no client-derivable media URL and stay as clickable links, so paste a direct `.gif` URL to embed one.
- Optional minimal badge mode: a plain lock icon in place of the colored status tag.
- A lock indicator in the channel sidebar marks every conversation with encryption enabled.

## Installation

1. Install [BetterDiscord](https://betterdiscord.app/).
2. Copy `DiscordPG.plugin.js` into the BetterDiscord plugins folder (Settings > Plugins > Open Plugins Folder).
3. Enable DiscordPG in the plugins list.
4. On first activation the plugin downloads OpenPGP.js (`openpgp@5`) from jsDelivr into the plugins folder. This requires an internet connection once; afterwards the library is loaded from disk.

## Getting started

Open the plugin settings:

1. Under "Generate a new keypair", choose an algorithm, set a passphrase, and generate. Alternatively, paste an existing armored keypair under "Your keypair" and save. The passphrase protects your key at rest and is not stored; you unlock once per session (a prompt appears the first time a message needs decrypting or signing). Enable "Remember passphrase on this device" only if you accept storing it in plaintext.
2. Copy your public key and send it to the people you want to message. When they post theirs, click the save prompt that appears on the message, or paste the key manually under "Contacts".
3. In the conversation, use `/pgp-on` (or type `.pgp on`) to enable encryption, then chat normally.

## Usage

On BetterDiscord 1.13+ the plugin registers native slash commands: type `/pgp` and
they appear in Discord's autocomplete, replying with a private "only you can see
this" message. They are flat commands (`/pgp-on`, not `/pgp on`) because
BetterDiscord injects commands into Discord's index without the subcommand
expansion real application commands get.

| Command | Effect |
|---|---|
| `/pgp-on` | Enable encryption for the current channel |
| `/pgp-off` | Disable encryption for the current channel |
| `/pgp-status` | Show whether encryption is active here |
| `/pgp-share` | Post your public key into the channel |
| `/pgp-fingerprint` | Post your key's fingerprint (for out-of-band verification) |
| `/pgp-revoke` | Post your revocation certificate and delete your keypair (confirmed) |
| `/pgp-group-add` | Add a saved contact to this channel's recipient group |
| `/pgp-group-remove` | Remove a contact from this channel's group |
| `/pgp-group-list` | List this channel's group members |
| `/pgp-group-clear` | Clear this channel's group |
| `/pgp-help` | List commands |
| `/pgp-debug` | Show plugin state (key, contacts, channel status) |

Every command is also available as a typed message with a `.pgp` prefix (e.g.
`.pgp on`, `.pgp group add @bob`), which works on any BetterDiscord version and
avoids the slash-command menu entirely.

Mention-based targeting: with encryption enabled, `@contact message` encrypts to that contact only, instead of the channel's group. Both real Discord mentions and a plain-text `@label` matching a saved contact's label are recognized. A mention that resolves to a saved contact narrows the recipients to that contact; a mention of yourself or of someone you have no key for is treated as an ordinary mention. The "Encrypted only for ..." toast shows exactly who a targeted message reached.

## Security

This is a community project, not a professionally audited security product. Read
this section before relying on it for anything sensitive.

**What is protected**

- **Message content.** Text you send on an enabled channel is encrypted to the recipients' public keys (and your own) before it leaves your client. Discord and anyone watching the channel see only an armored PGP block.
- **Sender authenticity.** With signing on, messages are signed with your private key. On receipt, a signature is marked verified only when it was made by the message author's saved key, so a valid block replayed under another account is flagged as unverified.
- **Keys at rest.** When your key has a passphrase, it is stored encrypted by OpenPGP's own key protection, and the passphrase is held in memory only; you unlock once per session and it is never written to disk. "Remember on this device" is an explicit opt-in that trades this protection for convenience.
- **Fail-closed sending and editing.** If encryption cannot complete for any reason, the message is not sent; the plugin never falls back to plaintext on an enabled channel, including during startup before it has finished loading. Editing a message re-encrypts the new text as well; an edit that mixes plaintext around the existing block is re-encrypted whole, never posted in the clear.
- **Revocation.** A revocation certificate posted in chat is verified cryptographically (never trusted based on who posted it) and, when it matches a saved contact, blocks further encryption to that key.

**What is NOT protected**

- **Keys without a passphrase, or with "Remember" on.** A key generated without a passphrase is stored **unencrypted**, and enabling "Remember on this device" writes the passphrase to the BetterDiscord data folder in plaintext. In either case, anyone with access to your OS user profile can read the key. Use a passphrase, leave "Remember" off, and do not reuse a passphrase you use elsewhere.
- **Keys in memory.** While the plugin is running and unlocked, your decrypted key and passphrase live in the client's memory; an attacker who can read the process (malware running as you, a memory dump) can recover them. Encryption at rest does not protect a compromised, running endpoint.
- **Metadata.** Discord still sees who is talking to whom, when, how often, and message sizes. Encryption hides content, not relationships.
- **Attachments and embeds.** Only text content is encrypted. Files, images, stickers, reactions, and voice are not. Sending a file on an encrypted channel still uploads it to Discord in the clear, because uploads go through a separate path the plugin does not touch.
- **Endpoint compromise.** If your client or machine is compromised, the attacker has your keys and your decrypted messages.

**Trust model**

Key distribution is **trust-on-first-use**: there is no key server and no certificate authority. When you save a contact's key you are trusting that it belongs to them. For real assurance, **verify fingerprints out of band** (in person or over a trusted channel) before treating a contact as authenticated; the settings panel and the in-chat key card both show the fingerprint, and `/pgp-fingerprint` posts it. The plugin never silently changes a saved key, binds signature verification to the message author, and processes only cryptographically valid revocations.

**Other notes**

- Rich content is off by default: loading remote media in a decrypted message discloses your IP and read time to the media host, and a unique URL can identify you. When on, media is click-to-load and each button names the host.
- OpenPGP.js is downloaded once from jsDelivr on first run. The plugin pins an exact library version and verifies the download against a hard-coded SHA-256 before executing it — and re-verifies the on-disk copy on every load — so a compromised CDN, package, or tampered cache file cannot run code in your client. Remote media (when rich content is enabled) is fetched with a size cap and a timeout, and will not follow a redirect to a different host than the one shown on the "Load media" button.
- Client modifications are against Discord's Terms of Service. Use at your own discretion.

## Limitations

- Discord limits messages to 2000 characters. PGP ciphertext is substantially larger than its plaintext, so only short messages fit; oversized messages are rejected before sending with a notice. Each additional recipient increases ciphertext size.
- Attachments, embeds, stickers, and voice are not encrypted; only text content is.
- Both parties need the plugin. Without it, recipients see the raw armored block.
- The plugin depends on Discord's internal module and DOM structure, which change over time. A Discord update may require a plugin update.

## License

[MIT](LICENSE)
