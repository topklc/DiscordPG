# DiscordPG

A [BetterDiscord](https://betterdiscord.app/) plugin that provides end-to-end PGP encryption for Discord messages, built on [OpenPGP.js](https://openpgpjs.org/). All keys and messages use standard ASCII-armored OpenPGP formats and are fully interoperable with GnuPG and any other OpenPGP implementation.

## Features

**Key management**
- In-app key generation: ECC (Curve25519, Ed25519, NIST P-256/384/521, Brainpool, secp256k1) or RSA (2048, 3072, or 4096 bit), with optional passphrase protection.
- Import and export of armored keypairs.
- Contact keyring: store the public keys of the people you message. Contacts can be added by Discord username alone; the plugin resolves and pins the numeric user ID automatically.
- Automatic contact capture: when someone posts a public key in chat, the plugin renders a compact card with the key's algorithm and fingerprint and a one-click "Save contact" action attributed to the message author.
- Contacts are editable in place (label, user ID, key) and self-heal if saved under an incorrect ID, by matching the sender's username.
- Key revocation: every keypair has a revocation certificate, shown beneath the private key. Deleting your keypair prompts you to copy and publish it first, with an option to bypass. When a valid certificate is posted in chat, every client verifies its signature against the stored key and marks the matching contact revoked; encryption to a revoked key is then blocked until the contact sends a new one. The message author is never trusted, only the signature.

**Encryption**
- Per-channel encryption toggle. With the toggle on, outgoing messages are encrypted to the channel's recipients (detected automatically in direct messages) and to your own key, and optionally signed.
- Recipient targeting via mentions: mentioning a saved contact restricts encryption to that contact only. A message that begins with the mention is encrypted even in channels where the toggle is off, enabling one-off private messages.
- Fail-closed behavior throughout: if encryption cannot be completed for any reason, the message is not sent. Plaintext is never transmitted on an encrypted channel.

**Decryption and display**
- Incoming PGP message blocks are decrypted automatically and rendered inline with a status badge. The badge expands to show the raw armored payload with a copy action.
- Optional rich content rendering (disabled by default): custom Discord emoji, clickable links, and inline images. Remote media is click-to-load unless explicitly set to load automatically. See Security considerations.
- Optional minimal badge mode: a plain lock icon in place of the colored status tag.
- A lock indicator in the channel sidebar marks every conversation with encryption enabled.

## Installation

1. Install [BetterDiscord](https://betterdiscord.app/).
2. Copy `DiscordPG.plugin.js` into the BetterDiscord plugins folder (Settings > Plugins > Open Plugins Folder).
3. Enable DiscordPG in the plugins list.
4. On first activation the plugin downloads OpenPGP.js (`openpgp@5`) from jsDelivr into the plugins folder. This requires an internet connection once; afterwards the library is loaded from disk.

## Getting started

Open the plugin settings:

1. Under "Generate a new keypair", choose an algorithm, set a passphrase, and generate. Alternatively, paste an existing armored keypair under "My identity" and save.
2. Copy your public key and send it to the people you want to message. When they post theirs, click the save prompt that appears on the message, or paste the key manually under "Contacts".
3. In the conversation, type `/pgp on` to enable encryption, then chat normally.

## Usage

| Command | Effect |
|---|---|
| `/pgp on` | Enable encryption for the current channel |
| `/pgp off` | Disable encryption for the current channel |
| `/pgp status` | Show whether encryption is active here |
| `/pgp debug` | Show plugin state (key, contacts, channel status) |

Every command is also available with a `.pgp` prefix, which avoids Discord's slash-command menu.

Mention-based targeting: with encryption enabled, `@contact message` encrypts to that contact only, instead of all channel recipients. Both real Discord mentions and a plain-text `@label` matching a saved contact's label are recognized. If a mentioned user has no saved key, the send is blocked and the missing user is named in the error.

## Security considerations

- The private key and passphrase are stored unencrypted in the BetterDiscord data folder. Anyone with access to your OS user profile can read them. Do not use a passphrase you use elsewhere.
- Message content is end-to-end encrypted, but metadata is not: Discord still sees who is messaging whom, when, and message sizes.
- Loading remote media referenced in a decrypted message reveals your IP address and read time to the media host, and a unique URL can identify you specifically. For this reason rich content is off by default and media is click-to-load; each load button names the host it will contact.
- Custom emoji rendering fetches images from Discord's CDN, which discloses the emoji ID to Discord.
- OpenPGP.js is fetched from a CDN on first run. Review the plugin source and pin or verify the library yourself if your threat model requires it.
- Client modifications are against Discord's Terms of Service. Use at your own discretion.

## Limitations

- Discord limits messages to 2000 characters. PGP ciphertext is substantially larger than its plaintext, so only short messages fit; oversized messages are rejected before sending with a notice. Each additional recipient increases ciphertext size.
- Attachments, embeds, stickers, and voice are not encrypted; only text content is.
- Both parties need the plugin. Without it, recipients see the raw armored block.
- The plugin depends on Discord's internal module and DOM structure, which change over time. A Discord update may require a plugin update.
