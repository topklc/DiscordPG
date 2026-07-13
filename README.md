# DiscordPG

A [BetterDiscord](https://betterdiscord.app/) plugin that adds **end-to-end PGP encryption** to Discord messages using [OpenPGP.js](https://openpgpjs.org/). Everything is standard **ASCII-armored** PGP, so it interoperates with GnuPG and any other OpenPGP tool.

## Features

- 🔑 **In-app key generation** — ECC (Curve25519, NIST, Brainpool, secp256k1) or RSA (2048/3072/4096-bit).
- 📥 **Import / export** your own armored keypair and your contacts' armored public keys.
- 🔒 **Encrypt on send** — per-channel toggle; messages are encrypted to the channel's recipients (auto-detected in DMs) and to yourself, optionally signed.
- 🎯 **@mention targeting** — mention a saved contact (or type `@theirlabel`) to encrypt ONLY for them; a message *starting* with the mention works even in channels without the toggle. Contacts saved with a wrong User ID self-heal by username match.
- 🔓 **Auto-decrypt on receive** — incoming `-----BEGIN PGP MESSAGE-----` blocks are decrypted inline with a badge; click the badge to view/copy the raw armored payload.
- ✅ **Sidebar indicator** — a small 🔒 next to every PGP-enabled channel/DM.
- 💬 **Chat commands** — `/pgp on | off | status | debug` (also `.pgp …` if Discord's slash menu interferes).

## Install

1. Install [BetterDiscord](https://betterdiscord.app/).
2. Copy `DiscordPG.plugin.js` into your BetterDiscord **plugins** folder
   (Settings → Plugins → *Open Plugins Folder*).
3. Enable **DiscordPG** in the Plugins list.
4. On first run it downloads OpenPGP.js (`openpgp@5`) from jsDelivr into the plugins
   folder as `.openpgp.min.js`. Requires an internet connection once.

## Setup

Open the plugin's settings (gear icon next to it):

1. **Generate a new keypair** — pick ECC or RSA, set a passphrase, click *Generate*. (Or paste an existing armored keypair and click *Save keys*.)
2. **Copy public key** and send it to the people you want to talk to.
3. **Add a contact** — paste their armored public key. For DMs, set the **User ID**
   to that person's Discord ID so their key is selected automatically
   (enable Developer Mode → right-click user → *Copy User ID*).

## Usage

In any channel:

```
/pgp on       enable encryption for this channel
/pgp off      disable it
/pgp status   show current state
```

With encryption on, just type normally — outgoing messages are encrypted (and signed if enabled). Incoming PGP blocks are decrypted automatically and shown with a 🔓 badge.

## Limitations & security

- **Your private key and passphrase are stored in plaintext** in the BetterDiscord data
  folder. Anyone with access to your machine profile can read them.
- Discord caps messages at **2000 characters**. PGP ciphertext is bulky, so only short
  messages fit; longer ones are rejected before sending (you'll get a toast).
- Client mods violate Discord's ToS in the strict sense; use at your own risk.
- OpenPGP.js is fetched from a CDN on first run. If you need real assurance, review the
  code and pin/verify the library hash yourself.
