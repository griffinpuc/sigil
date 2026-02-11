# Sigil

**Sigil** is a Forge security mod that enforces **server-authenticated player access** using **cryptographically signed certificates**.
If enabled, players who do not present a valid Sigil certificate are disconnected during join.

Sigil is intended for servers that want **explicit, cryptographic control over who may connect**, beyond vanilla UUID checks.

---

## Features

- Server-signed player certificates (Ed25519)
- Two identity modes:
  - **ONLINE_UUID** – certificate bound to UUID + player name
  - **OFFLINE_KEYPAIR** – certificate bound to player public key
- **Per-server** client credential folders
- Admin-side provisioning bundles
- Certificate revocation support
- Deterministic server identity via signing key fingerprint

---

## Supported Versions

- **Minecraft:** 1.20.1
- **Loader:** Forge

Do **not** assume compatibility with other 1.20.x versions unless explicitly tested.

---

## Server Installation

1. Install Sigil on the server.
2. Start the server once (to generate keys and config).
3. Stop the server.
4. Configure `sigil-server.toml`.
5. Restart the server.

---

## Server Configuration

File:
```
config/sigil-server.toml
```

Example:
```toml
[sigil]
requireCert = true
handshakeTimeoutSeconds = 5
defaultCertDaysValid = 365
identityMode = "ONLINE_UUID"
enforceNameMatch = true
```

---

## Server Identity & Keys

On first run, Sigil generates a **server Ed25519 signing keypair**.

Key locations:
```
config/sigil/keys/
├── server_ed25519_private.key
└── server_ed25519_public.key
```

To display the server public key fingerprint:
```
/sigil pubkey
```

The fingerprint is used to derive a stable **serverId**, which clients use for per-server credential storage.

---

## Admin Commands

All commands require **OP (permission level 3)**.

```
/sigil issueUuid <uuid> <name> [daysValid]
/sigil issueKey <name> <publicKeyBase64> [daysValid]
/sigil provision <name> [daysValid]
/sigil revoke <serialBase64>
/sigil pubkey
```

### Command Descriptions

#### `issueUuid` — ONLINE_UUID (Online-mode servers)
Issues a certificate bound to a **specific Minecraft UUID and player name**.

- Intended for **online-mode** servers
- Relies on Mojang authentication for identity
- The certificate acts as a **server-signed allow-list entry**
- No client private key is required

Use this when you want:
- Time-limited or revocable access
- An extra authorization layer on top of Mojang auth

---

#### `provision` — OFFLINE_KEYPAIR (Recommended for offline/private servers)
Generates a **new Ed25519 keypair** and issues a matching certificate.

- Intended for **offline-mode**, LAN, or private servers
- Provides true cryptographic identity (proof of key possession)
- Generates a complete bundle for the player

Output:
```
config/sigil/provisioned/<player>/<serverId>/
├── player_cert.json
└── player_ed25519_private.key
```

Use this when you want:
- Strong identity guarantees
- No reliance on Mojang authentication
- Minimal player-side setup errors

---

#### `issueKey` — OFFLINE_KEYPAIR (Advanced / manual)
Issues a certificate for an **existing Ed25519 public key** supplied by the admin.

- Requires a **base64-encoded Ed25519 public key (X.509)**
- Does NOT generate a private key
- Intended for advanced users managing their own keys

Use this when:
- Players already have their own keypairs
- You integrate Sigil with an external identity system

---

## Client Setup

Sigil **must be installed client-side**.

### ONLINE_UUID

Player installs the issued certificate to:
```
<minecraft>/config/sigil/servers/<serverId>/player_cert.json
```

Legacy path `config/sigil/player_cert.json` is automatically migrated on first connect.

---

### OFFLINE_KEYPAIR

Player installs both files to:
```
<minecraft>/config/sigil/servers/<serverId>/
├── player_cert.json
└── player_ed25519_private.key
```

---

## Security Notes

- OFFLINE private keys are equivalent to passwords
- Revoke certificates immediately if compromised
- Do not widen Minecraft version support without testing

---

## Disclaimer

Sigil enforces **access control**, not anti-cheat.
