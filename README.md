# Sigil

**Sigil** is a Forge security mod that enforces **server-authenticated player access** using **cryptographically signed certificates**.

If enabled, players who do not successfully complete the Sigil authentication handshake are **disconnected during login**.

Sigil is designed for servers that want **explicit cryptographic control over who may connect**, including **offline-mode servers**, without relying solely on Mojang authentication.

---

## Features

- Server-signed player certificates (**Ed25519**)
- Two identity modes:
  - **ONLINE_UUID** – certificate bound to Mojang UUID + player name
  - **OFFLINE_KEYPAIR** – certificate bound to a player Ed25519 keypair
- **Per-server** client credential folders
- **Server trust pinning** (prevents MITM and key exfiltration)
- Admin-side provisioning and issue bundles (ready-to-zip)
- Certificate revocation support
- Sliding-window **rate limiting** for auth failures
- Deterministic server identity via signing-key fingerprint
- Hardened challenge–response proof:
  `protocolVersion || serverFingerprint || challenge`

---

## Supported Versions

- **Minecraft:** 1.20.1
- **Loader:** Forge

Do **not** assume compatibility with other 1.20.x versions unless explicitly tested.

---

## Server Installation

1. Install Sigil on the server.
2. Start the server once (generates keys and config).
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

rateLimitWindowSeconds = 30
rateLimitMaxAttempts = 10
acceptLegacyProof = true
```

### Key Options

- `identityMode`
  - `ONLINE_UUID` – requires Mojang-authenticated UUIDs
  - `OFFLINE_KEYPAIR` – cryptographic identity, works in offline mode

- `rateLimitWindowSeconds` / `rateLimitMaxAttempts`
  Limits repeated failed authentication attempts by IP and UUID.

- `acceptLegacyProof`
  Allows older clients that sign the raw challenge instead of the hardened payload.

---

## Server Identity & Keys

On first run, Sigil generates a **server Ed25519 signing keypair**.

```
config/sigil/keys/
├── server_ed25519_private.key
└── server_ed25519_public.key
```

To display the server fingerprint:
```
/sigil pubkey
```

The fingerprint:
- Uniquely identifies the server
- Derives the **serverId**
- Is pinned by clients for trust verification

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

---

### `issueUuid` — ONLINE_UUID

Issues a certificate bound to a **specific Mojang UUID and player name**.

Sigil creates:
- An archival copy under `config/sigil/issued/`
- A **ready-to-zip client bundle** containing:
  - `player_cert.json`
  - `trusted_fingerprint.txt`

The bundle is what you distribute to the player.

---

### `provision` — OFFLINE_KEYPAIR (Recommended)

Generates a **new Ed25519 keypair** and issues a matching certificate.

Output:
```
config/sigil/provisioned/<player>/<serverId>/
├── player_cert.json
├── player_ed25519_private.key
└── trusted_fingerprint.txt
```

This bundle already includes **server trust pinning**.

**WARNING:**  
`player_ed25519_private.key` is equivalent to a password.  
If leaked, revoke the certificate immediately.

---

### `issueKey` — OFFLINE_KEYPAIR (Advanced)

Issues a certificate for an **existing Ed25519 public key**.

- Public key must be **X.509 base64**
- Does NOT generate a private key
- A trust-pinned bundle is still generated for the client

---

## Client Setup

Sigil **must be installed client-side**.

### Installing a Bundle (Recommended)

For both ONLINE_UUID and OFFLINE_KEYPAIR:

1. Admin provides a bundle folder.
2. Player copies **all files** into:
```
<minecraft>/config/sigil/servers/<serverId>/
```

No additional setup is required.

---

### Manual Setup (Advanced)

If installing files manually, the client **must** have:

```
config/sigil/servers/<serverId>/
├── player_cert.json
├── trusted_fingerprint.txt
└── (OFFLINE only) player_ed25519_private.key
```

Without `trusted_fingerprint.txt`, the client will **refuse to send credentials**.

---

## Client Trust Configuration

File:
```
config/sigil-client.toml
```

Option:
```toml
[sigil]
autoTrustFirstSeen = false
```

- When `false` (default): trust must be pre-pinned
- When `true`: first-seen server fingerprint is pinned automatically

Auto-trust is intended for **development and first-time bootstrap only**.

---

## Security Notes

- Offline private keys are **password-equivalent**
- Trust pinning prevents MITM and credential exfiltration
- Server key changes will hard-fail client connections
- Revocation takes effect immediately

---

## Disclaimer

Sigil enforces **access control**, not anti-cheat.
