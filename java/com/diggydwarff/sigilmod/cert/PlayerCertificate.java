package com.diggydwarff.sigilmod.cert;

import java.util.UUID;

public class PlayerCertificate {
    public int version = 1;

    public String playerName;

    // ONLINE_UUID mode
    public String uuid; // may be null in OFFLINE_KEYPAIR

    // OFFLINE_KEYPAIR mode
    public String playerPublicKeyBase64; // X.509 encoded public key, Base64 (may be null in ONLINE_UUID)

    public long issuedAtEpochSec;
    public long expiresAtEpochSec;

    // NEW: revoke by serial
    public String serialBase64; // required in both modes

    // server signature over canonical payload
    public String signatureBase64;

    public UUID uuidAsUuidOrNull() {
        if (uuid == null || uuid.isBlank()) return null;
        return UUID.fromString(uuid);
    }
}