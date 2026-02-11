package com.diggydwarff.sigilmod.cert;

import com.diggydwarff.sigilmod.crypto.SigilCrypto;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.UUID;

public final class CertPayload {
    private CertPayload() {}

    public static byte[] toSigningBytes(PlayerCertificate cert) {
        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            DataOutputStream out = new DataOutputStream(baos);

            out.writeInt(cert.version);

            // playerName
            byte[] nameBytes = cert.playerName.getBytes(StandardCharsets.UTF_8);
            out.writeInt(nameBytes.length);
            out.write(nameBytes);

            out.writeLong(cert.issuedAtEpochSec);
            out.writeLong(cert.expiresAtEpochSec);

            // serial
            byte[] serialBytes = SigilCrypto.b64d(cert.serialBase64);
            out.writeInt(serialBytes.length);
            out.write(serialBytes);

            // mode discriminator + identity binding
            UUID uuid = cert.uuidAsUuidOrNull();
            if (uuid != null) {
                out.writeByte(1); // ONLINE_UUID payload
                out.writeLong(uuid.getMostSignificantBits());
                out.writeLong(uuid.getLeastSignificantBits());
            } else {
                out.writeByte(2); // OFFLINE_KEYPAIR payload
                byte[] pub = SigilCrypto.b64d(cert.playerPublicKeyBase64);
                out.writeInt(pub.length);
                out.write(pub);
            }

            out.flush();
            return baos.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}