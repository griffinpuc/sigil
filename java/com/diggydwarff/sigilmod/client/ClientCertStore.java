package com.diggydwarff.sigilmod.client;

import com.diggydwarff.sigilmod.cert.CertCodec;
import com.diggydwarff.sigilmod.cert.PlayerCertificate;
import com.diggydwarff.sigilmod.config.SigilPaths;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Optional;

public final class ClientCertStore {
    private ClientCertStore() {}

    public static Optional<String> loadRawCertJson(String serverId) {
        try {
            var path = SigilPaths.clientCertFile(serverId);
            if (!Files.exists(path)) return Optional.empty();
            return Optional.of(Files.readString(path, StandardCharsets.UTF_8));
        } catch (Exception e) {
            return Optional.empty();
        }
    }

    public static Optional<PrivateKey> loadPrivateKey(String serverId) {
        try {
            var path = SigilPaths.clientPrivateKeyFile(serverId);
            if (!Files.exists(path)) return Optional.empty();

            String b64 = Files.readString(path, StandardCharsets.UTF_8).trim();
            byte[] enc = Base64.getDecoder().decode(b64);

            KeyFactory kf = KeyFactory.getInstance("Ed25519");
            return Optional.of(kf.generatePrivate(new PKCS8EncodedKeySpec(enc)));
        } catch (Exception e) {
            return Optional.empty();
        }
    }
}