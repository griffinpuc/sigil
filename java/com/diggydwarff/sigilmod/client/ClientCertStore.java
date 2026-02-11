package com.diggydwarff.sigilmod.client;

import com.diggydwarff.sigilmod.config.SigilPaths;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Optional;

public final class ClientCertStore {
    private ClientCertStore() {}

    // ---- Cert + private key ----

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

    public static Optional<String> loadRawCertJsonWithLegacyFallback(String serverId) {
        // 1) Preferred per-server cert
        Optional<String> perServer = loadRawCertJson(serverId);
        if (perServer.isPresent()) return perServer;

        // 2) Legacy global cert (pre-Option-A)
        try {
            Path legacy = SigilPaths.baseDir().resolve("player_cert.json");
            if (!Files.exists(legacy)) return Optional.empty();

            String json = Files.readString(legacy, StandardCharsets.UTF_8);

            // Migrate to per-server folder (client-side server dir)
            Files.createDirectories(SigilPaths.clientServerDir(serverId));
            Files.writeString(SigilPaths.clientCertFile(serverId), json, StandardCharsets.UTF_8);

            return Optional.of(json);
        } catch (Exception e) {
            return Optional.empty();
        }
    }

    // ---- Trust pinning ----

    public static Optional<String> readTrustedFingerprint(String serverId) {
        return readSmallTextFile(SigilPaths.clientTrustedFingerprintFile(serverId));
    }

    public static void writeTrustedFingerprint(String serverId, String fingerprintBase64) {
        writeSmallTextFile(SigilPaths.clientTrustedFingerprintFile(serverId), fingerprintBase64);
    }

    public static Optional<String> readLastSeenFingerprint(String serverId) {
        return readSmallTextFile(SigilPaths.clientLastSeenFingerprintFile(serverId));
    }

    public static void writeLastSeenFingerprint(String serverId, String fingerprintBase64) {
        writeSmallTextFile(SigilPaths.clientLastSeenFingerprintFile(serverId), fingerprintBase64);
    }

    public static String serverDirPathString(String serverId) {
        return SigilPaths.clientServerDir(serverId).toString().replace('\\', '/');
    }

    public static String fingerprintToBase64(byte[] fingerprintBytes) {
        return Base64.getEncoder().encodeToString(fingerprintBytes);
    }

    private static Optional<String> readSmallTextFile(Path p) {
        try {
            if (!Files.exists(p)) return Optional.empty();
            return Optional.of(Files.readString(p, StandardCharsets.UTF_8).trim());
        } catch (Exception e) {
            return Optional.empty();
        }
    }

    private static void writeSmallTextFile(Path p, String contents) {
        try {
            Files.createDirectories(p.getParent());
            Files.writeString(p, contents.trim() + "\n", StandardCharsets.UTF_8);
        } catch (Exception ignored) {
        }
    }
}
