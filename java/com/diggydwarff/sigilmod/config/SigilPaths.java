package com.diggydwarff.sigilmod.config;

import net.minecraftforge.fml.loading.FMLPaths;

import java.nio.file.Path;

public final class SigilPaths {
    private SigilPaths() {}

    public static Path baseDir() { return FMLPaths.CONFIGDIR.get().resolve("sigil"); }
    public static Path keysDir() { return baseDir().resolve("keys"); }

    // Issued certs
    public static Path issuedDir() { return baseDir().resolve("issued"); }

    // Organize issued certs:
    // - ONLINE_UUID: issued/by_uuid/<uuid>/<serial>.json
    // - OFFLINE_KEYPAIR: issued/by_name/<name>/<serial>.json
    public static Path issuedByUuidDir(String uuid) { return issuedDir().resolve("by_uuid").resolve(safeSegment(uuid)); }
    public static Path issuedByNameDir(String name) { return issuedDir().resolve("by_name").resolve(safeSegment(name)); }

    public static Path revokedFile() { return baseDir().resolve("revoked.json"); }

    // server signing keys
    public static Path privateKeyFile() { return keysDir().resolve("server_ed25519_private.key"); }
    public static Path publicKeyFile()  { return keysDir().resolve("server_ed25519_public.key"); }

    // Client per-server credential folders
    public static Path serversDir() { return baseDir().resolve("servers"); }
    public static Path serverDir(String serverId) { return serversDir().resolve(serverId); }
    public static Path clientServerDir(String serverId) { return serverDir(serverId); }

    public static Path clientCertFile(String serverId) { return clientServerDir(serverId).resolve("player_cert.json"); }
    public static Path clientPrivateKeyFile(String serverId) { return clientServerDir(serverId).resolve("player_ed25519_private.key"); }

    // Trust pinning files (client)
    public static Path clientTrustedFingerprintFile(String serverId) {
        return clientServerDir(serverId).resolve("trusted_fingerprint.txt");
    }
    public static Path clientLastSeenFingerprintFile(String serverId) {
        return clientServerDir(serverId).resolve("last_seen_fingerprint.txt");
    }

    // Server-side provisioning bundles
    public static Path provisionedDir() { return baseDir().resolve("provisioned"); }
    public static Path provisionedServerDir(String playerName, String serverId) {
        return provisionedDir().resolve(safeSegment(playerName)).resolve(serverId);
    }
    public static Path provisionedCertFile(String playerName, String serverId) {
        return provisionedServerDir(playerName, serverId).resolve("player_cert.json");
    }
    public static Path provisionedPrivateKeyFile(String playerName, String serverId) {
        return provisionedServerDir(playerName, serverId).resolve("player_ed25519_private.key");
    }

    // NEW: include trust pin in provisioned bundle
    public static Path provisionedTrustedFingerprintFile(String playerName, String serverId) {
        return provisionedServerDir(playerName, serverId).resolve("trusted_fingerprint.txt");
    }

    private static String safeSegment(String s) {
        if (s == null || s.isBlank()) return "_";
        // Keep it filesystem-safe and predictable
        return s.replaceAll("[^a-zA-Z0-9._-]", "_");
    }

    // Issued "client bundle" folders (what you zip and give to player)
    // ONLINE_UUID: issued/by_uuid/<uuid>/bundle_<serial>/...
    // OFFLINE_KEYPAIR: issued/by_name/<name>/bundle_<serial>/...
    public static Path issuedBundleDirForOnline(String uuid, String serialBase64) {
        return issuedByUuidDir(uuid).resolve("bundle_" + safeSegment(serialBase64));
    }
    public static Path issuedBundleDirForOffline(String name, String serialBase64) {
        return issuedByNameDir(name).resolve("bundle_" + safeSegment(serialBase64));
    }

    public static Path issuedBundleCertFile(Path bundleDir) {
        return bundleDir.resolve("player_cert.json");
    }
    public static Path issuedBundleTrustedFingerprintFile(Path bundleDir) {
        return bundleDir.resolve("trusted_fingerprint.txt");
    }
}
