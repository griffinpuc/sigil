package com.diggydwarff.sigilmod.config;

import net.minecraftforge.fml.loading.FMLPaths;

import java.nio.file.Path;

public final class SigilPaths {
    private SigilPaths() {}

    public static Path baseDir() { return FMLPaths.CONFIGDIR.get().resolve("sigil"); }
    public static Path keysDir() { return baseDir().resolve("keys"); }
    public static Path issuedDir() { return baseDir().resolve("issued"); }
    public static Path revokedFile() { return baseDir().resolve("revoked.json"); }

    // server signing keys
    public static Path privateKeyFile() { return keysDir().resolve("server_ed25519_private.key"); }
    public static Path publicKeyFile()  { return keysDir().resolve("server_ed25519_public.key"); }

    // NEW: client per-server credential folders
    public static Path serversDir() { return baseDir().resolve("servers"); }
    public static Path serverDir(String serverId) { return serversDir().resolve(serverId); }
    public static Path clientCertFile(String serverId) { return serverDir(serverId).resolve("player_cert.json"); }
    public static Path clientPrivateKeyFile(String serverId) { return serverDir(serverId).resolve("player_ed25519_private.key"); }

    // NEW: server-side provisioning bundles for admins to distribute
    public static Path provisionedDir() { return baseDir().resolve("provisioned"); }
    public static Path provisionedServerDir(String playerName, String serverId) {
        return provisionedDir().resolve(playerName).resolve(serverId);
    }
    public static Path provisionedCertFile(String playerName, String serverId) {
        return provisionedServerDir(playerName, serverId).resolve("player_cert.json");
    }
    public static Path provisionedPrivateKeyFile(String playerName, String serverId) {
        return provisionedServerDir(playerName, serverId).resolve("player_ed25519_private.key");
    }
}