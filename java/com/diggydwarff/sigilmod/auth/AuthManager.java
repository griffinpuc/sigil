package com.diggydwarff.sigilmod.auth;

import com.diggydwarff.sigilmod.cert.CertCodec;
import com.diggydwarff.sigilmod.cert.CertPayload;
import com.diggydwarff.sigilmod.cert.PlayerCertificate;
import com.diggydwarff.sigilmod.config.SigilConfig;
import com.diggydwarff.sigilmod.crypto.KeyManager;
import com.diggydwarff.sigilmod.crypto.SigilCrypto;
import com.diggydwarff.sigilmod.net.C2SAuthResponse;
import com.diggydwarff.sigilmod.net.S2CAuthChallenge;
import com.diggydwarff.sigilmod.net.SigilNetwork;
import com.diggydwarff.sigilmod.revoke.RevocationList;
import net.minecraft.network.chat.Component;
import net.minecraft.server.MinecraftServer;
import net.minecraft.server.level.ServerPlayer;
import net.minecraftforge.network.PacketDistributor;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.Arrays;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

public final class AuthManager {
    private static final AuthManager INSTANCE = new AuthManager();
    public static AuthManager get() { return INSTANCE; }

    private final Map<UUID, PendingAuth> pending = new ConcurrentHashMap<>();
    private volatile boolean loaded = false;

    private AuthManager() {}

    public void ensureLoaded() {
        if (loaded) return;
        KeyManager.loadOrCreate();
        RevocationList.get().load();
        loaded = true;
    }

    private IdentityMode identityMode() {
        String raw = SigilConfig.IDENTITY_MODE.get();
        if (raw == null) return IdentityMode.ONLINE_UUID;
        return switch (raw.trim().toUpperCase()) {
            case "OFFLINE_KEYPAIR" -> IdentityMode.OFFLINE_KEYPAIR;
            default -> IdentityMode.ONLINE_UUID;
        };
    }

    public void onPlayerJoin(ServerPlayer player) {
        // Never enforce Sigil on singleplayer/integrated server
        if (player.getServer().isSingleplayer()) return;
        if (!SigilConfig.REQUIRE_CERT.get()) return;

        ensureLoaded();

        byte[] challenge = SigilCrypto.randomBytes(32);
        int timeoutSec = SigilConfig.HANDSHAKE_TIMEOUT_SECONDS.get();
        long deadline = player.getServer().getTickCount() + (timeoutSec * 20L);

        pending.put(player.getUUID(), new PendingAuth(challenge, deadline));

        S2CAuthChallenge msg = new S2CAuthChallenge(
                1,
                challenge,
                KeyManager.get().publicKeyFingerprint()
        );

        SigilNetwork.CHANNEL.send(PacketDistributor.PLAYER.with(() -> player), msg);
    }

    public void onPlayerQuit(ServerPlayer player) {
        pending.remove(player.getUUID());
    }

    public void onResponse(ServerPlayer player, C2SAuthResponse msg) {
        if (player.getServer().isSingleplayer()) return;
        if (!SigilConfig.REQUIRE_CERT.get()) return;

        PendingAuth pa = pending.get(player.getUUID());
        if (pa == null) return;

        AuthResult res = verify(player, pa, msg);
        if (res == AuthResult.SUCCESS) {
            pending.remove(player.getUUID());
            player.sendSystemMessage(AuthMessages.success());
            System.out.println("[Sigil] Auth success: " + player.getGameProfile().getName());
            return;
        }

        pa.lastFailReason = res.name();
        disconnect(player, AuthMessages.kick(res));
        System.out.println("[Sigil] Auth failed (" + res.name() + "): " + player.getGameProfile().getName());
    }

    public void tick(MinecraftServer server) {
        if (server.isSingleplayer()) return;
        if (!SigilConfig.REQUIRE_CERT.get()) return;
        if (!loaded) return;

        long now = server.getTickCount();

        for (Map.Entry<UUID, PendingAuth> e : pending.entrySet()) {
            ServerPlayer p = server.getPlayerList().getPlayer(e.getKey());
            if (p == null) continue;

            PendingAuth pa = e.getValue();
            if (now > pa.deadlineGameTime) {
                disconnect(p, Component.literal(
                        "Sigil Authentication Failed\n" +
                                "Handshake timed out.\n" +
                                "Please contact the server administrator."
                ));
                pending.remove(e.getKey());
                System.out.println("[Sigil] Auth failed (HANDSHAKE_TIMEOUT): " + p.getGameProfile().getName());
            }
        }
    }

    private AuthResult verify(ServerPlayer player, PendingAuth pa, C2SAuthResponse msg) {
        if (msg.protocolVersion != 1) return AuthResult.BAD_PROTOCOL;
        if (!Arrays.equals(pa.challenge, msg.challengeEcho)) return AuthResult.CHALLENGE_MISMATCH;
        if (msg.certJson == null || msg.certJson.isBlank()) return AuthResult.MISSING_CERT;

        final PlayerCertificate cert;
        try {
            cert = CertCodec.fromJson(msg.certJson);
        } catch (Exception ex) {
            return AuthResult.INVALID_CERT_JSON;
        }

        // Required fields (common)
        if (cert.playerName == null || cert.playerName.isBlank()) return AuthResult.INVALID_CERT_JSON;
        if (cert.serialBase64 == null || cert.serialBase64.isBlank()) return AuthResult.INVALID_CERT_JSON;
        if (cert.signatureBase64 == null || cert.signatureBase64.isBlank()) return AuthResult.INVALID_CERT_JSON;

        // Expiry
        long now = Instant.now().getEpochSecond();
        if (cert.expiresAtEpochSec <= now) return AuthResult.EXPIRED;

        // Revocation (by serial)
        if (RevocationList.get().isRevoked(cert.serialBase64)) return AuthResult.REVOKED;

        // Optional name enforcement
        if (SigilConfig.ENFORCE_NAME_MATCH.get()) {
            String serverName = player.getGameProfile().getName();
            if (!serverName.equals(cert.playerName)) return AuthResult.NAME_MISMATCH;
        }

        // Verify server signature (common)
        byte[] payload = CertPayload.toSigningBytes(cert);
        byte[] serverSig = SigilCrypto.b64d(cert.signatureBase64);
        boolean serverOk = SigilCrypto.verifyEd25519(KeyManager.get().publicKey(), payload, serverSig);
        if (!serverOk) return AuthResult.INVALID_SIGNATURE;

        // Mode-specific checks
        IdentityMode mode = identityMode();

        if (mode == IdentityMode.ONLINE_UUID) {
            if (cert.uuid == null || cert.uuid.isBlank()) return AuthResult.INVALID_CERT_JSON;
            UUID u = cert.uuidAsUuidOrNull();
            if (u == null) return AuthResult.INVALID_CERT_JSON;
            if (!player.getUUID().equals(u)) return AuthResult.UUID_MISMATCH;
            return AuthResult.SUCCESS;
        }

        // OFFLINE_KEYPAIR
        if (cert.playerPublicKeyBase64 == null || cert.playerPublicKeyBase64.isBlank()) return AuthResult.MISSING_PUBLIC_KEY;
        if (msg.clientProofSig == null || msg.clientProofSig.length == 0) return AuthResult.MISSING_CLIENT_PROOF;

        final PublicKey playerPub;
        try {
            byte[] x509 = SigilCrypto.b64d(cert.playerPublicKeyBase64);
            KeyFactory kf = KeyFactory.getInstance("Ed25519");
            playerPub = kf.generatePublic(new X509EncodedKeySpec(x509));
        } catch (Exception e) {
            return AuthResult.MISSING_PUBLIC_KEY;
        }

        // Proof: client signs server challenge
        boolean proofOk = SigilCrypto.verifyEd25519(playerPub, msg.challengeEcho, msg.clientProofSig);
        return proofOk ? AuthResult.SUCCESS : AuthResult.INVALID_CLIENT_PROOF;
    }

    private void disconnect(ServerPlayer p, Component reason) {
        p.connection.disconnect(reason);
    }

    private enum IdentityMode {
        ONLINE_UUID,
        OFFLINE_KEYPAIR
    }
}