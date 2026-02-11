package com.diggydwarff.sigilmod.client;

import com.diggydwarff.sigilmod.config.SigilConfig;
import com.diggydwarff.sigilmod.crypto.SigilCrypto;
import com.diggydwarff.sigilmod.net.C2SAuthResponse;
import com.diggydwarff.sigilmod.net.S2CAuthChallenge;
import com.diggydwarff.sigilmod.net.SigilNetwork;
import com.diggydwarff.sigilmod.util.ServerId;
import net.minecraft.client.Minecraft;
import net.minecraft.network.chat.Component;

import java.nio.ByteBuffer;
import java.security.PrivateKey;

public final class ClientNetHandler {
    private ClientNetHandler() {}

    public static void onChallenge(S2CAuthChallenge msg) {
        String serverId = ServerId.fromFingerprint(msg.pubkeyFingerprint);

        // Always record last-seen fingerprint for UX/debugging.
        // ClientCertStore will implement these helpers.
        String fingerprintB64 = ClientCertStore.fingerprintToBase64(msg.pubkeyFingerprint);
        ClientCertStore.writeLastSeenFingerprint(serverId, fingerprintB64);

        // Trust pinning:
        // - If trusted exists and changes -> hard fail.
        // - If trusted missing -> do not send credentials unless autoTrustFirstSeen enabled.
        String trusted = ClientCertStore.readTrustedFingerprint(serverId).orElse(null);
        boolean autoTrust = SigilConfig.CLIENT.autoTrustFirstSeen.get(); // to be added in SigilConfig
        if (trusted != null && !trusted.equals(fingerprintB64)) {
        // Tell server "no cert / no proof" so it kicks with a real disconnect screen.
            SigilNetwork.CHANNEL.sendToServer(
                    new C2SAuthResponse(msg.protocolVersion, msg.challenge, "", new byte[0])
            );
            return;

        }
        if (trusted == null) {
            if (autoTrust) {
                ClientCertStore.writeTrustedFingerprint(serverId, fingerprintB64);
            } else {
            // Tell server "no cert / no proof" so it kicks with a real disconnect screen.
                SigilNetwork.CHANNEL.sendToServer(
                        new C2SAuthResponse(msg.protocolVersion, msg.challenge, "", new byte[0])
                );
                return;

            }
        }

        // Load cert (per-server with legacy fallback migration)
        String certJson = ClientCertStore
                .loadRawCertJsonWithLegacyFallback(serverId)
                .orElse("");

        // Optional: send proof if player has a private key for this serverId
        byte[] proof = new byte[0];
        PrivateKey pk = ClientCertStore.loadPrivateKey(serverId).orElse(null);
        if (pk != null) {
            // Security upgrade (6):
            // Sign proofPayload = protocolVersion || pubkeyFingerprint || challenge
            byte[] proofPayload = buildProofPayload(msg.protocolVersion, msg.pubkeyFingerprint, msg.challenge);
            proof = SigilCrypto.signEd25519(pk, proofPayload);
        }

        // Send response
        SigilNetwork.CHANNEL.sendToServer(
                new C2SAuthResponse(msg.protocolVersion, msg.challenge, certJson, proof)
        );
    }

    private static byte[] buildProofPayload(int protocolVersion, byte[] pubkeyFingerprint, byte[] challenge) {
        // protocolVersion as 4-byte big-endian, then raw fingerprint bytes, then raw challenge bytes
        ByteBuffer bb = ByteBuffer.allocate(4 + pubkeyFingerprint.length + challenge.length);
        bb.putInt(protocolVersion);
        bb.put(pubkeyFingerprint);
        bb.put(challenge);
        return bb.array();
    }

    private static void hardDisconnect(String msg) {
        Minecraft mc = Minecraft.getInstance();

        mc.execute(() -> {
            Component title = Component.literal("Sigil");
            Component reason = Component.literal(msg);

            // Force-close the underlying connection if it exists.
            // (ClientPacketListener has no disconnect(), but its Connection does.)
            if (mc.getConnection() != null) {
                try {
                    mc.getConnection().getConnection().disconnect(reason);
                } catch (Throwable ignored) {
                }
            }

            // Always show a disconnect screen, even during the login phase.
            mc.setScreen(new net.minecraft.client.gui.screens.DisconnectedScreen(
                    mc.screen,
                    title,
                    reason
            ));

            // Make sure we aren't stuck in a half-loaded state.
            mc.clearLevel();
        });
    }


}
