package com.diggydwarff.sigilmod.client;

import com.diggydwarff.sigilmod.crypto.SigilCrypto;
import com.diggydwarff.sigilmod.net.C2SAuthResponse;
import com.diggydwarff.sigilmod.net.S2CAuthChallenge;
import com.diggydwarff.sigilmod.net.SigilNetwork;
import com.diggydwarff.sigilmod.util.ServerId;
import net.minecraftforge.network.PacketDistributor;

import java.security.PrivateKey;

public final class ClientNetHandler {
    private ClientNetHandler() {}

    public static void onChallenge(S2CAuthChallenge msg) {
        String serverId = ServerId.fromFingerprint(msg.pubkeyFingerprint);

        String certJson = ClientCertStore
                .loadRawCertJsonWithLegacyFallback(serverId)
                .orElse("");

        // Optional: send proof if player has a private key for this serverId
        byte[] proof = new byte[0];
        PrivateKey pk = ClientCertStore.loadPrivateKey(serverId).orElse(null);
        if (pk != null) {
            proof = SigilCrypto.signEd25519(pk, msg.challenge);
        }

        // Send response
        SigilNetwork.CHANNEL.sendToServer(
                new C2SAuthResponse(msg.protocolVersion, msg.challenge, certJson, proof)
        );

    }
}