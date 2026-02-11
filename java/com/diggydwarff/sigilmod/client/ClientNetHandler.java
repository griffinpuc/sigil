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

        String certJson = ServerCredentialStore.loadRawCertJson(serverId).orElse("");

        byte[] proofSig = new byte[0];
        PrivateKey priv = ServerCredentialStore.loadPrivateKey(serverId).orElse(null);
        if (priv != null) {
            // proof = sign(challenge) (OFFLINE_KEYPAIR uses it; ONLINE_UUID ignores)
            proofSig = SigilCrypto.signEd25519(priv, msg.challenge);
        }

        C2SAuthResponse resp = new C2SAuthResponse(
                msg.protocolVersion,
                msg.challenge,
                certJson,
                proofSig
        );

        SigilNetwork.CHANNEL.sendToServer(resp);
    }
}