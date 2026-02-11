package com.diggydwarff.sigilmod.net;

import com.diggydwarff.sigilmod.auth.AuthManager;
import net.minecraft.network.FriendlyByteBuf;
import net.minecraft.server.level.ServerPlayer;
import net.minecraftforge.network.NetworkEvent;

import java.util.function.Supplier;

public class C2SAuthResponse {
    public int protocolVersion;
    public byte[] challengeEcho;
    public String certJson;
    public byte[] clientProofSig; // NEW (OFFLINE_KEYPAIR)

    public C2SAuthResponse(int protocolVersion, byte[] challengeEcho, String certJson, byte[] clientProofSig) {
        this.protocolVersion = protocolVersion;
        this.challengeEcho = challengeEcho;
        this.certJson = certJson;
        this.clientProofSig = clientProofSig == null ? new byte[0] : clientProofSig;
    }

    public static void encode(C2SAuthResponse msg, FriendlyByteBuf buf) {
        buf.writeInt(msg.protocolVersion);
        buf.writeByteArray(msg.challengeEcho);
        buf.writeUtf(msg.certJson == null ? "" : msg.certJson, 1_000_000);
        buf.writeByteArray(msg.clientProofSig == null ? new byte[0] : msg.clientProofSig);
    }

    public static C2SAuthResponse decode(FriendlyByteBuf buf) {
        int pv = buf.readInt();
        byte[] echo = buf.readByteArray();
        String json = buf.readUtf(1_000_000);
        byte[] proof = buf.readByteArray();
        return new C2SAuthResponse(pv, echo, json, proof);
    }

    public static void handle(C2SAuthResponse msg, Supplier<NetworkEvent.Context> ctx) {
        ServerPlayer sp = ctx.get().getSender();
        if (sp != null) {
            ctx.get().enqueueWork(() -> AuthManager.get().onResponse(sp, msg));
        }
        ctx.get().setPacketHandled(true);
    }
}