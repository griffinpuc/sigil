package com.diggydwarff.sigilmod.net;

import com.diggydwarff.sigilmod.client.ClientNetHandler;
import net.minecraft.network.FriendlyByteBuf;
import net.minecraftforge.network.NetworkEvent;

import java.util.function.Supplier;

public class S2CAuthChallenge {
    public int protocolVersion;
    public byte[] challenge;
    public byte[] pubkeyFingerprint;

    public S2CAuthChallenge(int protocolVersion, byte[] challenge, byte[] pubkeyFingerprint) {
        this.protocolVersion = protocolVersion;
        this.challenge = challenge;
        this.pubkeyFingerprint = pubkeyFingerprint;
    }

    public static void encode(S2CAuthChallenge msg, FriendlyByteBuf buf) {
        buf.writeInt(msg.protocolVersion);
        buf.writeByteArray(msg.challenge);
        buf.writeByteArray(msg.pubkeyFingerprint);
    }

    public static S2CAuthChallenge decode(FriendlyByteBuf buf) {
        int pv = buf.readInt();
        byte[] ch = buf.readByteArray();
        byte[] fp = buf.readByteArray();
        return new S2CAuthChallenge(pv, ch, fp);
    }

    public static void handle(S2CAuthChallenge msg, Supplier<NetworkEvent.Context> ctx) {
        ctx.get().enqueueWork(() -> ClientNetHandler.onChallenge(msg));
        ctx.get().setPacketHandled(true);
    }
}
