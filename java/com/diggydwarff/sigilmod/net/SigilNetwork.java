package com.diggydwarff.sigilmod.net;

import com.diggydwarff.sigilmod.SigilMod;
import net.minecraft.resources.ResourceLocation;
import net.minecraftforge.network.NetworkRegistry;
import net.minecraftforge.network.simple.SimpleChannel;

public final class SigilNetwork {
    private SigilNetwork() {}

    private static final String PROTOCOL = "1";
    public static SimpleChannel CHANNEL;

    public static void init() {
        CHANNEL = NetworkRegistry.ChannelBuilder
                .named(new ResourceLocation(SigilMod.MODID, "main"))
                .clientAcceptedVersions(PROTOCOL::equals)
                .serverAcceptedVersions(PROTOCOL::equals)
                .networkProtocolVersion(() -> PROTOCOL)
                .simpleChannel();

        int id = 0;
        CHANNEL.messageBuilder(S2CAuthChallenge.class, id++)
                .encoder(S2CAuthChallenge::encode)
                .decoder(S2CAuthChallenge::decode)
                .consumerMainThread(S2CAuthChallenge::handle)
                .add();

        CHANNEL.messageBuilder(C2SAuthResponse.class, id++)
                .encoder(C2SAuthResponse::encode)
                .decoder(C2SAuthResponse::decode)
                .consumerMainThread(C2SAuthResponse::handle)
                .add();
    }
}
