package com.diggydwarff.sigilmod.client;

import net.minecraftforge.api.distmarker.Dist;
import net.minecraftforge.fml.common.Mod;

@Mod.EventBusSubscriber(value = Dist.CLIENT, bus = Mod.EventBusSubscriber.Bus.MOD)
public final class ClientInit {
    private ClientInit() {}
    // You can add client-only setup events later if needed.
}
