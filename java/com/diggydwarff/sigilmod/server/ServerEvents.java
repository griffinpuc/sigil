package com.diggydwarff.sigilmod.server;

import com.diggydwarff.sigilmod.auth.AuthManager;
import net.minecraftforge.event.TickEvent;
import net.minecraftforge.event.entity.player.PlayerEvent;
import net.minecraftforge.event.server.ServerStartedEvent;
import net.minecraftforge.eventbus.api.SubscribeEvent;

public class ServerEvents {

    @SubscribeEvent
    public void onServerStarted(ServerStartedEvent e) {
        // Load keys + revoked list early
        AuthManager.get().ensureLoaded();
    }

    @SubscribeEvent
    public void onPlayerLogin(PlayerEvent.PlayerLoggedInEvent e) {
        if (e.getEntity() instanceof net.minecraft.server.level.ServerPlayer sp) {
            AuthManager.get().onPlayerJoin(sp);
        }
    }

    @SubscribeEvent
    public void onPlayerLogout(PlayerEvent.PlayerLoggedOutEvent e) {
        if (e.getEntity() instanceof net.minecraft.server.level.ServerPlayer sp) {
            AuthManager.get().onPlayerQuit(sp);
        }
    }

    @SubscribeEvent
    public void onServerTick(TickEvent.ServerTickEvent e) {
        if (e.phase != TickEvent.Phase.END) return;
        AuthManager.get().tick(e.getServer());
    }
}
