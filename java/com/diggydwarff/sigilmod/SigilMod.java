package com.diggydwarff.sigilmod;

import com.diggydwarff.sigilmod.config.SigilConfig;
import com.diggydwarff.sigilmod.net.SigilNetwork;
import com.diggydwarff.sigilmod.server.ServerEvents;
import com.diggydwarff.sigilmod.server.SigilCommands;
import com.mojang.logging.LogUtils;
import net.minecraftforge.api.distmarker.Dist;
import net.minecraftforge.common.MinecraftForge;
import net.minecraftforge.eventbus.api.IEventBus;
import net.minecraftforge.eventbus.api.SubscribeEvent;
import net.minecraftforge.fml.common.Mod;
import net.minecraftforge.fml.event.lifecycle.FMLClientSetupEvent;
import net.minecraftforge.fml.event.lifecycle.FMLCommonSetupEvent;
import net.minecraftforge.event.server.ServerStartingEvent;
import net.minecraftforge.fml.javafmlmod.FMLJavaModLoadingContext;
import net.minecraftforge.registries.RegisterEvent;
import org.slf4j.Logger;

// The value here should match an entry in the META-INF/mods.toml file
@Mod(SigilMod.MODID)
public class SigilMod
{
    // Define mod id in a common place for everything to reference
    public static final String MODID = "sigilmod";
    // Directly reference a slf4j logger
    private static final Logger LOGGER = LogUtils.getLogger();

    public SigilMod()
    {
        IEventBus modEventBus = FMLJavaModLoadingContext.get().getModEventBus();

        modEventBus.addListener(this::commonSetup);
        modEventBus.addListener(this::register);

        SigilConfig.register();          // Forge config
        SigilNetwork.init();             // SimpleChannel + message registration
        MinecraftForge.EVENT_BUS.register(new ServerEvents()); // join/tick/quit
        MinecraftForge.EVENT_BUS.register(new SigilCommands()); // RegisterCommandsEvent handler

        MinecraftForge.EVENT_BUS.register(this);
    }

    @SubscribeEvent
    public void register(RegisterEvent event) {

    }

    private void commonSetup(final FMLCommonSetupEvent event)
    {
    }

    // You can use SubscribeEvent and let the Event Bus discover methods to call
    @SubscribeEvent
    public void onServerStarting(ServerStartingEvent event)
    {

    }
    // You can use EventBusSubscriber to automatically register all static methods in the class annotated with @SubscribeEvent
    @Mod.EventBusSubscriber(modid = MODID, bus = Mod.EventBusSubscriber.Bus.MOD, value = Dist.CLIENT)
    public static class ClientModEvents
    {
        @SubscribeEvent
        public static void onClientSetup(FMLClientSetupEvent event)
        {

        }
    }
}
