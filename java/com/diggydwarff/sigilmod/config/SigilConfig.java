package com.diggydwarff.sigilmod.config;

import net.minecraftforge.common.ForgeConfigSpec;
import net.minecraftforge.fml.ModLoadingContext;
import net.minecraftforge.fml.config.ModConfig;

public final class SigilConfig {
    private SigilConfig() {}

    public static final ForgeConfigSpec SPEC;

    public static final ForgeConfigSpec.BooleanValue REQUIRE_CERT;
    public static final ForgeConfigSpec.IntValue HANDSHAKE_TIMEOUT_SECONDS;
    public static final ForgeConfigSpec.IntValue DEFAULT_CERT_DAYS_VALID;

    // NEW
    public static final ForgeConfigSpec.ConfigValue<String> IDENTITY_MODE; // "ONLINE_UUID" or "OFFLINE_KEYPAIR"
    public static final ForgeConfigSpec.BooleanValue ENFORCE_NAME_MATCH;

    static {
        ForgeConfigSpec.Builder b = new ForgeConfigSpec.Builder();

        b.push("sigil");
        REQUIRE_CERT = b.comment("If true, players must present a valid Sigil certificate to stay connected.")
                .define("requireCert", true);

        HANDSHAKE_TIMEOUT_SECONDS = b.comment("How many seconds a player has to complete the certificate handshake.")
                .defineInRange("handshakeTimeoutSeconds", 5, 1, 60);

        DEFAULT_CERT_DAYS_VALID = b.comment("Default certificate validity in days when issuing without specifying days.")
                .defineInRange("defaultCertDaysValid", 365, 1, 3650);

        IDENTITY_MODE = b.comment("ONLINE_UUID or OFFLINE_KEYPAIR")
                .define("identityMode", "ONLINE_UUID");

        ENFORCE_NAME_MATCH = b.comment("If true, cert playerName must equal the joining player's name. Strongly recommended in OFFLINE_KEYPAIR.")
                .define("enforceNameMatch", true);

        b.pop();
        SPEC = b.build();
    }

    public static void register() {
        ModLoadingContext.get().registerConfig(ModConfig.Type.SERVER, SPEC, "sigil-server.toml");
    }
}
