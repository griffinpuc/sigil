package com.diggydwarff.sigilmod.config;

import net.minecraftforge.common.ForgeConfigSpec;
import net.minecraftforge.fml.ModLoadingContext;
import net.minecraftforge.fml.config.ModConfig;

public final class SigilConfig {
    private SigilConfig() {}

    public enum IdentityMode {
        ONLINE_UUID,
        OFFLINE_KEYPAIR
    }

    public static final ForgeConfigSpec SERVER_SPEC;
    public static final ForgeConfigSpec CLIENT_SPEC;

    // ---- Server ----
    public static final ForgeConfigSpec.BooleanValue REQUIRE_CERT;
    public static final ForgeConfigSpec.IntValue HANDSHAKE_TIMEOUT_SECONDS;
    public static final ForgeConfigSpec.IntValue DEFAULT_CERT_DAYS_VALID;

    public static final ForgeConfigSpec.ConfigValue<String> IDENTITY_MODE; // "ONLINE_UUID" or "OFFLINE_KEYPAIR"
    public static final ForgeConfigSpec.BooleanValue ENFORCE_NAME_MATCH;

    // (3) Rate limiting
    public static final ForgeConfigSpec.IntValue RATE_LIMIT_WINDOW_SECONDS;
    public static final ForgeConfigSpec.IntValue RATE_LIMIT_MAX_ATTEMPTS;

    // (6) Backward compatibility for old clients (signing raw challenge)
    public static final ForgeConfigSpec.BooleanValue ACCEPT_LEGACY_PROOF;

    // ---- Client ----
    public static final class CLIENT {
        private CLIENT() {}

        // (1) Trust pinning behavior
        public static ForgeConfigSpec.BooleanValue autoTrustFirstSeen;
    }

    static {
        // SERVER
        ForgeConfigSpec.Builder s = new ForgeConfigSpec.Builder();

        s.push("sigil");
        REQUIRE_CERT = s.comment("If true, players must present a valid Sigil certificate to stay connected.")
                .define("requireCert", true);

        HANDSHAKE_TIMEOUT_SECONDS = s.comment("How many seconds a player has to complete the certificate handshake.")
                .defineInRange("handshakeTimeoutSeconds", 5, 1, 60);

        DEFAULT_CERT_DAYS_VALID = s.comment("Default certificate validity in days when issuing without specifying days.")
                .defineInRange("defaultCertDaysValid", 365, 1, 3650);

        IDENTITY_MODE = s.comment("ONLINE_UUID or OFFLINE_KEYPAIR")
                .define("identityMode", "ONLINE_UUID");

        ENFORCE_NAME_MATCH = s.comment("If true, cert playerName must equal the joining player's name. Strongly recommended in OFFLINE_KEYPAIR.")
                .define("enforceNameMatch", true);

        RATE_LIMIT_WINDOW_SECONDS = s.comment("Rate limit window (seconds) for repeated auth failures. 0 disables.")
                .defineInRange("rateLimitWindowSeconds", 30, 0, 3600);

        RATE_LIMIT_MAX_ATTEMPTS = s.comment("Max failed auth attempts per window (by IP or UUID). 0 disables.")
                .defineInRange("rateLimitMaxAttempts", 10, 0, 1000);

        ACCEPT_LEGACY_PROOF = s.comment("If true, accept legacy clients that sign the raw challenge instead of the upgraded proofPayload.")
                .define("acceptLegacyProof", true);

        s.pop();
        SERVER_SPEC = s.build();

        // CLIENT
        ForgeConfigSpec.Builder c = new ForgeConfigSpec.Builder();
        c.push("sigil");

        CLIENT.autoTrustFirstSeen = c.comment(
                        "If false (default), Sigil will NOT send cert/proof to an untrusted server.\n" +
                                "To trust a server, put its fingerprint into:\n" +
                                "config/sigil/servers/<serverId>/trusted_fingerprint.txt\n" +
                                "If true, the first seen fingerprint is auto-pinned."
                )
                .define("autoTrustFirstSeen", false);

        c.pop();
        CLIENT_SPEC = c.build();
    }

    public static void register() {
        ModLoadingContext.get().registerConfig(ModConfig.Type.SERVER, SERVER_SPEC, "sigil-server.toml");
        ModLoadingContext.get().registerConfig(ModConfig.Type.CLIENT, CLIENT_SPEC, "sigil-client.toml");
    }
}
