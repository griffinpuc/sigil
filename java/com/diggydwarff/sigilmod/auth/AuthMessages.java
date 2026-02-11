package com.diggydwarff.sigilmod.auth;

import com.diggydwarff.sigilmod.config.SigilConfig;
import com.diggydwarff.sigilmod.config.SigilPaths;
import net.minecraft.network.chat.Component;

public final class AuthMessages {
    private AuthMessages() {}

    // Backwards compatible
    public static Component kick(AuthResult r) {
        return kick(r, null, null);
    }

    // New: richer messages with mode + serverId for correct file paths
    public static Component kick(AuthResult r, String serverId, SigilConfig.IdentityMode mode) {
        String paths = expectedClientPaths(serverId, mode);

        return switch (r) {
            case MISSING_CERT ->
                    Component.literal(
                            "Sigil Authentication Failed\n" +
                                    "Missing client certificate.\n" +
                                    paths
                    );

            case UUID_MISMATCH ->
                    Component.literal(
                            "Sigil Authentication Failed\n" +
                                    "UUID mismatch (likely offline-mode UUID vs Mojang UUID).\n" +
                                    "This server is using ONLINE_UUID certs.\n" +
                                    paths
                    );

            case NAME_MISMATCH ->
                    Component.literal(
                            "Sigil Authentication Failed\n" +
                                    "Username does not match issued certificate.\n" +
                                    paths
                    );

            case REVOKED ->
                    Component.literal(
                            "Sigil Authentication Failed\n" +
                                    "Your access certificate has been revoked.\n" +
                                    "Contact the server administrator.\n"
                    );

            case EXPIRED ->
                    Component.literal(
                            "Sigil Authentication Failed\n" +
                                    "Your access certificate has expired.\n" +
                                    "Contact the server administrator.\n"
                    );

            case BAD_PROTOCOL ->
                    Component.literal(
                            "Sigil Authentication Failed\n" +
                                    "Protocol version mismatch.\n" +
                                    "Update client/server Sigil to the same version.\n"
                    );

            case CHALLENGE_MISMATCH ->
                    Component.literal(
                            "Sigil Authentication Failed\n" +
                                    "Challenge mismatch.\n" +
                                    "Retry connecting. If it persists, report to the admin.\n"
                    );

            case INVALID_CERT_JSON ->
                    Component.literal(
                            "Sigil Authentication Failed\n" +
                                    "Certificate JSON is invalid/corrupt.\n" +
                                    paths
                    );

            case INVALID_SIGNATURE, INVALID_CLIENT_PROOF ->
                    Component.literal(
                            "Sigil Authentication Failed\n" +
                                    "Certificate/proof verification failed.\n" +
                                    paths
                    );

            case MISSING_PUBLIC_KEY ->
                    Component.literal(
                            "Sigil Authentication Failed\n" +
                                    "Certificate missing required public key (OFFLINE_KEYPAIR).\n" +
                                    paths
                    );

            case MISSING_CLIENT_PROOF ->
                    Component.literal(
                            "Sigil Authentication Failed\n" +
                                    "Client identity proof missing (OFFLINE_KEYPAIR).\n" +
                                    paths
                    );

            case RATE_LIMITED ->
                    Component.literal(
                            "Sigil Authentication Failed\n" +
                                    "Rate limited due to repeated auth failures.\n" +
                                    "Wait a bit and try again.\n"
                    );

            default ->
                    Component.literal(
                            "Sigil Authentication Failed\n" +
                                    "Reason: " + r.name() + "\n" +
                                    paths
                    );
        };
    }

    private static String expectedClientPaths(String serverId, SigilConfig.IdentityMode mode) {
        if (serverId == null || mode == null) {
            return "Client files:\n" +
                    "config/sigil/servers/<serverId>/player_cert.json\n" +
                    "(OFFLINE_KEYPAIR also requires player_ed25519_private.key)\n";
        }

        String base = SigilPaths.clientServerDir(serverId).toString().replace('\\', '/');
        String cert = base + "/player_cert.json";
        String key = base + "/player_ed25519_private.key";

        return switch (mode) {
            case ONLINE_UUID -> "Expected client file:\n" + cert + "\n";
            case OFFLINE_KEYPAIR -> "Expected client files:\n" + cert + "\n" + key + "\n";
        };
    }

    public static Component success() {
        return Component.literal(
                "Sigil Authentication Successful\n" +
                        "Access granted by server authority."
        );
    }
}
