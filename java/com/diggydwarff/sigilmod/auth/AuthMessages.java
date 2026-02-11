package com.diggydwarff.sigilmod.auth;

import net.minecraft.network.chat.Component;

public final class AuthMessages {
    private AuthMessages() {}

    public static Component kick(AuthResult r) {
        return switch (r) {
            case MISSING_CERT ->
                    Component.literal(
                            "Sigil Authentication Failed\n" +
                                    "Missing server certificate.\n" +
                                    "Please contact the server administrator."
                    );

            case NAME_MISMATCH ->
                    Component.literal(
                            "Sigil Authentication Failed\n" +
                                    "Username does not match issued certificate.\n" +
                                    "Please contact the server administrator."
                    );

            case REVOKED ->
                    Component.literal(
                            "Sigil Authentication Failed\n" +
                                    "Your access certificate has been revoked.\n" +
                                    "Please contact the server administrator."
                    );

            case EXPIRED ->
                    Component.literal(
                            "Sigil Authentication Failed\n" +
                                    "Your access certificate has expired.\n" +
                                    "Please contact the server administrator."
                    );

            case INVALID_SIGNATURE, INVALID_CLIENT_PROOF ->
                    Component.literal(
                            "Sigil Authentication Failed\n" +
                                    "Certificate verification failed.\n" +
                                    "Please contact the server administrator."
                    );

            case MISSING_CLIENT_PROOF ->
                    Component.literal(
                            "Sigil Authentication Failed\n" +
                                    "Client identity proof missing.\n" +
                                    "Please contact the server administrator."
                    );

            default ->
                    Component.literal(
                            "Sigil Authentication Failed\n" +
                                    "An unknown authentication error occurred.\n" +
                                    "Please contact the server administrator."
                    );
        };
    }

    public static Component success() {
        return Component.literal(
                "Sigil Authentication Successful\n" +
                        "Access granted by server authority."
        );
    }
}
