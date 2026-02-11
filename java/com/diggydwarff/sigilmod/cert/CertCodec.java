package com.diggydwarff.sigilmod.cert;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

public final class CertCodec {
    private static final Gson GSON = new GsonBuilder().setPrettyPrinting().create();

    private CertCodec() {}

    public static String toJson(PlayerCertificate cert) {
        return GSON.toJson(cert);
    }

    public static PlayerCertificate fromJson(String json) {
        return GSON.fromJson(json, PlayerCertificate.class);
    }

    public static PlayerCertificate read(Path path) throws IOException {
        String json = Files.readString(path, StandardCharsets.UTF_8);
        return fromJson(json);
    }

    public static void write(Path path, PlayerCertificate cert) throws IOException {
        Files.createDirectories(path.getParent());
        Files.writeString(path, toJson(cert), StandardCharsets.UTF_8);
    }
}
