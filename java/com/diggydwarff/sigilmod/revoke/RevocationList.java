package com.diggydwarff.sigilmod.revoke;

import com.diggydwarff.sigilmod.config.SigilPaths;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;

import java.io.IOException;
import java.lang.reflect.Type;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;


public final class RevocationList {
    private static final Gson GSON = new GsonBuilder().setPrettyPrinting().create();
    private static final Type SET_TYPE = new TypeToken<Set<String>>() {}.getType();

    private static final RevocationList INSTANCE = new RevocationList();
    public static RevocationList get() { return INSTANCE; }

    private final Set<String> revokedSerials = new HashSet<>();

    private RevocationList() {}

    public boolean isRevoked(String serialBase64) {
        return serialBase64 != null && revokedSerials.contains(serialBase64);
    }

    public void revoke(String serialBase64) {
        if (serialBase64 == null || serialBase64.isBlank()) return;
        revokedSerials.add(serialBase64);
        save();
    }

    public void load() {
        try {
            Files.createDirectories(SigilPaths.baseDir());
            if (!Files.exists(SigilPaths.revokedFile())) {
                save();
                return;
            }
            String json = Files.readString(SigilPaths.revokedFile(), StandardCharsets.UTF_8);
            Set<String> loaded = GSON.fromJson(json, SET_TYPE);
            revokedSerials.clear();
            if (loaded != null) revokedSerials.addAll(loaded);
        } catch (IOException e) {
            throw new RuntimeException("Failed to load revoked.json", e);
        }
    }

    public void save() {
        try {
            Files.createDirectories(SigilPaths.baseDir());
            String json = GSON.toJson(revokedSerials, SET_TYPE);
            Files.writeString(SigilPaths.revokedFile(), json, StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new RuntimeException("Failed to save revoked.json", e);
        }
    }
}