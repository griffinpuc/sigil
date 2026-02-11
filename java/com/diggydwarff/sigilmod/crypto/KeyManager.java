package com.diggydwarff.sigilmod.crypto;

import com.diggydwarff.sigilmod.config.SigilPaths;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;

public final class KeyManager {
    private static volatile KeyManager INSTANCE;

    private final PrivateKey privateKey;
    private final PublicKey publicKey;

    private KeyManager(PrivateKey priv, PublicKey pub) {
        this.privateKey = priv;
        this.publicKey = pub;
    }

    public static KeyManager get() {
        if (INSTANCE == null) throw new IllegalStateException("KeyManager not loaded yet");
        return INSTANCE;
    }

    public static void loadOrCreate() {
        try {
            Files.createDirectories(SigilPaths.keysDir());

            if (Files.exists(SigilPaths.privateKeyFile()) && Files.exists(SigilPaths.publicKeyFile())) {
                PrivateKey priv = loadPrivateKey(SigilPaths.privateKeyFile());
                PublicKey pub = loadPublicKey(SigilPaths.publicKeyFile());
                INSTANCE = new KeyManager(priv, pub);
                return;
            }

            KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed25519");
            KeyPair kp = kpg.generateKeyPair();

            saveKey(SigilPaths.privateKeyFile(), kp.getPrivate().getEncoded());
            saveKey(SigilPaths.publicKeyFile(), kp.getPublic().getEncoded());

            INSTANCE = new KeyManager(kp.getPrivate(), kp.getPublic());
        } catch (GeneralSecurityException | IOException e) {
            throw new RuntimeException("Failed to load/create server keys", e);
        }
    }

    public PrivateKey privateKey() { return privateKey; }
    public PublicKey publicKey() { return publicKey; }

    public byte[] publicKeyFingerprint() {
        return SigilCrypto.sha256(publicKey.getEncoded());
    }

    private static void saveKey(java.nio.file.Path path, byte[] encoded) throws IOException {
        String b64 = Base64.getEncoder().encodeToString(encoded);
        Files.writeString(path, b64 + "\n", StandardCharsets.UTF_8);
    }

    private static PrivateKey loadPrivateKey(java.nio.file.Path path) throws IOException, GeneralSecurityException {
        String b64 = Files.readString(path, StandardCharsets.UTF_8).trim();
        byte[] enc = Base64.getDecoder().decode(b64);
        KeyFactory kf = KeyFactory.getInstance("Ed25519");
        return kf.generatePrivate(new PKCS8EncodedKeySpec(enc));
    }

    private static PublicKey loadPublicKey(java.nio.file.Path path) throws IOException, GeneralSecurityException {
        String b64 = Files.readString(path, StandardCharsets.UTF_8).trim();
        byte[] enc = Base64.getDecoder().decode(b64);
        KeyFactory kf = KeyFactory.getInstance("Ed25519");
        return kf.generatePublic(new X509EncodedKeySpec(enc));
    }
}
