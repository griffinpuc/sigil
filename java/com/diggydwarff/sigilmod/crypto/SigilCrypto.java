package com.diggydwarff.sigilmod.crypto;

import java.security.*;
import java.util.Base64;

public final class SigilCrypto {
    private static final SecureRandom RNG = new SecureRandom();

    private SigilCrypto() {}

    public static byte[] randomBytes(int n) {
        byte[] b = new byte[n];
        RNG.nextBytes(b);
        return b;
    }

    public static byte[] sha256(byte[] in) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return md.digest(in);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] signEd25519(PrivateKey privateKey, byte[] payload) {
        try {
            Signature sig = Signature.getInstance("Ed25519");
            sig.initSign(privateKey);
            sig.update(payload);
            return sig.sign();
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    public static boolean verifyEd25519(PublicKey publicKey, byte[] payload, byte[] signature) {
        try {
            Signature sig = Signature.getInstance("Ed25519");
            sig.initVerify(publicKey);
            sig.update(payload);
            return sig.verify(signature);
        } catch (GeneralSecurityException e) {
            return false;
        }
    }

    public static String b64(byte[] in) {
        return Base64.getEncoder().encodeToString(in);
    }

    public static byte[] b64d(String in) {
        return Base64.getDecoder().decode(in);
    }
}
