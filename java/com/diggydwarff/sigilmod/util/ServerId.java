package com.diggydwarff.sigilmod.util;

public final class ServerId {
    private ServerId() {}

    public static String fromFingerprint(byte[] fp) {
        // hex
        StringBuilder sb = new StringBuilder(fp.length * 2);
        for (byte b : fp) sb.append(String.format("%02x", b));
        return sb.toString();
    }
}