package com.diggydwarff.sigilmod.auth;

public class PendingAuth {
    public final byte[] challenge;
    public final long deadlineGameTime;

    public PendingAuth(byte[] challenge, long deadlineGameTime) {
        this.challenge = challenge;
        this.deadlineGameTime = deadlineGameTime;
    }

    public String lastFailReason = null;
}