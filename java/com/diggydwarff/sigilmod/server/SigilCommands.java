package com.diggydwarff.sigilmod.server;

import com.diggydwarff.sigilmod.cert.CertCodec;
import com.diggydwarff.sigilmod.cert.CertPayload;
import com.diggydwarff.sigilmod.cert.PlayerCertificate;
import com.diggydwarff.sigilmod.config.SigilConfig;
import com.diggydwarff.sigilmod.config.SigilPaths;
import com.diggydwarff.sigilmod.crypto.KeyManager;
import com.diggydwarff.sigilmod.crypto.SigilCrypto;
import com.diggydwarff.sigilmod.revoke.RevocationList;
import com.diggydwarff.sigilmod.util.ServerId;
import com.mojang.brigadier.CommandDispatcher;
import com.mojang.brigadier.arguments.IntegerArgumentType;
import com.mojang.brigadier.arguments.StringArgumentType;
import net.minecraft.commands.CommandSourceStack;
import net.minecraft.commands.Commands;
import net.minecraft.network.chat.Component;
import net.minecraftforge.event.RegisterCommandsEvent;
import net.minecraftforge.eventbus.api.SubscribeEvent;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;

import java.nio.file.Path;
import java.time.Instant;
import java.util.UUID;

public class SigilCommands {

    @SubscribeEvent
    public void onRegisterCommands(RegisterCommandsEvent e) {
        register(e.getDispatcher());
    }

    private void register(CommandDispatcher<CommandSourceStack> d) {
        d.register(
                Commands.literal("sigil")
                        .requires(src -> src.hasPermission(3))

                        // ONLINE_UUID: issue by UUID + name
                        .then(Commands.literal("issueUuid")
                                .then(Commands.argument("uuid", StringArgumentType.string())
                                        .then(Commands.argument("name", StringArgumentType.word())
                                                .executes(ctx -> {
                                                    UUID uuid = UUID.fromString(StringArgumentType.getString(ctx, "uuid"));
                                                    String name = StringArgumentType.getString(ctx, "name");
                                                    int days = SigilConfig.DEFAULT_CERT_DAYS_VALID.get();
                                                    return issueOnlineUuid(ctx.getSource(), uuid, name, days);
                                                })
                                                .then(Commands.argument("daysValid", IntegerArgumentType.integer(1, 3650))
                                                        .executes(ctx -> {
                                                            UUID uuid = UUID.fromString(StringArgumentType.getString(ctx, "uuid"));
                                                            String name = StringArgumentType.getString(ctx, "name");
                                                            int days = IntegerArgumentType.getInteger(ctx, "daysValid");
                                                            return issueOnlineUuid(ctx.getSource(), uuid, name, days);
                                                        })
                                                )
                                        )
                                )
                        )

                        // OFFLINE_KEYPAIR: issue by name + publicKeyBase64 (X509)
                        .then(Commands.literal("issueKey")
                                .then(Commands.argument("name", StringArgumentType.word())
                                        .then(Commands.argument("publicKeyBase64", StringArgumentType.string())
                                                .executes(ctx -> {
                                                    String name = StringArgumentType.getString(ctx, "name");
                                                    String pubB64 = StringArgumentType.getString(ctx, "publicKeyBase64");
                                                    int days = SigilConfig.DEFAULT_CERT_DAYS_VALID.get();
                                                    return issueOfflineKeypair(ctx.getSource(), name, pubB64, days);
                                                })
                                                .then(Commands.argument("daysValid", IntegerArgumentType.integer(1, 3650))
                                                        .executes(ctx -> {
                                                            String name = StringArgumentType.getString(ctx, "name");
                                                            String pubB64 = StringArgumentType.getString(ctx, "publicKeyBase64");
                                                            int days = IntegerArgumentType.getInteger(ctx, "daysValid");
                                                            return issueOfflineKeypair(ctx.getSource(), name, pubB64, days);
                                                        })
                                                )
                                        )
                                )
                        )

                        // revoke by serial
                        .then(Commands.literal("revoke")
                                .then(Commands.argument("serialBase64", StringArgumentType.string())
                                        .executes(ctx -> {
                                            String serial = StringArgumentType.getString(ctx, "serialBase64");
                                            RevocationList.get().revoke(serial);
                                            ctx.getSource().sendSuccess(() -> Component.literal("Revoked serial: " + serial), true);
                                            return 1;
                                        })
                                )
                        )

                        .then(Commands.literal("pubkey")
                                .executes(ctx -> {
                                    KeyManager.loadOrCreate();
                                    String fp = SigilCrypto.b64(KeyManager.get().publicKeyFingerprint());
                                    ctx.getSource().sendSuccess(() -> Component.literal("Sigil public key fingerprint (sha256,b64): " + fp), false);
                                    ctx.getSource().sendSuccess(() -> Component.literal("Public key file: " + SigilPaths.publicKeyFile()), false);
                                    return 1;
                                })
                        )
                        .then(Commands.literal("provision")
                                .then(Commands.argument("name", StringArgumentType.word())
                                        .executes(ctx -> {
                                            String name = StringArgumentType.getString(ctx, "name");
                                            int days = SigilConfig.DEFAULT_CERT_DAYS_VALID.get();
                                            return provisionOfflineBundle(ctx.getSource(), name, days);
                                        })
                                        .then(Commands.argument("daysValid", IntegerArgumentType.integer(1, 3650))
                                                .executes(ctx -> {
                                                    String name = StringArgumentType.getString(ctx, "name");
                                                    int days = IntegerArgumentType.getInteger(ctx, "daysValid");
                                                    return provisionOfflineBundle(ctx.getSource(), name, days);
                                                })
                                        )
                                )
                        )
        );
    }

    private int issueOnlineUuid(CommandSourceStack src, UUID uuid, String name, int daysValid) {
        KeyManager.loadOrCreate();
        long now = Instant.now().getEpochSecond();
        long expires = now + (daysValid * 24L * 60L * 60L);

        PlayerCertificate cert = new PlayerCertificate();
        cert.version = 1;
        cert.playerName = name;
        cert.uuid = uuid.toString();
        cert.playerPublicKeyBase64 = null;
        cert.issuedAtEpochSec = now;
        cert.expiresAtEpochSec = expires;
        cert.serialBase64 = SigilCrypto.b64(SigilCrypto.randomBytes(24));

        byte[] payload = CertPayload.toSigningBytes(cert);
        cert.signatureBase64 = SigilCrypto.b64(SigilCrypto.signEd25519(KeyManager.get().privateKey(), payload));

        return writeIssued(src, cert);
    }

    private int issueOfflineKeypair(CommandSourceStack src, String name, String publicKeyBase64, int daysValid) {
        KeyManager.loadOrCreate();
        long now = Instant.now().getEpochSecond();
        long expires = now + (daysValid * 24L * 60L * 60L);

        PlayerCertificate cert = new PlayerCertificate();
        cert.version = 1;
        cert.playerName = name;
        cert.uuid = null;
        cert.playerPublicKeyBase64 = publicKeyBase64;
        cert.issuedAtEpochSec = now;
        cert.expiresAtEpochSec = expires;
        cert.serialBase64 = SigilCrypto.b64(SigilCrypto.randomBytes(24));

        byte[] payload = CertPayload.toSigningBytes(cert);
        cert.signatureBase64 = SigilCrypto.b64(SigilCrypto.signEd25519(KeyManager.get().privateKey(), payload));

        return writeIssued(src, cert);
    }

    private int writeIssued(CommandSourceStack src, PlayerCertificate cert) {
        try {
            // Determine serverId + fingerprint for trust pin file
            String serverId = ServerId.fromFingerprint(KeyManager.get().publicKeyFingerprint());
            String fpB64 = SigilCrypto.b64(KeyManager.get().publicKeyFingerprint());

            // Choose issued dir organization
            Path dir;
            Path bundleDir;

            if (cert.uuid != null && !cert.uuid.isBlank()) {
                // ONLINE_UUID
                dir = SigilPaths.issuedByUuidDir(cert.uuid);
                bundleDir = SigilPaths.issuedBundleDirForOnline(cert.uuid, cert.serialBase64);
            } else {
                // OFFLINE_KEYPAIR
                dir = SigilPaths.issuedByNameDir(cert.playerName);
                bundleDir = SigilPaths.issuedBundleDirForOffline(cert.playerName, cert.serialBase64);
            }

            Files.createDirectories(dir);
            Files.createDirectories(bundleDir);

            // 1) Keep archival copy in issued/<group>/<serial>.json
            Path out = dir.resolve(cert.serialBase64 + ".json");
            CertCodec.write(out, cert);

            // 2) Write client bundle files (zip this folder and send to player)
            Path bundleCert = SigilPaths.issuedBundleCertFile(bundleDir);
            CertCodec.write(bundleCert, cert);

            Path bundleTrust = SigilPaths.issuedBundleTrustedFingerprintFile(bundleDir);
            Files.writeString(bundleTrust, fpB64 + "\n", StandardCharsets.UTF_8);

            src.sendSuccess(() -> Component.literal("Issued Sigil cert for " + cert.playerName), true);
            src.sendSuccess(() -> Component.literal("Serial: " + cert.serialBase64), false);
            src.sendSuccess(() -> Component.literal("Saved (archive): " + out), false);

            src.sendSuccess(() -> Component.literal("Client bundle dir: " + bundleDir), false);
            src.sendSuccess(() -> Component.literal("Bundle contains:"), false);
            src.sendSuccess(() -> Component.literal(" - player_cert.json"), false);
            src.sendSuccess(() -> Component.literal(" - trusted_fingerprint.txt"), false);

            src.sendSuccess(() -> Component.literal(
                    "Player installs bundle contents to: <minecraft>/config/sigil/servers/" + serverId + "/"
            ), false);

            return 1;
        } catch (Exception ex) {
            src.sendFailure(Component.literal("Failed to write cert: " + ex.getMessage()));
            return 0;
        }
    }



    private int provisionOfflineBundle(CommandSourceStack src, String name, int daysValid) {
        try {
            KeyManager.loadOrCreate();

            // serverId from server signing pubkey fingerprint
            String serverId = ServerId.fromFingerprint(KeyManager.get().publicKeyFingerprint());

            // generate player keypair (admin is ultimate authority)
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed25519");
            KeyPair kp = kpg.generateKeyPair();

            String playerPublicKeyBase64 = Base64.getEncoder().encodeToString(kp.getPublic().getEncoded());
            String playerPrivateKeyBase64 = Base64.getEncoder().encodeToString(kp.getPrivate().getEncoded());

            // build OFFLINE_KEYPAIR cert
            long now = Instant.now().getEpochSecond();
            long expires = now + (daysValid * 24L * 60L * 60L);

            PlayerCertificate cert = new PlayerCertificate();
            cert.version = 1;
            cert.playerName = name;
            cert.uuid = null;
            cert.playerPublicKeyBase64 = playerPublicKeyBase64;
            cert.issuedAtEpochSec = now;
            cert.expiresAtEpochSec = expires;
            cert.serialBase64 = SigilCrypto.b64(SigilCrypto.randomBytes(24));

            byte[] payload = CertPayload.toSigningBytes(cert);
            cert.signatureBase64 = SigilCrypto.b64(SigilCrypto.signEd25519(KeyManager.get().privateKey(), payload));

            // write bundle folder
            var bundleDir = SigilPaths.provisionedServerDir(name, serverId);
            Files.createDirectories(bundleDir);

            // cert file
            var certOut = SigilPaths.provisionedCertFile(name, serverId);
            CertCodec.write(certOut, cert);

            // private key file (PKCS8 b64)
            var privOut = SigilPaths.provisionedPrivateKeyFile(name, serverId);
            Files.writeString(privOut, playerPrivateKeyBase64 + "\n", StandardCharsets.UTF_8);

            // trusted fingerprint file (base64 sha256 fingerprint)
            var trustOut = SigilPaths.provisionedTrustedFingerprintFile(name, serverId);
            String fpB64 = SigilCrypto.b64(KeyManager.get().publicKeyFingerprint());
            Files.writeString(trustOut, fpB64 + "\n", StandardCharsets.UTF_8);

            src.sendSuccess(() -> Component.literal("Provisioned OFFLINE bundle for " + name), true);
            src.sendSuccess(() -> Component.literal("serverId: " + serverId), false);
            src.sendSuccess(() -> Component.literal("Bundle dir: " + bundleDir), false);
            src.sendSuccess(() -> Component.literal("Give player these two files:"), false);
            src.sendSuccess(() -> Component.literal(" - " + certOut.getFileName()), false);
            src.sendSuccess(() -> Component.literal(" - " + privOut.getFileName()), false);
            src.sendSuccess(() -> Component.literal(" - " + trustOut.getFileName()), false);
            src.sendSuccess(() -> Component.literal("Player installs to: <minecraft>/config/sigil/servers/" + serverId + "/"), false);
            src.sendSuccess(() -> Component.literal("WARNING: player_ed25519_private.key IS A PASSWORD."), false);
            src.sendSuccess(() -> Component.literal("Do NOT send it in public chat. Prefer encrypted transfer."), false);
            src.sendSuccess(() -> Component.literal("If leaked, revoke the cert immediately: /sigil revoke <serialBase64>"), false);

            return 1;
        } catch (Exception ex) {
            src.sendFailure(Component.literal("Provision failed: " + ex.getMessage()));
            return 0;
        }
    }
}