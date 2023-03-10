/*
 * MIT Licence
 * Copyright (c) 2023 Simon Frankenberger
 *
 * Please see LICENCE.md for complete licence text.
 */
package eu.fraho.libs.totp;

import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.jetbrains.annotations.Contract;
import org.jetbrains.annotations.NotNull;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Random;

@Slf4j
public class Totp {
    private final Random random;
    @Getter
    private final TotpSettings settings;

    public Totp(@NotNull TotpSettings settings) {
        this(settings, new SecureRandom());
    }

    public Totp(@NotNull TotpSettings settings, @NotNull Random random) {
        this.settings = settings;
        this.random = random;
    }

    @Contract(pure = true)
    public boolean verifyCode(byte @NotNull [] secret, int code) {
        return verifyCode(secret, code, getTimeIndex());
    }

    @Contract(pure = true)
    public boolean verifyCode(byte @NotNull [] secret, int code, long counter) {
        int tokenMask = getTokenMod();
        SecretKeySpec key = new SecretKeySpec(secret, "RAW");
        try {
            Mac mac = Mac.getInstance(settings.getHmac());
            mac.init(key);
            ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);

            for (int i = -settings.getVariance(); i <= settings.getVariance(); i++) {
                buffer.putLong(0, counter + i);
                byte[] timeBytes = buffer.array();
                int calculated = createCode(mac, timeBytes, tokenMask);
                log.trace("Verifying code offset={}, calculated={}, given={}", i, calculated, code);
                if (calculated == code) {
                    return true;
                }
            }
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            log.error("Error checking totp pin", e);
        }

        return false;
    }

    @Contract(pure = true, value = "-> new")
    public byte @NotNull [] generateSecret() {
        byte[] secret = new byte[settings.getSecretLength()];
        random.nextBytes(secret);
        return secret;
    }

    @Contract(pure = true)
    private int getTokenMod() {
        return (int) Math.pow(10, settings.getTokenLength());
    }

    @Contract(pure = true)
    private long getTimeIndex() {
        return System.currentTimeMillis() / 1000 / 30;
    }

    @Contract(pure = true)
    private int createCode(@NotNull Mac mac, byte @NotNull [] counter, int tokenMask) {
        byte[] hash = mac.doFinal(counter);
        int offset = hash[hash.length - 1] & 0x0f;
        return ((hash[offset] & 0x7f) << 24
                | (hash[offset + 1] & 0xff) << 16
                | (hash[offset + 2] & 0xff) << 8
                | (hash[offset + 3] & 0xff)) % tokenMask;
    }
}
