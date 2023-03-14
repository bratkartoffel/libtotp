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
import java.util.concurrent.TimeUnit;

@Slf4j
public class Totp {
    private final Random random;
    @Getter
    private final TotpSettings settings;

    public Totp() {
        this(TotpSettings.DEFAULT);
    }

    public Totp(@NotNull TotpSettings settings) {
        this(settings, new SecureRandom());
    }

    public Totp(@NotNull TotpSettings settings, @NotNull Random random) {
        this.settings = settings;
        this.random = random;
    }

    /**
     * Verify the given code using a secret and the current time.
     *
     * @param secret shared secret
     * @param code   the code to verify
     * @return <code>true</code> if the code is valid according to the configured settings, <code>false</code> otherwise
     */
    @Contract(pure = true)
    public boolean verifyCode(byte @NotNull [] secret, int code) {
        return verifyCode(secret, code, getTimeIndex());
    }


    /**
     * Verify the given code using a secret and a custom counter.
     *
     * @param secret  shared secret
     * @param code    the code to verify
     * @param counter custom counter
     * @return <code>true</code> if the code is valid according to the configured settings, <code>false</code> otherwise
     */
    @Contract(pure = true)
    public boolean verifyCode(byte @NotNull [] secret, int code, long counter) {
        int tokenMask = getTokenMod();
        SecretKeySpec key = new SecretKeySpec(secret, "RAW");
        try {
            Mac mac = getMac(key);
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

    /**
     * Generate a new shared secret
     *
     * @return shared secret
     */
    @Contract(pure = true, value = "-> new")
    public byte @NotNull [] generateSecret() {
        byte[] secret = new byte[settings.getSecretLength()];
        random.nextBytes(secret);
        return secret;
    }

    /**
     * Generate and return the currently valid code for the given secret.
     *
     * @param secret shared secret
     * @return current code
     * @throws IllegalArgumentException if the given secret is invalid
     */
    @Contract(pure = true)
    public int getCode(byte @NotNull [] secret) throws IllegalArgumentException {
        return getCode(secret, getTimeIndex());
    }

    /**
     * Generate and return the currently valid code for the given secret.
     *
     * @param secret  shared secret
     * @param counter custom counter
     * @return current code
     * @throws IllegalArgumentException if the given secret is invalid
     */
    @Contract(pure = true)
    public int getCode(byte @NotNull [] secret, long counter) throws IllegalArgumentException {
        int tokenMask = getTokenMod();
        SecretKeySpec key = new SecretKeySpec(secret, "RAW");
        try {
            Mac mac = getMac(key);
            ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
            buffer.putLong(0, counter);
            return createCode(mac, buffer.array(), tokenMask);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new IllegalArgumentException(e);
        }
    }

    @Contract(pure = true)
    private int getTokenMod() {
        return (int) Math.pow(10, settings.getTokenLength());
    }

    @Contract(pure = true)
    private long getTimeIndex() {
        return TimeUnit.MILLISECONDS.toSeconds(System.currentTimeMillis()) / 30;
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

    @Contract(pure = true, value = "_ -> new")
    private @NotNull Mac getMac(@NotNull SecretKeySpec key) throws NoSuchAlgorithmException, InvalidKeyException {
        Mac mac = Mac.getInstance(settings.getHmac());
        mac.init(key);
        return mac;
    }
}
