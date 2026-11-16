package com.example.keycloak.otp;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Locale;

public final class TotpGenerator {
    private static final int STEP_SECONDS = 180;
    private static final int DIGITS = 6;
    private static final String HMAC_ALGORITHM = "HmacSHA512";

    private TotpGenerator() {
    }

    private static String serverSecret() {
        String value = System.getenv("TOTP_SERVER_SECRET");
        if (value == null || value.isBlank()) {
            throw new IllegalStateException("TOTP_SERVER_SECRET is not set");
        }
        return value;
    }

    public static String compute(String userKey, long timeMillis) throws GeneralSecurityException {
        long counter = Math.floorDiv(timeMillis / 1000, (long) STEP_SECONDS);
        return computeForCounter(userKey, counter);
    }

    /** window = تعداد بازه مجاز قبل و بعد از بازه فعلی (۱ یعنی کمی تلورانس برای تاخیر). */
    public static boolean verify(String userKey, String code, long timeMillis, int window)
            throws GeneralSecurityException {
        long counter = Math.floorDiv(timeMillis / 1000, (long) STEP_SECONDS);
        byte[] submitted = code.getBytes(StandardCharsets.UTF_8);
        boolean ok = false;
        for (long i = counter - window; i <= counter + window; i++) {
            byte[] expected = computeForCounter(userKey, i).getBytes(StandardCharsets.UTF_8);
            ok |= MessageDigest.isEqual(expected, submitted);
        }
        return ok;
    }

    private static String computeForCounter(String userKey, long counter) throws GeneralSecurityException {
        byte[] key = (serverSecret() + userKey).getBytes(StandardCharsets.UTF_8);
        Mac mac = Mac.getInstance(HMAC_ALGORITHM);
        mac.init(new SecretKeySpec(key, HMAC_ALGORITHM));
        byte[] hash = mac.doFinal(ByteBuffer.allocate(8).putLong(counter).array());

        int offset = hash[hash.length - 1] & 0x0F;
        int binary = ((hash[offset] & 0x7F) << 24)
                | ((hash[offset + 1] & 0xFF) << 16)
                | ((hash[offset + 2] & 0xFF) << 8)
                | (hash[offset + 3] & 0xFF);
        int otp = binary % 1_000_000;
        return String.format(Locale.ROOT, "%0" + DIGITS + "d", otp);
    }
}