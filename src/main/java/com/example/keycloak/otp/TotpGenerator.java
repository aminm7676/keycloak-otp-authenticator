import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Locale;

public class TotpGenerator {

    private static final String ALGORITHM = "HmacSHA512";

    private static String serverSecret() {
        String value = System.getenv("TOTP_SERVER_SECRET");

        if (value == null || value.isBlank()) {
           // throw new IllegalStateException("TOTP_SERVER_SECRET is not set");
           return "eqwhkjehqwA$anP@rdakht!20sa.";
        }

        return value;
    }

    private static int serverDigits() {
        String value = System.getenv("TOTP_SERVER_DIGITS");

        if (value == null || value.isBlank()) {
            //throw new IllegalStateException("TOTP_SERVER_DIGITS is not set");
            return 6;
        }

        try {
            int digits = Integer.parseInt(value.trim());

            if (digits < 1 || digits > 9) {
                throw new IllegalArgumentException("TOTP_SERVER_DIGITS must be between 1 and 9");
                
            }

            return digits;

        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("TOTP_SERVER_DIGITS must be a valid integer", e);
        }
    }

    private static int serverPeriod() {
        String value = System.getenv("TOTP_SERVER_PERIOD");

        if (value == null || value.isBlank()) {
            //throw new IllegalStateException("TOTP_SERVER_PERIOD is not set");
            return 180;
        }

        try {
            int period = Integer.parseInt(value.trim());

            if (period <= 0) {
                throw new IllegalArgumentException("TOTP_SERVER_PERIOD must be greater than zero");
            }

            return period;

        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("TOTP_SERVER_PERIOD must be a valid integer", e);
        }
    }

    private static String generateOtp(byte[] secretBytes, long counter, int digits)
            throws Exception {

        byte[] counterBytes = ByteBuffer.allocate(8)
                .putLong(counter)
                .array();

        Mac mac = Mac.getInstance(ALGORITHM);

        mac.init(new SecretKeySpec(secretBytes, ALGORITHM));

        byte[] hash = mac.doFinal(counterBytes);

        int offset = hash[hash.length - 1] & 0x0F;

        int binary =
                ((hash[offset] & 0x7F) << 24) |
                ((hash[offset + 1] & 0xFF) << 16) |
                ((hash[offset + 2] & 0xFF) << 8) |
                (hash[offset + 3] & 0xFF);

        long modulus = (long) Math.pow(10, digits);

        long otp = binary % modulus;

        return String.format(Locale.ROOT, "%0" + digits + "d", otp);
    }

    public static String compute(String key) {

        if (key == null || key.isBlank()) {
            throw new IllegalArgumentException("Key cannot be empty");
        }

        try {

            String secret = serverSecret() + key;

            int period = serverPeriod();
            int digits = serverDigits();

            byte[] secretBytes = secret.getBytes(StandardCharsets.UTF_8);

            long counter = System.currentTimeMillis() / 1000 / period;

            return generateOtp(secretBytes, counter, digits);

        } catch (Exception e) {
            throw new RuntimeException("Failed to generate TOTP", e);
        }
    }

    public static boolean verify(String key, String totpCode) {

        if (key == null || key.isBlank() || totpCode == null) {
            return false;
        }

        try {

            String secret = serverSecret() + key;

            int period = serverPeriod();
            int digits = serverDigits();

            if (!totpCode.matches("\\d{" + digits + "}")) {
                return false;
            }

            byte[] secretBytes = secret.getBytes(StandardCharsets.UTF_8);

            long currentCounter = System.currentTimeMillis() / 1000 / period;

            // Allow previous, current and next time window.
            for (long counter = currentCounter - 1;
                 counter <= currentCounter + 1;
                 counter++) {

                String generatedOtp = generateOtp(secretBytes, counter, digits);

                if (MessageDigest.isEqual(
                        generatedOtp.getBytes(StandardCharsets.UTF_8),
                        totpCode.getBytes(StandardCharsets.UTF_8))) {

                    return true;
                }
            }

            return false;

        } catch (Exception e) {
            throw new RuntimeException("Failed to verify TOTP", e);
        }
    }
}