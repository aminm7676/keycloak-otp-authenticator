package com.example.keycloak.otp;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.sessions.AuthenticationSessionModel;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.Arrays;
import java.util.Base64;
import java.util.Locale;

public final class RabbitMqOtpAuthenticator implements Authenticator {
    private static final String FORM_TEMPLATE = "login-otp-form.ftl";
    private static final String FORM_FIELD = "otp";
    private static final String NOTE_PREFIX = "rabbitmq-otp.";
    private static final String HASH_NOTE = NOTE_PREFIX + "hash";
    private static final String SALT_NOTE = NOTE_PREFIX + "salt";
    private static final String EXPIRES_AT_NOTE = NOTE_PREFIX + "expires-at";
    private static final String ATTEMPTS_NOTE = NOTE_PREFIX + "attempts";
    private static final Duration OTP_LIFETIME = Duration.ofMinutes(5);
    private static final int MAX_ATTEMPTS = 5;
    private static final int PBKDF2_ITERATIONS = 120_000;
    private static final int HASH_BITS = 256;
    private static final int SALT_BYTES = 16;
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private final RabbitMqOtpPublisher publisher;

    public RabbitMqOtpAuthenticator(RabbitMqOtpPublisher publisher) {
        this.publisher = publisher;
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        AuthenticationSessionModel authenticationSession = context.getAuthenticationSession();
        if (hasUsableChallenge(authenticationSession)) {
            context.challenge(form(context).createForm(FORM_TEMPLATE));
            return;
        }

        clearOtpState(authenticationSession);
        String otp = generateOtp();
        byte[] salt = new byte[SALT_BYTES];
        SECURE_RANDOM.nextBytes(salt);

        try {
            byte[] hash = hash(otp, salt);
            authenticationSession.setAuthNote(HASH_NOTE, Base64.getEncoder().encodeToString(hash));
            authenticationSession.setAuthNote(SALT_NOTE, Base64.getEncoder().encodeToString(salt));
            authenticationSession.setAuthNote(
                    EXPIRES_AT_NOTE,
                    Long.toString(System.currentTimeMillis() + OTP_LIFETIME.toMillis()));
            authenticationSession.setAuthNote(ATTEMPTS_NOTE, "0");

            // publisher.publish(context.getUser().getId(), context.getUser().getUsername(), otp);
            String phoneNumber = context.getUser().getFirstAttribute("phoneNumber");

            if (phoneNumber == null || phoneNumber.isBlank()) {
                failClosed(context);
                return;
            }

            publisher.publish(context.getUser().getId(),phoneNumber,otp);

            context.challenge(form(context).createForm(FORM_TEMPLATE));
            
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            failClosed(context);
        } catch (Exception exception) {
            failClosed(context);
        } finally {
            Arrays.fill(salt, (byte) 0);
        }
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        AuthenticationSessionModel authenticationSession = context.getAuthenticationSession();
        StoredChallenge challenge = readChallenge(authenticationSession);
        if (challenge == null) {
            clearOtpState(authenticationSession);
            failWithPage(context, AuthenticationFlowError.EXPIRED_CODE,
                    "The verification code is missing or no longer valid.");
            return;
        }

        if (System.currentTimeMillis() >= challenge.expiresAt()) {
            clearOtpState(authenticationSession);
            failWithPage(context, AuthenticationFlowError.EXPIRED_CODE,
                    "The verification code has expired. Restart sign-in to request a new code.");
            return;
        }

        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        String submittedOtp = formData.getFirst(FORM_FIELD);
        submittedOtp = submittedOtp == null ? "" : submittedOtp.trim();

        int nextAttempt = challenge.attempts() + 1;
        boolean valid = submittedOtp.matches("\\d{6}") && matches(submittedOtp, challenge);
        if (valid) {
            clearOtpState(authenticationSession);
            context.success();
            return;
        }

        if (nextAttempt >= MAX_ATTEMPTS) {
            clearOtpState(authenticationSession);
            failWithPage(context, AuthenticationFlowError.INVALID_CREDENTIALS,
                    "Too many invalid attempts. Restart sign-in to request a new code.");
            return;
        }

        authenticationSession.setAuthNote(ATTEMPTS_NOTE, Integer.toString(nextAttempt));
        LoginFormsProvider form = form(context)
                .setFormData(formData)
                .addError(new FormMessage(FORM_FIELD,
                        "Invalid verification code. " + (MAX_ATTEMPTS - nextAttempt) + " attempts remain."));
        context.failureChallenge(
                AuthenticationFlowError.INVALID_CREDENTIALS,
                form.createForm(FORM_TEMPLATE));
    }

    private static boolean hasUsableChallenge(AuthenticationSessionModel session) {
        StoredChallenge challenge = readChallenge(session);
        return challenge != null
                && challenge.expiresAt() > System.currentTimeMillis()
                && challenge.attempts() < MAX_ATTEMPTS;
    }

    private static StoredChallenge readChallenge(AuthenticationSessionModel session) {
        String hash = session.getAuthNote(HASH_NOTE);
        String salt = session.getAuthNote(SALT_NOTE);
        String expiresAt = session.getAuthNote(EXPIRES_AT_NOTE);
        String attempts = session.getAuthNote(ATTEMPTS_NOTE);
        if (hash == null || salt == null || expiresAt == null || attempts == null) {
            return null;
        }
        try {
            return new StoredChallenge(
                    Base64.getDecoder().decode(hash),
                    Base64.getDecoder().decode(salt),
                    Long.parseLong(expiresAt),
                    Integer.parseInt(attempts));
        } catch (IllegalArgumentException exception) {
            return null;
        }
    }

    private static boolean matches(String submittedOtp, StoredChallenge challenge) {
        try {
            byte[] submittedHash = hash(submittedOtp, challenge.salt());
            try {
                return MessageDigest.isEqual(challenge.hash(), submittedHash);
            } finally {
                Arrays.fill(submittedHash, (byte) 0);
            }
        } catch (GeneralSecurityException exception) {
            return false;
        }
    }

    private static byte[] hash(String otp, byte[] salt) throws GeneralSecurityException {
        char[] characters = otp.toCharArray();
        PBEKeySpec keySpec = new PBEKeySpec(characters, salt, PBKDF2_ITERATIONS, HASH_BITS);
        try {
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
                    .generateSecret(keySpec)
                    .getEncoded();
        } finally {
            keySpec.clearPassword();
            Arrays.fill(characters, '\0');
        }
    }

    private static String generateOtp() {
        return String.format(Locale.ROOT, "%06d", SECURE_RANDOM.nextInt(1_000_000));
    }

    private static LoginFormsProvider form(AuthenticationFlowContext context) {
        return context.form().setAttribute("otpExpiresInMinutes", OTP_LIFETIME.toMinutes());
    }

    private static void failClosed(AuthenticationFlowContext context) {
        clearOtpState(context.getAuthenticationSession());
        Response response = context.form()
                .setError("The verification code could not be delivered. Please try again later.")
                .createErrorPage(Response.Status.SERVICE_UNAVAILABLE);
        context.failure(AuthenticationFlowError.INTERNAL_ERROR, response);
    }

    private static void failWithPage(
            AuthenticationFlowContext context,
            AuthenticationFlowError error,
            String message) {
        Response response = context.form()
                .setError(message)
                .createErrorPage(Response.Status.UNAUTHORIZED);
        context.failure(error, response);
    }

    private static void clearOtpState(AuthenticationSessionModel session) {
        session.removeAuthNote(HASH_NOTE);
        session.removeAuthNote(SALT_NOTE);
        session.removeAuthNote(EXPIRES_AT_NOTE);
        session.removeAuthNote(ATTEMPTS_NOTE);
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
    }

    @Override
    public void close() {
    }

    private record StoredChallenge(byte[] hash, byte[] salt, long expiresAt, int attempts) {
    }
}
