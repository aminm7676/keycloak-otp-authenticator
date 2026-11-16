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

import java.security.GeneralSecurityException;
import java.time.Duration;

public final class RabbitMqTotpAuthenticator implements Authenticator {
    private static final String FORM_TEMPLATE = "login-otp-form.ftl";
    private static final String FORM_FIELD = "otp";
    private static final String NOTE_PREFIX = "rabbitmq-totp.";
    private static final String EXPIRES_AT_NOTE = NOTE_PREFIX + "expires-at";
    private static final String ATTEMPTS_NOTE = NOTE_PREFIX + "attempts";
    private static final Duration OTP_LIFETIME = Duration.ofMinutes(3);
    private static final int MAX_ATTEMPTS = 5;
    private static final int VERIFY_WINDOW = 1;

    private final RabbitMqOtpPublisher publisher;

    public RabbitMqTotpAuthenticator(RabbitMqOtpPublisher publisher) {
        this.publisher = publisher;
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        AuthenticationSessionModel session = context.getAuthenticationSession();
        if (hasUsableChallenge(session)) {
            context.challenge(form(context).createForm(FORM_TEMPLATE));
            return;
        }

        clearState(session);
        try {
            UserModel user = context.getUser();
            String otp = TotpGenerator.compute(user.getId(), System.currentTimeMillis());

            session.setAuthNote(EXPIRES_AT_NOTE,
                    Long.toString(System.currentTimeMillis() + OTP_LIFETIME.toMillis()));
            session.setAuthNote(ATTEMPTS_NOTE, "0");

            publisher.publish(user.getId(), user.getUsername(), otp);
            context.challenge(form(context).createForm(FORM_TEMPLATE));
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            failClosed(context);
        } catch (Exception exception) {
            failClosed(context);
        }
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        AuthenticationSessionModel session = context.getAuthenticationSession();
        long[] state = readState(session);
        if (state == null) {
            clearState(session);
            failWithPage(context, AuthenticationFlowError.EXPIRED_CODE,
                    "The verification code is missing or no longer valid.");
            return;
        }

        long expiresAt = state[0];
        int attempts = (int) state[1];

        if (System.currentTimeMillis() >= expiresAt) {
            clearState(session);
            failWithPage(context, AuthenticationFlowError.EXPIRED_CODE,
                    "The verification code has expired. Restart sign-in to request a new code.");
            return;
        }

        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        String submittedOtp = formData.getFirst(FORM_FIELD);
        submittedOtp = submittedOtp == null ? "" : submittedOtp.trim();

        int nextAttempt = attempts + 1;
        boolean valid = false;
        if (submittedOtp.matches("\\d{6}")) {
            try {
                valid = TotpGenerator.verify(
                        context.getUser().getId(), submittedOtp, System.currentTimeMillis(), VERIFY_WINDOW);
            } catch (GeneralSecurityException | IllegalStateException exception) {
                valid = false;
            }
        }

        if (valid) {
            clearState(session);
            context.success();
            return;
        }

        if (nextAttempt >= MAX_ATTEMPTS) {
            clearState(session);
            failWithPage(context, AuthenticationFlowError.INVALID_CREDENTIALS,
                    "Too many invalid attempts. Restart sign-in to request a new code.");
            return;
        }

        session.setAuthNote(ATTEMPTS_NOTE, Integer.toString(nextAttempt));
        LoginFormsProvider form = form(context)
                .setFormData(formData)
                .addError(new FormMessage(FORM_FIELD,
                        "Invalid verification code. " + (MAX_ATTEMPTS - nextAttempt) + " attempts remain."));
        context.failureChallenge(
                AuthenticationFlowError.INVALID_CREDENTIALS,
                form.createForm(FORM_TEMPLATE));
    }

    private static boolean hasUsableChallenge(AuthenticationSessionModel session) {
        long[] state = readState(session);
        return state != null
                && state[0] > System.currentTimeMillis()
                && state[1] < MAX_ATTEMPTS;
    }

    private static long[] readState(AuthenticationSessionModel session) {
        String expiresAt = session.getAuthNote(EXPIRES_AT_NOTE);
        String attempts = session.getAuthNote(ATTEMPTS_NOTE);
        if (expiresAt == null || attempts == null) {
            return null;
        }
        try {
            return new long[] {Long.parseLong(expiresAt), Long.parseLong(attempts)};
        } catch (NumberFormatException exception) {
            return null;
        }
    }

    private static LoginFormsProvider form(AuthenticationFlowContext context) {
        return context.form().setAttribute("otpExpiresInMinutes", OTP_LIFETIME.toMinutes());
    }

    private static void failClosed(AuthenticationFlowContext context) {
        clearState(context.getAuthenticationSession());
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

    private static void clearState(AuthenticationSessionModel session) {
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
}