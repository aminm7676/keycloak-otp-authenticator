package com.example.keycloak.otp;

import com.rabbitmq.client.AMQP;
import com.rabbitmq.client.Channel;
import com.rabbitmq.client.Connection;
import com.rabbitmq.client.ConnectionFactory;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeoutException;

public final class RabbitMqOtpPublisher {
    private static final int DEFAULT_PORT = 5672;
    private static final int DEFAULT_TIMEOUT_MILLIS = 5_000;
    private static final int PUBLISH_CONFIRM_TIMEOUT_MILLIS = 5_000;

    private final Settings settings;

    public RabbitMqOtpPublisher() {
        this.settings = Settings.fromEnvironment();
    }

    public void publish(String userId, String username, String otp)
            throws IOException, TimeoutException, InterruptedException {
        ConnectionFactory factory = new ConnectionFactory();
        factory.setHost(settings.host());
        factory.setPort(settings.port());
        factory.setUsername(settings.username());
        factory.setPassword(settings.password());
        factory.setVirtualHost(settings.virtualHost());
        factory.setConnectionTimeout(settings.connectionTimeoutMillis());
        factory.setHandshakeTimeout(settings.connectionTimeoutMillis());
        factory.setAutomaticRecoveryEnabled(false);
        factory.setTopologyRecoveryEnabled(false);

        byte[] body = json(userId, username, otp).getBytes(StandardCharsets.UTF_8);
        AMQP.BasicProperties properties = new AMQP.BasicProperties.Builder()
                .contentType("application/json")
                .contentEncoding(StandardCharsets.UTF_8.name())
                .deliveryMode(2)
                .build();

        try (Connection connection = factory.newConnection("keycloak-otp-publisher");
             Channel channel = connection.createChannel()) {
            channel.queueDeclare(settings.queue(), true, false, false, null);
            channel.confirmSelect();
            channel.basicPublish("", settings.queue(), true, properties, body);
            channel.waitForConfirmsOrDie(PUBLISH_CONFIRM_TIMEOUT_MILLIS);
        }
    }

    private static String json(String userId, String username, String otp) {
        return "{\"userId\":\"" + escapeJson(userId)
                + "\",\"username\":\"" + escapeJson(username)
                + "\",\"otp\":\"" + escapeJson(otp) + "\"}";
    }

    private static String escapeJson(String value) {
        StringBuilder escaped = new StringBuilder(value.length() + 16);
        for (int i = 0; i < value.length(); i++) {
            char character = value.charAt(i);
            switch (character) {
                case '"' -> escaped.append("\\\"");
                case '\\' -> escaped.append("\\\\");
                case '\b' -> escaped.append("\\b");
                case '\f' -> escaped.append("\\f");
                case '\n' -> escaped.append("\\n");
                case '\r' -> escaped.append("\\r");
                case '\t' -> escaped.append("\\t");
                default -> {
                    if (character < 0x20) {
                        escaped.append(String.format("\\u%04x", (int) character));
                    } else {
                        escaped.append(character);
                    }
                }
            }
        }
        return escaped.toString();
    }

    private record Settings(
            String host,
            int port,
            String username,
            String password,
            String virtualHost,
            String queue,
            int connectionTimeoutMillis) {

        private static Settings fromEnvironment() {
            return new Settings(
                    environment("RABBITMQ_HOST", "localhost"),
                    positiveInteger("RABBITMQ_PORT", DEFAULT_PORT),
                    environment("RABBITMQ_USERNAME", "guest"),
                    environment("RABBITMQ_PASSWORD", "guest"),
                    environment("RABBITMQ_VHOST", "/"),
                    environment("RABBITMQ_QUEUE", "keycloak.otp"),
                    positiveInteger("RABBITMQ_CONNECTION_TIMEOUT_MS", DEFAULT_TIMEOUT_MILLIS));
        }

        private static String environment(String name, String defaultValue) {
            String value = System.getenv(name);
            return value == null || value.isBlank() ? defaultValue : value;
        }

        private static int positiveInteger(String name, int defaultValue) {
            String value = System.getenv(name);
            if (value == null || value.isBlank()) {
                return defaultValue;
            }
            try {
                int parsed = Integer.parseInt(value);
                if (parsed <= 0) {
                    throw new IllegalArgumentException(name + " must be a positive integer");
                }
                return parsed;
            } catch (NumberFormatException exception) {
                throw new IllegalArgumentException(name + " must be a positive integer", exception);
            }
        }
    }
}
