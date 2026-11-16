# Keycloak RabbitMQ OTP Authenticator

Build with Java 21 and Maven, then copy `target/keycloak-otp-authenticator-1.0.0.jar`
to Keycloak's `providers` directory and run `kc.sh build` (or `kc.bat build`). Add
**RabbitMQ OTP** after a user-identifying execution in the browser flow.

RabbitMQ settings are read from environment variables:

- `RABBITMQ_HOST` (default `localhost`)
- `RABBITMQ_PORT` (default `5672`)
- `RABBITMQ_USERNAME` (default `guest`)
- `RABBITMQ_PASSWORD` (default `guest`)
- `RABBITMQ_VHOST` (default `/`)
- `RABBITMQ_QUEUE` (default `keycloak.otp`)
- `RABBITMQ_CONNECTION_TIMEOUT_MS` (default `5000`)
- `TOTP_SERVER_SECRET` (default `eqwhkjehqwA$anP@rdakht!20sa.`)


The durable queue is declared by the provider. Published JSON contains `userId`,
`username`, and `otp`. The OTP lifetime is five minutes with at most five attempts.
