// Intentionally vulnerable hardcoded secrets (JavaScript object literals).
// Synthetic fixtures for scanner demos only — not real credentials.

const config = {
  apiKey: "example-only-not-a-real-api-key",
  password: "EXAMPLE_ONLY_not_a_real_password",
  jwtSecret: "example-only-jwt-value-for-tests",
  databasePassword: "example-only-db-value-for-tests",
};

module.exports = config;
