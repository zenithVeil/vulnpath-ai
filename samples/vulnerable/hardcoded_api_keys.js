// Intentionally vulnerable hardcoded secrets (JavaScript object literals).

const config = {
  apiKey: "sk_test_hardcoded_demo_key",
  password: "SuperSecret123!",
  jwtSecret: "hardcoded-jwt-signing-secret",
  databasePassword: "db-pass-should-not-be-here",
};

module.exports = config;
