// Intentionally vulnerable hardcoded secrets sample.
// Synthetic fixtures for scanner demos only — not real credentials.

const config = {
  databaseUser: 'demo_user_only',
  databasePassword: 'EXAMPLE_ONLY_not_a_real_password',
  apiKey: 'sk_test_fake_key_for_fixture_only',
  jwtSecret: 'fake-jwt-secret-for-tests-only',
  awsAccessKeyId: 'AKIA_EXAMPLE_NOT_REAL_0000',
  awsSecretAccessKey: 'fake_secret_access_key_for_fixture_only',
};

module.exports = config;
