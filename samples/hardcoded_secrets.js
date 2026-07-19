// Intentionally vulnerable hardcoded secrets sample.
// These are fake credentials for security scanning demos only.

const config = {
  databaseUser: 'admin',
  databasePassword: 'P@ssw0rd123!',
  apiKey: 'sk_test_51HARDcodedExampleKeyForDemoOnly',
  jwtSecret: 'super-secret-signing-key',
  awsAccessKeyId: 'AKIAIOSFODNN7EXAMPLE',
  awsSecretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
};

module.exports = config;
