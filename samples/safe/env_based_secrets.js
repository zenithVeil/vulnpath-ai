// Negative example: secrets come from process.env, not string literals.

const apiKey = process.env.API_KEY;
const password = process.env.DB_PASSWORD;
const jwtSecret = process.env.JWT_SECRET;
const databasePassword = process.env.DATABASE_PASSWORD;

module.exports = { apiKey, password, jwtSecret, databasePassword };
