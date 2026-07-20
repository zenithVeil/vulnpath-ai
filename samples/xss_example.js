// Intentionally vulnerable Express reflected XSS sample.
// Do not use this pattern in production.

const express = require('express');

const app = express();
const port = 3000;

app.get('/search', (req, res) => {
  const query = req.query.q || '';

  // VULNERABLE: untrusted input is embedded in HTML without escaping.
  res.send(`
    <!doctype html>
    <html>
      <head><title>Search</title></head>
      <body>
        <h1>Search results for: ${query}</h1>
        <p>No results found.</p>
      </body>
    </html>
  `);
});

app.listen(port, () => {
  console.log(`Vulnerable search app listening on http://localhost:${port}`);
});