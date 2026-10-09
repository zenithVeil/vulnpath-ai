// Negative example: HTML escaped before send; no innerHTML / template literals.

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function renderSearch(req, res) {
  const raw = req.query.q || '';
  const safe = escapeHtml(raw);
  res.send('<h1>Search: ' + safe + '</h1>');
}

module.exports = { escapeHtml, renderSearch };
