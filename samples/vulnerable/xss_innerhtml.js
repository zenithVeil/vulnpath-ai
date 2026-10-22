// Intentionally vulnerable DOM XSS via innerHTML.

function renderComment(userInput) {
  const output = document.getElementById("comments");
  // VULNERABLE: untrusted input assigned to innerHTML.
  output.innerHTML = userInput;
}
