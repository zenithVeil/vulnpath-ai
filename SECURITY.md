# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 1.x     | Yes       |

## Reporting a vulnerability

Please report security issues **privately**:

- Use GitHub **Security Advisories** on this repository, or
- Contact the maintainer via the email on the GitHub profile

Do **not** open a public issue for an undisclosed vulnerability.

## Intentional test fixtures

Files under `samples/` (especially `samples/vulnerable/`) are **deliberate unsafe examples** used only for the scanner benchmark and demos.

- They use **synthetic** credentials and patterns
- They are **not** production code
- Findings in those paths are expected and do not indicate a compromise of this project

## Scope

VulnPath-AI is an offline static scanner. It reports findings and fix suggestions only; it does not exploit systems or apply changes without the user reviewing them.
