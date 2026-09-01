# Security Policy

Report vulnerabilities **privately**. Do not open a public issue for a suspected authentication bypass, oracle, or secret leak.

## How to report

Open **Security → Advisories → New draft security advisory** on this repository.

Include the Acumatica version, the scheme (`HMAC` / `HMACTS` / `SECRET` / `BASIC` / `JWT` / `NONE`), and whether a sender can distinguish failure modes.

## Please do not

- Open a public issue that includes a real webhook secret, even a rotated one.
- Ask us to attach licensed `PX.*` assemblies to a ticket.

## Supported versions

The latest Release on the `main` branch, targeting Acumatica 2025 R2 – 2026 R1.
