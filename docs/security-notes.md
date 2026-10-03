# Web Security Notes — Common Vulnerabilities & Remediation

Companion reference used while building and reviewing this service.

## 1. Injection (SQLi / NoSQLi / Command)
- **Risk**: untrusted input concatenated into queries or shells.
- **In our app**: all DB access goes through SQLAlchemy parameter binding; the
  scanner module uses `socket`/`select`, never `subprocess`.
- **Remediation**: parameterize queries; avoid `shell=True`; validate/whitelist
  ports and CIDRs before use.

## 2. Broken Access Control
- **Risk**: unauthenticated users can reach admin functionality.
- **In our app**: `POST /api/scans` is the only write endpoint; it is constrained
  by the `SCAN_ALLOWED_CIDRS` allow-list, but has no auth in dev.
- **Remediation (production)**:
  - Put the API behind an auth layer (mTLS / OAuth2 / signed tokens).
  - Enforce RBAC: read-only vs operator.
  - Keep the allow-list server-side (never client-provided).

## 3. Security Misconfiguration
- **Risk**: default creds, debug mode, exposed admin ports.
- **In our app**: `.env` contains a placeholder DB password; `FLASK_DEBUG=1`
  is set only in `scripts/run_api.sh` for local dev.
- **Remediation**: rotate `POSTGRES_PASSWORD`; disable debug in prod; bind the
  API to a private subnet / SG; terminate TLS at an ALB or nginx.

## 4. Sensitive Data Exposure
- **Risk**: logs contain usernames/IPs; DB may contain credentials.
- **In our app**: we never log raw passwords; `raw` field stores the syslog
  line as-is (which is expected for audit).
- **Remediation**: encrypt the EBS volume; enable TLS for Postgres; scrub
  credentials from any parsed field before persistence; set retention.

## 5. Vulnerable & Outdated Components
- **Risk**: dependency CVEs.
- **In our app**: all deps pinned in `requirements.txt`.
- **Remediation**: run `pip-audit` / Dependabot; pin base image digests;
  rebuild on CVE notifications.

## 6. Identification & Authentication Failures
- **Risk**: brute-force of SSH / API.
- **In our app**: brute-force detection is literally the core rule
  (`brute_force` threats).
- **Remediation**: fail2ban / sshd rate limits; TOTP on the API; alert on
  `brute_force` threats of severity `critical`.

## 7. Server-Side Request Forgery (SSRF)
- **Risk**: user-supplied URLs cause the server to hit internal services.
- **In our app**: `POST /api/scans` accepts a target — mitigated by the CIDR
  allow-list.
- **Remediation**: never trust client-supplied targets; resolve DNS first,
  block link-local + metadata IPs (169.254.169.254).

## 8. Insecure Deserialization
- **Risk**: pickle / yaml.load on untrusted data.
- **In our app**: we only use `json.loads` and pydantic models.
- **Remediation**: keep JSON; avoid `pickle`; schema-validate every payload.

## 9. Insufficient Logging & Monitoring
- **Risk**: attacks go unnoticed.
- **In our app**: every detection produces a `Threat` row with severity,
  timestamps, and linked events — that's the whole point of this project.
- **Remediation**: ship API + container logs to a central store (CloudWatch,
  Loki, ELK); alert on `critical` threats and `/healthz` failures.

## 10. Using Components with Known Vulnerabilities
Overlaps with #5 — the practical rule: treat `requirements.txt`,
`Dockerfile`, and base-image tags as code review targets, and scan them.
