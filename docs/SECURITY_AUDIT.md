# AtlasDNS Security Audit — 2026-03-27

## Summary

Manual source-code review of `src/` targeting OWASP Top 10, DNS-specific threats,
and auth/session issues. Three critical findings were fixed in this commit; the
remainder are documented below for follow-up.

---

## Fixed (this commit)

### 1. Session tokens used UUID v4 — now uses 256-bit CSPRNG
- **File**: `src/web/users.rs` (create_session)
- **Severity**: Critical
- **Issue**: `Uuid::new_v4()` is not designed for security-token generation.
- **Fix**: Replaced with `generate_secure_token()` using `rand::thread_rng().fill()` producing 64 hex chars (256 bits).

### 2. API key hashing used SHA-256 — now uses bcrypt
- **File**: `src/web/users.rs` (create_user_api_key / validate_user_api_key)
- **Severity**: Critical
- **Issue**: SHA-256 has no work factor; compromised hashes are trivially cracked.
- **Fix**: API keys are now hashed with bcrypt. Validation supports both bcrypt (new) and SHA-256 (legacy migration path).

### 3. RPZ load-from-file path traversal
- **File**: `src/web/rpz.rs` (load_from_file)
- **Severity**: High
- **Issue**: User-supplied file path passed directly to filesystem without validation; `../../etc/shadow` would be accepted.
- **Fix**: Added `Component::ParentDir` rejection before loading.

---

## Open Findings (prioritized)

### HIGH

| # | File | Issue | Recommendation |
|---|------|-------|----------------|
| 4 | `src/web/users.rs:351` | `FORCE_ADMIN` + `ADMIN_PASSWORD` env vars allow fixed credentials | Gate behind `#[cfg(debug_assertions)]` or remove entirely |
| 5 | `src/web/users.rs:750` | `validate_session()` does not check `ip_address` stored on session | Add optional IP-pinning check |
| 6 | `src/web/server.rs` | No per-IP rate limiting on `/login` endpoint | Add IP-based rate limiter (the DNS rate limiter exists but doesn't cover HTTP) |

### MEDIUM

| # | File | Issue | Recommendation |
|---|------|-------|----------------|
| 7 | `src/web/users.rs:428` | Legacy SHA-256 password hashes still accepted | Set a migration deadline; force bcrypt rehash on next login |
| 8 | `src/web/users.rs:1135` | TOTP 2FA is a stub — any code is accepted | Implement proper TOTP verification or remove the feature |
| 9 | `src/dns/zone_parser.rs:109` | `$INCLUDE` directive has no depth limit | Cap at 10 levels to prevent stack exhaustion |

### LOW

| # | File | Issue | Recommendation |
|---|------|-------|----------------|
| 10 | `src/web/users.rs:231` | Audit log stored in unbounded `Vec` in memory | Persist to SQLite or cap + rotate |
| 11 | `src/web/users.rs:444` | Account lockout duration hardcoded to 30 min | Make configurable via env/config |
| 12 | `src/web/index.rs` | Query log has no hard upper bound | Use a ring buffer or LRU cache |

---

## Not Found (negative findings)

- **SQL injection**: All SQLite access uses `sqlx` with parameterized queries. No raw string interpolation found.
- **XSS**: Handlebars templates use auto-escaping by default. No `{{{triple-brace}}}` unescaped output found.
- **Command injection**: No `std::process::Command` with user-supplied input found.
- **DNS cache poisoning**: Transaction IDs are generated via `rand::thread_rng()` (CSPRNG). Source port randomization is in place.
- **DNSSEC**: Validation chain uses `hickory-resolver` with `dnssec-openssl` feature, which is the standard approach.
