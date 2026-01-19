# authopsy

RBAC vulnerability scanner for REST APIs. Tests authorization by comparing responses across Admin, User, and Anonymous roles.

```
╭─────────────────────────────────┬───────┬───────┬───────┬──────────╮
│ Endpoint                        │ Admin │ User  │ Anon  │ Status   │
├─────────────────────────────────┼───────┼───────┼───────┼──────────┤
│ GET /api/admin/users            │ 200   │ 200 ⚠ │ 401   │ CRITICAL │
│ DELETE /api/users/{id}          │ 200   │ 200 ⚠ │ 401   │ CRITICAL │
│ GET /api/users                  │ 200   │ 403   │ 401   │ OK       │
╰─────────────────────────────────┴───────┴───────┴───────┴──────────╯

Findings

[CRITICAL] GET /api/admin/users
  → Vertical Privilege Escalation: User can access Admin-only resource
    Fix: Verify user role matches required permission level
```

## Install

### Quick Install (Recommended)

```bash
curl -sSL https://raw.githubusercontent.com/burakozcn01/authopsy/main/install.sh | bash
```

### Homebrew (macOS/Linux)

```bash
brew tap burakozcn01/tap
brew install authopsy
```

### Debian/Ubuntu (.deb)

```bash
VERSION="1.0.0"
ARCH=$(dpkg --print-architecture)
curl -LO "https://github.com/burakozcn01/authopsy/releases/download/v${VERSION}/authopsy_${VERSION}_${ARCH}.deb"
sudo dpkg -i authopsy_${VERSION}_${ARCH}.deb
```

### From Source

```bash
git clone https://github.com/burakozcn01/authopsy
cd authopsy
make install
```

### Cargo

```bash
cargo install --git https://github.com/burakozcn01/authopsy
```

### Manual Download

Download pre-built binaries from [GitHub Releases](https://github.com/burakozcn01/authopsy/releases)

## Quick Start

**1. Get your API tokens**

You need two JWT tokens or API keys - one for an admin user, one for a regular user.

**2. Run a scan**

```bash
# With OpenAPI spec
authopsy scan \
  --url https://api.yoursite.com \
  --spec openapi.json \
  --admin "Bearer eyJhbG..." \
  --user "Bearer eyJhbG..."

# Without spec (manual endpoints)
authopsy scan \
  --url https://api.yoursite.com \
  --endpoints "GET /api/users, GET /api/admin/users, DELETE /api/users/{id}" \
  --admin "Bearer eyJhbG..." \
  --user "Bearer eyJhbG..."
```

**3. Check the results**

- `CRITICAL` = User can access admin-only data
- `HIGH` = Missing auth or significant data exposure
- `OK` = Access control working correctly

## Real World Examples

### Testing a Node.js/Express API

```bash
# 1. Start your API
npm run dev

# 2. Login as admin and user, grab the tokens
ADMIN_TOKEN="Bearer eyJhbGciOiJIUzI1NiIs..."
USER_TOKEN="Bearer eyJhbGciOiJIUzI1NiIs..."

# 3. Run authopsy
authopsy scan \
  --url http://localhost:3000 \
  --spec ./docs/swagger.json \
  --admin "$ADMIN_TOKEN" \
  --user "$USER_TOKEN" \
  --output results.json
```

### Testing with API Keys instead of JWT

```bash
authopsy scan \
  --url https://api.example.com \
  --spec openapi.yaml \
  --admin "sk_live_admin_xxx" \
  --user "sk_live_user_yyy" \
  --header "X-API-Key"
```

### Skip public endpoints

If you have known public endpoints, exclude them from warnings:

```bash
authopsy scan \
  --url https://api.example.com \
  --spec openapi.json \
  --admin "Bearer xxx" \
  --user "Bearer yyy" \
  --public-paths "/api/public,/api/health,/api/docs"
```

### Test for bypass vulnerabilities

The `fuzz` command tries query parameters like `?admin=true` and headers like `X-Debug: true` to find authorization bypasses:

```bash
authopsy fuzz \
  --url https://api.example.com \
  --spec openapi.json \
  --user "Bearer user_token"
```

Example output:
```
[CRITICAL] GET /api/admin/config - Header
  Trigger: X-Debug: true
  Status: 403 -> 200

[HIGH] GET /api/users - Query Param
  Trigger: include_details=true
  Size: 219 -> 422 bytes
```

### Generate HTML report

```bash
# Run scan and save results
authopsy scan ... --output results.json

# Generate report
authopsy report --input results.json --format html --output report.html
```

## What it detects

| Issue | Description | Severity |
|-------|-------------|----------|
| Vertical Privilege Escalation | User accesses admin-only endpoint | CRITICAL |
| Horizontal Privilege Escalation | User accesses another user's data | CRITICAL |
| Missing Authentication | Anonymous user can access protected endpoint | HIGH |
| Data Leakage | User response contains extra sensitive fields | HIGH |
| Query Param Bypass | `?admin=true` exposes more data | HIGH |
| Header Bypass | `X-Debug: true` bypasses auth | CRITICAL |
| Sensitive Field Exposure | Fields like `password`, `ssn` visible | MEDIUM |

## All Options

```
authopsy scan [OPTIONS] --url <URL> --admin <TOKEN> --user <TOKEN>

Options:
  -u, --url <URL>              API base URL
  -s, --spec <FILE>            OpenAPI/Swagger spec file
  -e, --endpoints <LIST>       Manual endpoint list (comma-separated)
      --admin <TOKEN>          Admin auth token
      --user <TOKEN>           User auth token
      --header <NAME>          Auth header name [default: Authorization]
  -c, --concurrency <N>        Concurrent requests [default: 50]
  -t, --timeout <SECS>         Request timeout [default: 10]
  -o, --output <FILE>          Save JSON results
      --skip-paths <PATHS>     Skip these paths
      --public-paths <PATHS>   Mark as intentionally public
  -p, --params <K=V,K=V>       Path parameter values
  -b, --bodies <FILE>          Request bodies JSON file
  -v, --verbose                Show progress details
```

```
authopsy fuzz [OPTIONS] --url <URL> --user <TOKEN>

Options:
  -u, --url <URL>              API base URL
  -s, --spec <FILE>            OpenAPI/Swagger spec file
  -e, --endpoints <LIST>       Manual endpoint list
      --user <TOKEN>           User auth token to test bypasses
      --header <NAME>          Auth header name [default: Authorization]
  -c, --concurrency <N>        Concurrent requests [default: 20]
  -v, --verbose                Show progress details
```

## How it works

1. Parses your OpenAPI spec (or uses manual endpoint list)
2. Sends each request 3 times: as Admin, User, and Anonymous
3. Compares the responses:
   - Status codes (403 vs 200)
   - Response body size
   - JSON structure and keys
   - Sensitive field names
4. Reports issues with fix recommendations

## Contributing

Issues and PRs welcome at https://github.com/burakozcn01/authopsy

## License

MIT
