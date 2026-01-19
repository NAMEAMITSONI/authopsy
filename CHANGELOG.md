# Changelog

## [1.0.0] - 2026-01-19

Initial release.

### Features

- **Scan command**: Compare API responses across Admin, User, and Anonymous roles
- **Fuzz command**: Test query parameters and headers for authorization bypasses
- **OpenAPI support**: Parse OpenAPI 3.x and Swagger 2.x specs
- **Manual endpoints**: Scan without spec file using `--endpoints`
- **Async scanning**: Concurrent requests with configurable limit
- **Multiple detection layers**:
  - Status code analysis (403 vs 200)
  - Response size comparison
  - JSON structure diffing
  - Sensitive field detection
- **Query param fuzzing**: Tests `?admin=true`, `?debug=true`, `?show_all=true`, etc.
- **Header fuzzing**: Tests `X-Debug`, `X-Admin`, `X-Forwarded-For`, etc.
- **Export formats**: JSON and HTML reports
- **Path filtering**: `--skip-paths` and `--public-paths` options
- **Custom auth headers**: Support for API keys, custom header names
- **Path parameter support**: Override default values with `--params`
- **Request body support**: Provide custom bodies via JSON file

### Severity levels

- **CRITICAL**: User can access admin-only resources
- **HIGH**: Missing authentication or significant data leak
- **MEDIUM**: Sensitive field names exposed
- **LOW**: Timing differences or minor info disclosure
- **OK**: Proper access control enforced
