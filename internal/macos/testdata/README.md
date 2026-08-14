# Sanitized macOS fixtures

Every file in this directory is handwritten, synthetic test data. The fixtures
model third-party application layouts and bounded command results without
containing copied unified logs, copied crash reports, real user paths, wireless
network names, IP addresses, or machine identifiers.

Fixture families:

- `bundles/wrapped`: a wrapped iOS-style application layout.
- `bundles/helper-heavy`: a main bundle with login-item and updater helpers.
- `dependencies/unusual-rpaths`: `@rpath`, `@loader_path`, and
  `@executable_path` resolution.
- `permissions`: correlated and unrelated synthetic privacy decisions.
- `crashes`: minimal structured `.ips` and `.crash` termination fields.
- `network`: managed and restricted command-result sets with no network
  identifiers.

`fixtures_test.go` consumes every family through exported `macos` package
entry points and rejects fixture content that violates these privacy rules.
