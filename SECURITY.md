# Security policy

`single-auth` handles authentication, credentials, sessions, cookies, OAuth,
and storage. Please report suspected vulnerabilities privately and avoid
posting exploit details in a public issue.

## Supported versions

The project is still a work-in-progress port and has not declared a stable
release line. Until a supported release matrix is published, security fixes are
made on the default branch only. The repository's current capability percentage
must not be interpreted as a production-readiness or security certification.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting flow from the repository's
**Security** tab and choose **Report a vulnerability**. Include:

- the affected package, endpoint, transport, plugin, or storage adapter;
- the commit or version tested;
- prerequisites and a minimal reproduction;
- expected and observed behavior;
- security impact and whether credentials or user data may be exposed;
- any suggested mitigation, if known.

If private vulnerability reporting is not available, contact the repository
maintainers through the private contact method published on their GitHub
profiles. Do not open a public issue containing secrets, personal data, access
tokens, session material, or a working exploit.

Please allow maintainers time to reproduce, assess, and prepare a coordinated
fix before public disclosure. You may request acknowledgement and discuss a
disclosure timeline in the private report.

## What to expect

Maintainers will aim to acknowledge a report, determine whether it affects the
current Go implementation, and communicate next steps through the private
report. Response times are best-effort while the project is pre-stable; this
document does not promise a fixed service-level agreement.

When a report is accepted, the fix should include a regression test that does
not disclose reusable secrets, an assessment of affected transports and
storage backends, and release notes or an advisory when a release process is in
place.

## Out of scope

The preserved `better-auth-main/` tree is a read-only development reference.
Vulnerabilities that exist only in that upstream TypeScript snapshot should be
reported to the Better Auth maintainers. JavaScript clients, JavaScript
framework integrations, CLI, billing integrations, and JavaScript-runtime
compatibility are not part of the current `single-auth` milestone.

Reports about a documented missing feature, without a security boundary being
bypassed in implemented Go code, should use the feature request template.
