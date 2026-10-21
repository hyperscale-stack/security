# Security policy

`github.com/hyperscale-stack/security` is an authentication and
authorization library: a flaw in it can expose every application built on
it. Thank you for reporting one privately.

## Supported versions

No module has been released yet. Security fixes land on `master`, and the
first release of every module will be `v1.0.0`.

Once released, security fixes ship as patch releases of the latest minor
version of each affected module (modules are versioned and tagged
independently, see [docs/releasing.md](docs/releasing.md)). `examples/`,
`internal/`, `e2e/` and `tools/` are never released.

## Reporting a vulnerability

Report it privately through GitHub's private vulnerability reporting:
[open a draft security advisory](https://github.com/hyperscale-stack/security/security/advisories/new)
("Report a vulnerability" in the repository's Security tab). Only you and
the repository's maintainers can see it.

Do not open a public issue, pull request or discussion about it. If you
cannot use GitHub's private reporting, open a public issue that asks for a
private contact and contains no detail of the vulnerability.

Please include:

- the affected module(s) and the version or commit;
- the configuration and options involved;
- the steps or a proof of concept that reproduce it;
- the impact you see, and the RFC or specification section concerned, if
  any.

Test only against code and deployments you own or are authorized to test.

## Scope

In scope:

- every released module of this repository: its code, its defaults and the
  security contracts documented in its godoc and in
  [docs/security-considerations.md](docs/security-considerations.md);
- deviations from the RFCs and specifications the modules implement;
- the build, CI and release supply chain of this repository.

Out of scope:

- the gaps [LIMITATIONS.md](LIMITATIONS.md) documents, unless the
  documentation is wrong about them;
- vulnerabilities of third-party dependencies or of the Go toolchain:
  report them upstream, and tell us when the way a module uses them makes
  one exploitable;
- the example programs (`examples/`) as deployable servers: they are
  demonstrations. A flaw that a user would copy from them into an
  application is in scope;
- the security of deployments and infrastructure built with the library.

## Disclosure

The project has a single maintainer; these are targets, not guarantees:

- we aim to acknowledge a report within 5 business days;
- we aim to give a first assessment (accepted or not, severity, affected
  modules) within 10 business days;
- we aim for coordinated disclosure within 90 days of the report: a fix
  released in the affected modules and a GitHub Security Advisory
  published, with a CVE requested through GitHub. Disclosure happens
  earlier when the fix ships earlier, and later only by agreement with the
  reporter.

Reporters are credited in the advisory unless they prefer not to be.
