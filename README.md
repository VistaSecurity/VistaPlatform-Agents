# Vista Platform agents

> **Private staging repository.** Nothing here is released, supported or
> public yet. This repository is being prepared to become the public home of
> the Vista Platform passive sensor and device interrogation agent. The work
> is tracked in the private epic VistaSecurity/VistaPlatform#2765; this README
> is replaced before the repository is made public.

## What will live here

- `cmd/sensor`, `cmd/device-agent`: the two customer-deployed executables,
  built and released separately, used by Vista Platform in managed mode and
  later on their own.
- `shared/`: the code both agents use, maintained here and nowhere else.
- Signed nightly and tagged builds, installers and compatibility metadata,
  published as this repository's releases.

The source arrives with the extraction work order (WO-04); signed builds with
WO-08. Until the extraction lands, the Go jobs of the pull-request gate fail
because there is no `go.mod` to build: that is intended, so the gate cannot go
green on an empty tree.

## Pull-request checks

Every pull request runs `.github/workflows/pr.yml` on GitHub-hosted runners
with a read-only token and no secrets: build, vet and test with CGO on
linux/amd64, CGO-free cross-builds for Linux, macOS and Windows, gofmt,
golangci-lint, govulncheck, and `scripts/check-workflows.mjs`, which fails if
any workflow asks for a runner GitHub does not host, uses an action that is not
pinned to a commit SHA, or asks for write permissions on a pull request. The
same commands run locally with `GOWORK=off`, Go 1.26.10 and, for the sensor,
`libpcap-dev`.

## License

> **DRAFT FOR COUNSEL REVIEW.** Not yet approved. There is no `LICENSE`,
> `NOTICE` or `CONTRIBUTING.md` in this repository yet; they land with the
> approved texts (work order WO-01).

The Vista Platform agents are **open source under the
Apache License 2.0 (`LICENSE`)**. You may use, modify and redistribute them,
commercially or not, under that licence's terms, including its patent grant and
its notice requirements. See `NOTICE` for the third-party components
and their licences.

The licensor is **Lakeshore Labs LLC**, which does business as **Vista
Security**.

Two things the Apache licence here does not cover:

- **Vista Platform itself.** The platform that manages these agents (its
  services, user interfaces, Helm chart and container images) is proprietary
  software under its own licence, published separately. Using these agents does
  not require it, and the Apache licence here grants no rights in it.
- **Third-party software you install alongside.** On Windows the sensor needs
  Npcap, which you install from its publisher under its own licence; its free
  licence covers up to five systems. On Linux and macOS the sensor uses the
  operating system's libpcap.

"Vista", "Vista Security" and "Vista Platform" are trademarks of Lakeshore Labs
LLC; the licence does not grant the right to use them beyond describing where
the software comes from.

Contributions: see `CONTRIBUTING.md`. Security reports: see
`SECURITY.md`.
