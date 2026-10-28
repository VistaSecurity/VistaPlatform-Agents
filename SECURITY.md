<!--
DRAFT FOR COUNSEL REVIEW. Installed from the draft prepared under work order WO-01 so
that the staging repository starts with its intake policy; the text is unchanged except
for the platform intake URL, which follows the repository names proposed in
D02. Placeholders in [BRACKETS] are owner decisions. Remove this comment, and
the banner below, when counsel has approved the text and before the
repository is made public.
-->

> **DRAFT FOR COUNSEL REVIEW.** Not yet approved; do not rely on it.

# Security policy

The Vista Platform agents run inside the networks of the organizations that
deploy them. The sensor sees their traffic; the device interrogation agent
holds credentials for their network devices and databases. We treat reports
about them accordingly.

## Reporting a vulnerability

**Do not open a public issue or pull request.**

Report privately through either channel:

- **GitHub private vulnerability reporting** on this repository (Security tab,
  "Report a vulnerability"). Preferred: the report, the fix and any CVE stay in
  one place.
- **E-mail**: [SECURITY CONTACT ADDRESS]. If you want to encrypt the report,
  ask for a key in a first message with no details in it.

**Is it the agents or the platform?** This repository covers the sensor, the
device interrogation agent, their installers, their release binaries and
signatures, and the agents' side of the managed-mode protocol. A vulnerability
in Vista Platform itself (its services, user interfaces, Helm chart or
container images) goes to the platform's security intake at
https://github.com/VistaSecurity/VistaPlatform-Distribution/security/advisories/new. If you are not sure which, send
it to either; we will move it, and we will tell you we did.

## What to include

- The agent (sensor or device interrogation agent), its version or nightly
  date, and the platform and architecture.
- Whether it ran managed by a Vista Platform installation or standalone.
- Reproduction steps, ideally the smallest case that shows the problem.
- What an attacker gains, and what position they need to start from (on the
  same network segment, controlling a device the agent interrogates, with
  local access to the host, and so on).

## What to expect

| | |
|---|---|
| Acknowledgement | within 3 business days |
| Initial assessment | within 10 business days |
| Fix or mitigation plan | communicated with the assessment |

We will tell you plainly if we think a report is not a vulnerability, and why.
We ask for 90 days before public disclosure, or until a fixed release ships if
that is sooner, and we will say so if a fix needs longer. Reporters are
credited in the advisory and release notes unless they ask not to be. There is
no paid bounty.

## Scope

**Findings we especially want:**

- A path by which an agent sends key material, credentials or other secrets
  off the host. The agents are built to collect posture, never key material:
  vendor responses are projected onto allowlisted fields and redacted before
  they leave the agent. A bypass is our highest-severity class.
- Automatic active probing of an address the operator did not declare as their
  own.
- Enrolment, credential-storage or managed-mode authentication weaknesses.
- Tampering with release binaries, installers, signatures or the compatibility
  metadata the platform uses to choose an agent version.
- Parser bugs a malicious device or packet can trigger (crashes, memory
  exhaustion, code execution).

**Out of scope:**

- Attacks that require administrative control of the host the agent runs on.
- Vulnerabilities in third-party components with no demonstrated impact on
  the agents (report those upstream; tell us if the agents are affected).
- Npcap or libpcap themselves; report those to their maintainers.
- Automated scanner output with no demonstrated impact.

## Supported versions

Security fixes land in the latest tagged release. Nightly builds are previews:
they receive fixes by being rebuilt, never by backport, and are not supported
for production use. [OWNER DECISION: whether the release paired with the
current platform release also receives backported fixes.]
