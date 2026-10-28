# Contributing

Thanks for looking. This repository holds the Vista Platform agents: the
passive network sensor and the device interrogation agent, licensed under the
Apache License 2.0 (see `LICENSE`). You can read, build, run, fork and modify
them under that licence.

## We do not accept code contributions

**Please do not open pull requests with code. They will be closed without
review.** That is not a judgement on your patch.

The reason, plainly: Lakeshore Labs LLC, which does business as Vista
Security, writes all of the code in this repository and also builds a
proprietary product. To keep the freedom to reuse its own code in that product
it needs to own every line here outright. Code from outside would arrive under
the Apache licence, which lets us use it but not relicense it, so it could
never move into anything we do not publish, and we would have to track it file
by file forever. We have chosen not to take that on. Your fork is yours to
change however the licence allows.

## What is welcome

- **Bug reports and feature requests** as GitHub issues. Detail helps: the
  agent and version (or nightly date), the operating system, how it was run
  (managed by a Vista Platform installation, or standalone), what you expected
  and what happened. Remove addresses, hostnames and anything secret from logs
  before you paste them.
- **Documentation corrections**, as issues: tell us what is wrong and what it
  should say.
- **Security reports**, privately: see `SECURITY.md`. Never in a public issue.

Describing a fix in an issue, in words, is welcome; we will write the code.
Please do not paste a patch into an issue, for the same reason we do not take
pull requests.

## If this changes

If we ever open the repository to code contributions, this file will say so
and will explain the contributor licence agreement we would ask for.
