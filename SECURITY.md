# Security policy

Fiery Dragon is a security monitoring tool, so a flaw in it can hide an attack.

## Reporting a vulnerability

**Don't open a public issue.** Use GitHub's private vulnerability reporting instead: on the repository's **Security** tab, choose **Report a vulnerability**.

Please include:
- what an attacker can do, for example evade capture, corrupt the log, or crash the daemon;
- how to reproduce it;
- the kernel version and the repo commit.

## Scope

- **In scope:** ways an unprivileged process can avoid being recorded, cause records to be wrong, or cause loss that isn't counted. Also, any parsing flaw in the daemon or the decoders.
- **Out of scope:** the limits declared in the threat model (`docs/threat-model.md`, once it exists). The main one is an attacker who already has root and can load kernel modules.

## Status

This project is pre-release. There are no supported versions yet.
