# Security policy

## Reporting a vulnerability

Please report security problems privately, not in public issues or pull requests.

- Use GitHub's private reporting: the repository's **Security** tab, then **Report a vulnerability** (https://github.com/b070nd/cvewatch/security/advisories/new).

Include what you found, how to reproduce it, the version (`cvewatch version`) and what you think the impact is. Do not include real webhook URLs, tokens or internal project names.

We aim to confirm receipt within a few working days, tell you whether we consider it a vulnerability, and agree a disclosure date with you. Our default is to publish a fix and an advisory within 90 days of the report, sooner if the fix is simple. We credit reporters who want credit.

This is a volunteer project. These are goals, not guarantees.

## Supported versions

Only the latest release receives security fixes.

## Scope

In scope: the `cvewatch` binary and container image, its configuration handling, and the MCP server.

Out of scope: weaknesses in third-party feeds and services, a compromised host or user account running the tool, and anything that needs the attacker to already control the configuration files. See the threat model in [docs/security.md](docs/security.md) for what the tool does and does not defend against.

## Good-faith research

If you make a good-faith effort to follow this policy, avoid harming other users, and give us reasonable time to fix an issue before disclosure, we will not pursue or support action against you for your research.

## For operators

[docs/security.md](docs/security.md) lists the protections built in and how to deploy the tool safely.
