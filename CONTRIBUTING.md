# Contributing to cvewatch

Thanks for your interest in cvewatch. This document explains how to build and test the project, how the code is laid out, and what we expect from contributions.

## Build and test

The Go module lives in the `app/` directory. Run all commands from there:

```sh
cd app
go vet ./...
go test -race ./...
```

Format code with `gofmt` before you commit:

```sh
gofmt -l -w .
```

Tests must not reach the network. Use fixtures stored with the tests instead.

## Repository layout

- `app/src/<package>` contains one package per concern. Keep each package focused on one job.
- `app/src/cmd` contains the command-line entry points.
- `app/src/feeds` contains the feed parsers, one file per feed type.
- `app/config` contains the default configuration, project definitions, and the tech list.
- `app/sources` contains the default feed source definitions.
- `docs/` contains the project documentation. Update it when behavior changes.

## Conventions

- Keep pull requests small and focused. One change per pull request is easier to review than several.
- Add tests for every behavior change. Use fixtures for input data. Do not call live feeds or APIs in tests.
- Write comments in plain, concise English. Explain why the code does something when that is not obvious. Do not restate what the code says.
- Do not add a new dependency without discussing it first. Open an issue or a discussion and explain why the standard library or existing code is not enough.
- Feed text is untrusted. Never log it unescaped. Never render it in HTML, Markdown, or terminal output without escaping it first.
- Never commit secrets, webhook URLs, tokens, or internal project names. Use placeholders in fixtures and examples.

## Adding a feed type

1. Add one parser file in `app/src/feeds`, for example `app/src/feeds/myfeed.go`.
2. Implement the parser so it returns the same normalized records as the existing parsers.
3. Register the parser in the `parsers` map in `app/src/feeds/feeds.go`, using the type name used in source definitions.
4. Add a fixture file and tests in `app/src/feeds` that run the parser against the fixture. Do not fetch the live feed in tests.
5. Add the source type to the feed documentation in `docs/`.

## Reporting bugs and security issues

- Bugs and feature requests: open a GitHub issue using the matching template. Include the cvewatch version from `cvewatch version`, your operating system, the command you ran, what you expected, and what happened. Remove secrets from logs before you paste them.
- Security issues: do not open a public issue or pull request. Report them through the private process described in `SECURITY.md`, or use the repository's private security advisory page.

## Licensing

By contributing, you agree that your contributions are licensed under the terms in the LICENSE file.
