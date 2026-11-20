# Contributing to depquiet

Thanks for your interest in contributing! depquiet is an open source tool that helps developers cut through vulnerability alert noise, and contributions from the community are what make it great.

## Quick Start

```bash
git clone https://github.com/samuelrojas-dev/depquiet.git
cd depquiet
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pip install pre-commit && pre-commit install   # runs ruff + mypy on every commit
python -m pytest tests/ -v
```

## Ways to Contribute

### Community Templates (easiest way to start)

The fastest way to contribute is by adding **dismiss templates** — curated rules that help depquiet filter known false positives.

Templates live in `templates/dismiss/` and look like this:

```yaml
id: prototype-pollution-lodash
title: Prototype pollution in lodash (not exploitable in most apps)
cves:
  - CVE-2020-8203
  - CVE-2019-10744
packages:
  - lodash
reason: >
  Prototype pollution in lodash requires attacker-controlled input
  to _.merge, _.defaultsDeep, or _.zipObjectDeep. Most applications
  do not pass untrusted input to these functions.
references:
  - https://github.com/advisories/GHSA-jf85-cpcp-j695
```

**Rules for templates:**

1. Every CVE must be real and verifiable
2. The `reason` must explain *why* it's safe to dismiss — not just that it's low severity
3. One template per logical group (e.g., all lodash prototype pollution CVEs together)
4. File name matches the `id` field: `{id}.yaml`

### Code Contributions

1. **Fork and branch**: create a feature branch from `main`
2. **Write tests first**: every new feature or bugfix needs a test in `tests/`
3. **Follow the style**: we use `ruff` for linting and `mypy` for type checking
4. **Keep dependencies at zero**: depquiet has zero runtime dependencies by design. If you need a library, it goes in `[project.optional-dependencies]`
5. **Run the checks**:

```bash
ruff check src/ tests/
ruff format --check src/ tests/
mypy src/depquiet/ --ignore-missing-imports
python -m pytest tests/ -v --cov=depquiet
```

### Bug Reports

Open an issue with:

- Your Python version and OS
- The command you ran
- The full error output
- If possible, the audit JSON that triggered the bug (sanitize any private package names)

### Feature Requests

Open an issue describing:

- The problem you're trying to solve
- How you imagine the solution working
- Any alternatives you've considered

## Architecture Overview

```
src/depquiet/
├── cli.py          # Entry point, argument parsing
├── config.py       # .depquiet.yaml config file support
├── engine.py       # Core orchestrator — runs parsers + filters
├── models.py       # Dataclasses: Vulnerability, FilterResult
├── output.py       # Terminal output with colors
├── sarif.py        # SARIF v2.1.0 export
├── parsers/
│   ├── npm.py         # npm audit JSON parser
│   ├── pip.py         # pip-audit JSON parser
│   ├── trivy.py       # Trivy JSON parser (lang-pkgs only)
│   ├── dependabot.py  # GitHub Dependabot alerts parser
│   └── grype.py       # Anchore Grype JSON parser
└── filters/
    ├── devdep.py       # devDependency filter
    ├── reachability.py # Import reachability analysis
    ├── epss.py         # EPSS score filter
    └── templates.py    # Community template matcher
```

**Key design principles:**

- Parsers convert tool-specific JSON into `Vulnerability` objects
- Filters take a list of vulnerabilities and return `FilterResult` objects with a reason
- The engine runs parsers then filters in order
- Output formatters (terminal, JSON, SARIF) consume `FilterResult` lists

## Pull Request Process

1. Update tests to cover your changes
2. Ensure all checks pass (`ruff`, `mypy`, `pytest`)
3. Update the README (short, user-facing) or the matching page in `docs/` if you're adding user-facing features
4. Fill out the PR template
5. A maintainer will review within a few days

## Code of Conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md). By participating, you agree to uphold a welcoming, inclusive environment.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
