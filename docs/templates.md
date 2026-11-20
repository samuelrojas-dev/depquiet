# Community templates

The built-in templates and how to contribute one.

depquiet ships with **20 built-in templates** in [nuclei-style](https://github.com/projectdiscovery/nuclei-templates) YAML.

A built-in template matches only when depquiet can read the project source and finds no
import of the package, or of any direct dependency that brings it in. Since 0.43 a match no
longer dismisses the alert: that is exactly the case where another library may load the
package (requests loads `certifi` on every HTTPS call), so the template's note is added to
the review instead. Custom templates without conditions are explicit unconditional
dismissal rules, so add `not-imported` conditions when that is not your intention.

Earlier versions gave each template a technical justification ("mitigated by Express 4.x
defaults", "timing attack") that depquiet never verified, and some were wrong. Since 0.40.5
the reason states only what was checked.

| Template | Package | CVE |
|---|---|---|
| lodash prototype pollution | lodash | CVE-2020-8203, CVE-2019-10744, CVE-2018-16487 |
| semver ReDoS | semver | CVE-2022-25883 |
| express open redirect | express | CVE-2024-29041 |
| axios SSRF | axios | CVE-2023-45857 |
| json5 prototype pollution | json5 | CVE-2022-46175 |
| webpack-dev-middleware path traversal | webpack-dev-middleware | CVE-2024-29180 |
| ip SSRF | ip | CVE-2023-42282 |
| requests proxy-auth leak | requests | CVE-2023-32681 |
| cryptography null dereference | cryptography | CVE-2024-0727 |
| minimist prototype pollution | minimist | CVE-2021-44906, CVE-2020-7598 |
| nth-check ReDoS | nth-check | CVE-2021-3803 |
| postcss ReDoS | postcss | CVE-2023-44270, CVE-2021-23382, CVE-2021-23368 |
| glob-parent ReDoS | glob-parent | CVE-2020-28469 |
| node-forge signature verification | node-forge | CVE-2022-24771, CVE-2022-24772, CVE-2022-24773 |
| shell-quote injection | shell-quote | CVE-2021-42740 |
| qs prototype pollution | qs | CVE-2022-24999 |
| word-wrap ReDoS | word-wrap | CVE-2023-26115 |
| tough-cookie prototype pollution | tough-cookie | CVE-2023-26136 |
| js-yaml code execution | js-yaml | CVE-2013-4660 |
| certifi root CA removal | certifi | CVE-2023-37920, CVE-2024-39689 |

```yaml
id: qs-prototype-pollution
reason: "No import of qs, or of a direct dependency that brings it in, was found in the project source. ..."
author: "@depquiet"
cves:
  - CVE-2022-24999
package: qs
not-imported: ["qs"]
```

## Contributing a template

1. Create a YAML file in `templates/dismiss/`
2. Add the CVE, affected package, and dismiss conditions
3. Open a PR — the community reviews and merges

A template's reason must state only what depquiet checks. Technical arguments about how a
library is used belong in the PR discussion, with a source, not in the dismissal text.
