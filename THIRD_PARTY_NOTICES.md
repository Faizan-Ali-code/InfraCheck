# Third-party notices

InfraChecker includes code derived from the following third-party project. Its licence applies to those parts only.

## google/csp-evaluator 1.1.8

- **Source:** https://github.com/google/csp-evaluator
- **Copyright:** Copyright 2016 Google Inc.
- **Licence:** Apache License 2.0, full text in [`licenses/csp-evaluator-LICENSE.txt`](licenses/csp-evaluator-LICENSE.txt)

| InfraChecker file | Derived from | Changes |
|---|---|---|
| `infrachecker/scanners/headers/csp/policy.py` | `csp.ts`, `parser.ts`, `finding.ts` | Translated from TypeScript to Python |
| `infrachecker/scanners/headers/csp/checks.py` (upstream checks and `strict_dynamic`) | `checks/security_checks.ts`, `checks/parser_checks.ts`, `checks/strictcsp_checks.ts` | Translated from TypeScript to Python |
| `infrachecker/scanners/headers/csp/urls.py` | `utils.ts` | Translated to Python; own URL parser instead of the browser URL API |
| `infrachecker/scanners/headers/csp/bypass_lists.py` | `allowlist_bypasses/angular.ts`, `flash.ts`, `jsonp.ts` | Data copied unchanged; converted to Python tuples |

Not derived from csp-evaluator: `csp/__init__.py` (verdict and ownership wrapper) and the `frame_ancestors`,
`report_to` and `reporting_endpoints` checks in `checks.py`.
