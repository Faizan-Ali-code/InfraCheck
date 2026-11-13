"""The checks, in the order they run for each target."""

from infracheck.checks import cookies, cors, csp, errors, exposure, headers, methods, spoofing, transport, versions

# errors runs before versions, so versions found in error pages are included.
CHECKS = {
    "transport": transport, "headers": headers, "csp": csp, "cookies": cookies, "cors": cors, "errors": errors,
    "versions": versions, "methods": methods, "spoofing": spoofing, "exposure": exposure,
}


def all_rules():
    return [rule for module in CHECKS.values() for rule in module.RULES.values()]
