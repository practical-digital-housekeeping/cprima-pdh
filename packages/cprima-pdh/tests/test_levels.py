"""Finding levels (ERROR, WARN, INFO), the recommended tier, and the exit code that depends on ERROR only."""
import json

import pytest
from pdh_testkit.runner import pdh_runner
from pdh_testkit.stubs import E, StubKP

from cprima_pdh.schema import filter_level, level_of, parse_schemas, validate, worst_level

# --- the default level of every rule kind ------------------------------------------------------

RULE_LEVELS = [
    ("required:UserName", "ERROR"),
    ("schema:unknown", "ERROR"),
    ("recommended:customer_no", "WARN"),
    ("protected:PIN", "WARN"),
    ("unprotected:customer_no", "WARN"),
    ("alias:serial_number", "WARN"),
    ("closed:unknown-field", "WARN"),
    ("expires", "WARN"),
    ("url:https", "WARN"),          # http:// is a valid URI: a WARN at most, never an ERROR
    ("schema:type-conflict", "WARN"),
    ("pattern:PIN", "INFO"),
]


@pytest.mark.parametrize("rule,level", RULE_LEVELS, ids=[r for r, _ in RULE_LEVELS])
def test_default_level_of_each_rule(rule, level):
    assert level_of(rule) == level


# --- requirement tiers: required (MUST) -> ERROR, recommended (SHOULD) -> WARN, optional (MAY) -> nothing ----

SCHEMAS = parse_schemas("""
[facet.login]
required = ["Title", "UserName", "Password", "URL"]
https_only = true

[schema.website]
facets = ["login"]

[schema.shop]
required = ["Title"]
recommended = ["customer_no"]
optional = ["fax"]
closed = true

[field.PIN]
pattern = '[0-9]{4}'
""")

# (case id, entry, expected {(rule, level)})
CASES = [
    ("required-missing-is-an-error", E(schema="website", username=""), {("required:UserName", "ERROR")}),
    ("http-is-a-warning-not-an-error", E(schema="website", url="http://x.example"), {("url:https", "WARN")}),
    ("recommended-missing-is-a-warning", E(schema="shop"), {("recommended:customer_no", "WARN")}),
    ("recommended-present-is-fine", E(schema="shop", custom={"customer_no": "K1"}), set()),
    ("optional-missing-is-no-finding", E(schema="shop", custom={"customer_no": "K1", "fax": "1"}), set()),
    ("recommended-field-is-known-to-closed", E(schema="shop", custom={"customer_no": "K1"}), set()),
    ("unknown-schema-is-an-error", E(schema="nope"), {("schema:unknown", "ERROR")}),
    ("format-hint-is-info", E(custom={"PIN": "12"}, protected=("PIN",)), {("pattern:PIN", "INFO")}),
]


@pytest.mark.parametrize("entry,expected", [c[1:] for c in CASES], ids=[c[0] for c in CASES])
def test_levels_of_findings(entry, expected):
    report = validate(StubKP([entry]), SCHEMAS)
    assert {(f.rule, f.level) for f in report.findings} == expected


def test_filter_and_worst_level():
    report = validate(StubKP([E(schema="website", username="", url="http://x.example", custom={"PIN": "1"},
                                protected=("PIN",))]), SCHEMAS)
    assert worst_level(report) == "ERROR"
    assert {f.level for f in filter_level(report, "WARN").findings} == {"WARN", "ERROR"}
    assert {f.level for f in filter_level(report, "ERROR").findings} == {"ERROR"}
    assert len(filter_level(report, "INFO").findings) == len(report.findings)
    assert worst_level(validate(StubKP([E(schema="website")]), SCHEMAS)) is None


# --- the CLI: --level filters the display, --fail-on decides the exit code -----------------------------------

TOML = """
[facet.login]
required = ["Title", "UserName", "Password", "URL"]
https_only = true

[schema.website]
facets = ["login"]
"""


@pytest.fixture
def run(monkeypatch, tmp_path):
    inner = pdh_runner(monkeypatch, tmp_path, TOML)
    return lambda entries, *args: inner(entries, "check", "validate", *args)


def test_warnings_alone_do_not_fail(run):
    result = run([E(schema="website", url="http://x.example")])
    assert result.exit_code == 0 and "URL is not https" in result.stdout and "WARN" in result.stdout


def test_an_error_fails(run):
    assert run([E(schema="website", username="")]).exit_code == 1


def test_fail_on_warn_makes_warnings_fail(run):
    assert run([E(schema="website", url="http://x.example")], "--fail-on", "WARN").exit_code == 1


def test_level_hides_lower_findings_but_not_from_the_exit_code(run):
    entries = [E(schema="website", url="http://x.example")]
    shown = run(entries, "--level", "ERROR", "--fail-on", "WARN")
    assert "URL is not https" not in shown.stdout  # hidden by the display filter
    assert shown.exit_code == 1                    # but still counted for the exit code


def test_level_is_in_the_json(run):
    data = json.loads(run([E(schema="website", url="http://x.example")], "-f", "json").stdout)
    assert [(f["rule"], f["level"]) for f in data["findings"]] == [("url:https", "WARN")]
    assert "severity" not in data["findings"][0]


def test_summary_lists_errors_first(run):
    entries = [E(title="a", schema="website", username=""), E(title="b", schema="website", url="http://x.example")]
    out = run(entries, "--summary").stdout
    assert out.index("ERROR") < out.index("WARN")
