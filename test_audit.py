"""Tests for the audit (audit.py) and drift (drift.py) engines.

Standard-library only, like the modules under test. Runs either way::

    python test_audit.py     # built-in runner, prints PASS/FAIL per test
    pytest test_audit.py     # optional, if pytest happens to be installed

The rule ids used here are read from COMPLIANCE_RULES itself (see the ID_*
constants below), so a renamed rule fails loudly at import time rather than
silently skipping a check.
"""
import json

from audit import audit_config, COMPLIANCE_RULES, WEAK_SAMPLE, HARDENED_SAMPLE
from drift import compute_drift


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_RULE_IDS = {rule['id'] for rule in COMPLIANCE_RULES}


def _rule_id(rule_id):
    """Return *rule_id*, asserting it really exists in COMPLIANCE_RULES."""
    assert rule_id in _RULE_IDS, f'unknown rule id {rule_id!r}; have {sorted(_RULE_IDS)}'
    return rule_id


ID_SVC_PASSWORD_ENCRYPTION = _rule_id('svc_password_encryption')
ID_ENABLE_SECRET           = _rule_id('enable_secret')
ID_NO_ENABLE_PASSWORD      = _rule_id('no_enable_password')
ID_VTY_SSH                 = _rule_id('vty_ssh')
ID_NO_TELNET               = _rule_id('no_telnet')
ID_NO_TRANSPORT_ALL        = _rule_id('no_transport_all')
ID_HTTP_SERVER_DISABLED    = _rule_id('http_server_disabled')
ID_SNMP_NO_DEFAULT_COMM    = _rule_id('snmp_no_default_comm')
ID_LOGGING_CONFIGURED      = _rule_id('logging_configured')
ID_NTP_CONFIGURED          = _rule_id('ntp_configured')


def verdict(config_text, rule_id):
    """Return the single result dict for *rule_id* from auditing *config_text*."""
    results, _ = audit_config(config_text)
    for r in results:
        if r['id'] == rule_id:
            return r
    raise KeyError(rule_id)


def assert_pass(config_text, rule_id):
    r = verdict(config_text, rule_id)
    assert r['status'] == 'pass', (
        f'expected {rule_id} to pass, got {r["status"]} (detail: {r["detail"]!r})'
    )


def assert_fail(config_text, rule_id):
    r = verdict(config_text, rule_id)
    assert r['status'] == 'fail', (
        f'expected {rule_id} to fail, got {r["status"]} (detail: {r["detail"]!r})'
    )


# A config that contains none of the audited constructs — the "absent" case
# for every must_contain rule and the passing case for every must_not_contain
# rule.
BARE = "hostname bare-router\n!\nend\n"


# ---------------------------------------------------------------------------
# Per-rule cases
# ---------------------------------------------------------------------------

def test_service_password_encryption():
    assert_pass("service password-encryption", ID_SVC_PASSWORD_ENCRYPTION)
    assert_fail(BARE, ID_SVC_PASSWORD_ENCRYPTION)


def test_enable_secret():
    assert_pass("enable secret 9 $9$abcdefghij", ID_ENABLE_SECRET)
    assert_fail(BARE, ID_ENABLE_SECRET)


def test_no_enable_password():
    assert_fail("enable password 7 0822455D0A16", ID_NO_ENABLE_PASSWORD)
    assert_pass(BARE, ID_NO_ENABLE_PASSWORD)
    # `enable secret` must not be mistaken for `enable password`.
    assert_pass("enable secret 9 $9$abcdefghij", ID_NO_ENABLE_PASSWORD)


def test_vty_ssh_required():
    assert_pass("line vty 0 4\n transport input ssh", ID_VTY_SSH)
    assert_fail(BARE, ID_VTY_SSH)


def test_telnet_forbidden():
    assert_fail("line vty 0 4\n transport input telnet", ID_NO_TELNET)
    assert_pass(BARE, ID_NO_TELNET)
    assert_pass("line vty 0 4\n transport input ssh", ID_NO_TELNET)


def test_transport_input_all_forbidden():
    assert_fail("line vty 0 4\n transport input all", ID_NO_TRANSPORT_ALL)
    assert_pass(BARE, ID_NO_TRANSPORT_ALL)
    assert_pass("line vty 0 4\n transport input ssh", ID_NO_TRANSPORT_ALL)


def test_http_server_disabled():
    assert_fail("ip http server", ID_HTTP_SERVER_DISABLED)
    assert_pass(BARE, ID_HTTP_SERVER_DISABLED)


def test_http_server_negation_anchor():
    """`no ip http server` must PASS — the ^ anchor is the whole point."""
    assert_pass("no ip http server", ID_HTTP_SERVER_DISABLED)
    assert_pass("no ip http server\nno ip http secure-server\n", ID_HTTP_SERVER_DISABLED)


def test_snmp_default_communities():
    assert_fail("snmp-server community public RO", ID_SNMP_NO_DEFAULT_COMM)
    # The rule carries ignorecase, so the uppercase form must fail too.
    assert_fail("snmp-server community PUBLIC RO", ID_SNMP_NO_DEFAULT_COMM)
    assert_fail("snmp-server community private RW", ID_SNMP_NO_DEFAULT_COMM)
    assert_pass("snmp-server community Zx91-mgmt RO", ID_SNMP_NO_DEFAULT_COMM)
    assert_pass(BARE, ID_SNMP_NO_DEFAULT_COMM)


def test_remote_syslog():
    assert_pass("logging host 10.0.0.100", ID_LOGGING_CONFIGURED)
    # The older bare form `logging <IP>` is also a real remote destination.
    assert_pass("logging 10.0.0.100", ID_LOGGING_CONFIGURED)
    # Local-only logging must NOT satisfy the rule.
    local_only = (
        "logging buffered 64000\n"
        "logging console critical\n"
        "logging trap informational\n"
    )
    assert_fail(local_only, ID_LOGGING_CONFIGURED)
    assert_fail(BARE, ID_LOGGING_CONFIGURED)


def test_ntp_configured():
    assert_pass("ntp server 216.239.35.0", ID_NTP_CONFIGURED)
    assert_fail(BARE, ID_NTP_CONFIGURED)


# ---------------------------------------------------------------------------
# Split-range VTY cases
# ---------------------------------------------------------------------------

SPLIT_VTY = (
    "line vty 0 4\n"
    " transport input ssh\n"
    "line vty 5 15\n"
    " transport input telnet\n"
)

SPLIT_VTY_ALL = (
    "line vty 0 4\n"
    " transport input ssh\n"
    "line vty 5 15\n"
    " transport input all\n"
)


def test_split_range_vty_telnet_detected():
    """SSH present on 0-4 but telnet on 5-15: SSH rule passes, telnet rule fails.

    Neither rule alone describes the device correctly — the insecure state is
    caught only by the pairing of the must_contain and must_not_contain rules.
    """
    assert_pass(SPLIT_VTY, ID_VTY_SSH)
    assert_fail(SPLIT_VTY, ID_NO_TELNET)


def test_split_range_vty_transport_all_detected():
    assert_pass(SPLIT_VTY_ALL, ID_VTY_SSH)
    assert_fail(SPLIT_VTY_ALL, ID_NO_TRANSPORT_ALL)


# ---------------------------------------------------------------------------
# Self-test regression guard
# ---------------------------------------------------------------------------

def test_weak_sample_scores_20():
    _, summary = audit_config(WEAK_SAMPLE)
    assert summary['score'] == 20, f"WEAK_SAMPLE score {summary['score']}, expected 20"


def test_hardened_sample_scores_100():
    _, summary = audit_config(HARDENED_SAMPLE)
    assert summary['score'] == 100, f"HARDENED_SAMPLE score {summary['score']}, expected 100"


def test_summary_counts_consistent():
    results, summary = audit_config(WEAK_SAMPLE)
    assert summary['total'] == len(COMPLIANCE_RULES) == len(results)
    assert summary['passed'] + summary['failed'] == summary['total']


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------

def _serialise(obj):
    return json.dumps(obj, sort_keys=True)


def test_audit_is_deterministic():
    runs = [_serialise(audit_config(WEAK_SAMPLE)) for _ in range(20)]
    assert len(set(runs)) == 1, 'audit_config(WEAK_SAMPLE) is not deterministic'


def test_drift_is_deterministic():
    runs = [_serialise(compute_drift(DRIFT_OLD, DRIFT_NEW)) for _ in range(20)]
    assert len(set(runs)) == 1, 'compute_drift is not deterministic'


# ---------------------------------------------------------------------------
# Drift basics
# ---------------------------------------------------------------------------

DRIFT_OLD = (
    "hostname edge-router\n"
    "ntp server 192.0.2.10\n"
    "logging host 192.0.2.50\n"
    "end\n"
)

DRIFT_NEW = (
    "hostname edge-router\n"
    "ntp server 198.51.100.10\n"
    "logging host 198.51.100.50\n"
    "end\n"
)


def test_drift_identical():
    result = compute_drift(DRIFT_OLD, DRIFT_OLD)
    assert result['identical'] is True
    assert result['added'] == 0
    assert result['removed'] == 0
    assert result['lines'] == []


def test_drift_two_line_change():
    result = compute_drift(DRIFT_OLD, DRIFT_NEW)
    assert result['identical'] is False
    assert result['added'] == 2, f"added={result['added']}, expected 2"
    assert result['removed'] == 2, f"removed={result['removed']}, expected 2"
    added = [ln['text'] for ln in result['lines'] if ln['kind'] == 'add']
    removed = [ln['text'] for ln in result['lines'] if ln['kind'] == 'remove']
    assert added == ['ntp server 198.51.100.10', 'logging host 198.51.100.50']
    assert removed == ['ntp server 192.0.2.10', 'logging host 192.0.2.50']
    # No ---/+++ file headers leak into the line list.
    assert all(not ln['text'].startswith(('---', '+++')) for ln in result['lines'])


def test_drift_direction_old_to_new():
    """old -> new: a line only in *new* is an addition, not a removal."""
    result = compute_drift("a\nb\n", "a\nb\nc\n")
    assert result['added'] == 1
    assert result['removed'] == 0


# ---------------------------------------------------------------------------
# Built-in runner (no third-party dependency)
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    import traceback

    tests = [(name, obj) for name, obj in sorted(globals().items())
             if name.startswith('test_') and callable(obj)]

    failures = 0
    for name, fn in tests:
        try:
            fn()
        except Exception:
            failures += 1
            print(f'FAIL {name}')
            print('     ' + traceback.format_exc().replace('\n', '\n     ').rstrip())
        else:
            print(f'PASS {name}')

    print()
    print(f'{len(tests) - failures}/{len(tests)} passed'
          + (f', {failures} FAILED' if failures else ''))
    raise SystemExit(1 if failures else 0)
