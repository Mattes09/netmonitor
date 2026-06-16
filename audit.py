"""Rule-based configuration compliance audit engine.

Standalone module — depends only on the Python standard library so it can
be imported by the Flask app or run directly for an offline self-test:

    python audit.py
"""
import re

# ---------------------------------------------------------------------------
# Rule definitions
# ---------------------------------------------------------------------------
# check semantics:
#   must_contain     -> pass if the pattern matches anywhere in the config
#   must_not_contain -> pass if the pattern matches nowhere in the config
#
# Patterns are matched with re.MULTILINE so ^ anchors to the start of each
# line — e.g. `^ip http server` must NOT match the line `no ip http server`.

COMPLIANCE_RULES = [
    {
        'id': 'svc_password_encryption',
        'title': 'Service password encryption enabled',
        'category': 'Password security',
        'severity': 'high',
        'check': 'must_contain',
        'pattern': r'^service password-encryption\b',
        'remediation': 'Enable `service password-encryption`.',
    },
    {
        'id': 'enable_secret',
        'title': 'Enable secret configured',
        'category': 'Password security',
        'severity': 'high',
        'check': 'must_contain',
        'pattern': r'^enable secret\b',
        'remediation': 'Use `enable secret` rather than a plaintext password.',
    },
    {
        'id': 'no_enable_password',
        'title': 'Avoid `enable password` (use `enable secret`)',
        'category': 'Password security',
        'severity': 'medium',
        'check': 'must_not_contain',
        'pattern': r'^enable password\b',
        'remediation': 'Replace `enable password` with `enable secret`: `enable password` is reversible (type 0 or type 7), whereas `enable secret` is stored as a one-way hash.',
    },
    {
        'id': 'vty_ssh',
        'title': 'SSH allowed on VTY lines',
        'category': 'Management access',
        'severity': 'high',
        'check': 'must_contain',
        'pattern': r'transport input.*\bssh\b',
        'remediation': 'Allow SSH on VTY lines.',
    },
    {
        'id': 'no_telnet',
        'title': 'Telnet disabled on VTY lines',
        'category': 'Management access',
        'severity': 'high',
        'check': 'must_not_contain',
        'pattern': r'transport input.*\btelnet\b',
        'remediation': 'Disable telnet on VTY lines.',
    },
    {
        'id': 'no_transport_all',
        'title': 'No `transport input all`',
        'category': 'Management access',
        'severity': 'medium',
        'check': 'must_not_contain',
        'pattern': r'transport input\s+all\b',
        'remediation': 'Avoid `transport input all`; specify ssh.',
    },
    {
        'id': 'http_server_disabled',
        'title': 'HTTP server disabled',
        'category': 'Services',
        'severity': 'medium',
        'check': 'must_not_contain',
        'pattern': r'^ip http server\b',
        'remediation': 'Disable the HTTP server (`no ip http server`) or use HTTPS only.',
    },
    {
        'id': 'snmp_no_default_comm',
        'title': 'No default SNMP communities',
        'category': 'Services',
        'severity': 'high',
        'check': 'must_not_contain',
        'pattern': r'snmp-server community\s+(public|private)\b',
        'ignorecase': True,
        'remediation': 'Replace default SNMP communities.',
    },
    {
        'id': 'logging_configured',
        'title': 'Logging destination configured',
        'category': 'Logging & time',
        'severity': 'low',
        'check': 'must_contain',
        'pattern': r'^logging\s+\S+',
        'remediation': 'Configure a syslog/logging destination.',
    },
    {
        'id': 'ntp_configured',
        'title': 'NTP server configured',
        'category': 'Logging & time',
        'severity': 'low',
        'check': 'must_contain',
        'pattern': r'^ntp server\b',
        'remediation': 'Configure an NTP server for accurate timestamps.',
    },
]


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

def _matched_line(config_text, match):
    """Return the full (stripped) config line containing *match*."""
    start = config_text.rfind('\n', 0, match.start()) + 1
    end = config_text.find('\n', match.end())
    if end == -1:
        end = len(config_text)
    return config_text[start:end].strip()


def audit_config(config_text):
    """Run all COMPLIANCE_RULES against *config_text*.

    Returns (results, summary) where results is a list of per-rule dicts
    and summary holds the aggregate counts and compliance score.
    """
    results = []
    for rule in COMPLIANCE_RULES:
        flags = re.MULTILINE
        if rule.get('ignorecase'):
            flags |= re.IGNORECASE
        match = re.search(rule['pattern'], config_text, flags)

        if rule['check'] == 'must_contain':
            status = 'pass' if match else 'fail'
            detail = _matched_line(config_text, match) if match else 'Not found'
        else:  # must_not_contain
            status = 'fail' if match else 'pass'
            detail = _matched_line(config_text, match) if match else 'Not present'

        results.append({
            'id': rule['id'],
            'title': rule['title'],
            'category': rule['category'],
            'severity': rule['severity'],
            'status': status,
            'detail': detail,
            'remediation': rule['remediation'],
        })

    total = len(results)
    passed = sum(1 for r in results if r['status'] == 'pass')
    failed = total - passed
    summary = {
        'total': total,
        'passed': passed,
        'failed': failed,
        'score': round(passed / total * 100) if total else 0,
        'failed_high': sum(1 for r in results if r['status'] == 'fail' and r['severity'] == 'high'),
        'failed_medium': sum(1 for r in results if r['status'] == 'fail' and r['severity'] == 'medium'),
        'failed_low': sum(1 for r in results if r['status'] == 'fail' and r['severity'] == 'low'),
    }
    return results, summary


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

WEAK_SAMPLE = """\
hostname weak-router
!
enable password cisco123
!
snmp-server community PUBLIC RO
ip http server
logging 192.0.2.50
ntp server 192.0.2.10
!
line vty 0 4
 transport input all
 password telnetpass
line vty 5 15
 transport input telnet
!
end
"""

HARDENED_SAMPLE = """\
hostname hardened-router
!
service password-encryption
enable secret 9 $9$abcdefghijklmnop
!
no ip http server
no ip http secure-server
snmp-server community S3cureC0mm RO
logging host 192.0.2.50
ntp server 192.0.2.10
!
line vty 0 4
 transport input ssh
 login local
!
end
"""


def _print_report(name, config_text):
    results, summary = audit_config(config_text)
    print(f'=== {name} ===')
    for r in results:
        mark = 'PASS' if r['status'] == 'pass' else 'FAIL'
        print(f"  [{mark}] {r['severity']:<6} {r['title']:<40} {r['detail']}")
    print(f"  Score: {summary['score']}%  "
          f"({summary['passed']}/{summary['total']} passed, "
          f"failed high={summary['failed_high']} "
          f"medium={summary['failed_medium']} low={summary['failed_low']})")
    print()


if __name__ == '__main__':
    _print_report('Weak sample config', WEAK_SAMPLE)
    _print_report('Hardened sample config', HARDENED_SAMPLE)
