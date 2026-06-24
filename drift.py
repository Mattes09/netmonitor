"""Configuration drift detection between two stored config backups.

Standalone module — depends only on the Python standard library (``difflib``)
so it can be imported by the Flask app / API or run directly for an offline
self-test:

    python drift.py

It is read-only and pure: a single function over two strings. It never touches
the database or a device — the caller fetches the two backups and passes their
config text in.
"""
import difflib


def compute_drift(old_text, new_text):
    """Compute the line-level drift between two configuration backups.

    Convention: *old_text* is the OLDER backup and *new_text* the NEWER one,
    so the unified diff reads older -> newer.

    Returns a dict::

        {
          "identical": bool,   # True when added == 0 and removed == 0
          "added": int,        # count of added (+) lines
          "removed": int,      # count of removed (-) lines
          "lines": [ {"kind": ..., "text": ...}, ... ],
        }

    where ``kind`` is one of ``"add"``, ``"remove"``, ``"context"`` or
    ``"hunk"`` (the ``@@ ... @@`` header). The leading ``+``/``-``/space diff
    marker is stripped into ``kind``; ``text`` holds the line content. The
    ``---`` / ``+++`` file-header lines are dropped — they add no value here.
    """
    added = 0
    removed = 0
    lines = []

    diff = difflib.unified_diff(
        old_text.splitlines(),
        new_text.splitlines(),
        lineterm='',
    )

    # unified_diff emits the two ---/+++ file headers exactly once, immediately
    # before the first @@ hunk. Skipping everything until the first hunk drops
    # those headers without misclassifying a real config line that happens to
    # start with '---'/'+++' (such a line only ever appears inside a hunk, with
    # its own leading -/+ marker).
    in_hunk = False
    for line in diff:
        if line.startswith('@@'):
            in_hunk = True
            lines.append({'kind': 'hunk', 'text': line})
        elif not in_hunk:
            continue  # ---/+++ file-header lines
        elif line.startswith('+'):
            added += 1
            lines.append({'kind': 'add', 'text': line[1:]})
        elif line.startswith('-'):
            removed += 1
            lines.append({'kind': 'remove', 'text': line[1:]})
        else:
            # Context lines carry a single leading space marker.
            text = line[1:] if line.startswith(' ') else line
            lines.append({'kind': 'context', 'text': text})

    return {
        'identical': added == 0 and removed == 0,
        'added': added,
        'removed': removed,
        'lines': lines,
    }


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

SAMPLE_OLD = """\
hostname edge-router
!
no ip http server
!
ntp server 192.0.2.10
!
line vty 0 4
 transport input ssh
 login local
!
end
"""

SAMPLE_NEW = """\
hostname edge-router
!
no ip http server
!
ntp server 192.0.2.10
ntp server 192.0.2.11
logging host 192.0.2.50
!
line vty 0 4
 transport input ssh
 exec-timeout 5 0
!
end
"""

_MARK = {'add': '+', 'remove': '-', 'hunk': '@', 'context': ' '}


def _print_drift(name, old_text, new_text):
    result = compute_drift(old_text, new_text)
    print(f'=== {name} ===')
    if result['identical']:
        print('  No drift — the two configurations are identical.')
    else:
        print(f"  Drift: {result['added']} added, {result['removed']} removed")
    for line in result['lines']:
        print(f"  {_MARK[line['kind']]} {line['text']}")
    print(f"  -> identical={result['identical']} "
          f"added={result['added']} removed={result['removed']}")
    print()


if __name__ == '__main__':
    _print_drift('Drift between two configs', SAMPLE_OLD, SAMPLE_NEW)
    _print_drift('Identical configs', SAMPLE_NEW, SAMPLE_NEW)
