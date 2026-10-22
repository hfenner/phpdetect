# Bundled NCSC product lists

`snapshot.json` contains verbatim product-list Markdown from
[NCSC-NL/php2shell](https://github.com/NCSC-NL/php2shell), its exact source commit
and commit date, and the upstream EUPL-1.2 license text. The lists remain subject
to that license. They are repackaged as JSON without changing their content.

The `Update bundled NCSC lists` GitHub Action checks upstream `main` hourly and
can also be run manually. It commits only when the snapshot changes. Discovery
reads this local file and never contacts NCSC. A snapshot is candidate inventory,
not proof of remediation; its commit date is not a guarantee of current coverage.

To refresh locally, run `python3 scripts/update_ncsc_snapshot.py` from the
repository root (requires Git, Python 3, and HTTPS access to GitHub).
