# Bundled NCSC product lists

`snapshot.json` contains verbatim product-list Markdown from
[NCSC-NL/php2shell](https://github.com/NCSC-NL/php2shell), its exact source commit
and commit date, and the upstream EUPL-1.2 license text. The lists remain subject
to that license. They are repackaged as JSON without changing their content.

The `Update bundled NCSC lists` GitHub Action checks upstream `main` hourly and
can also be run manually. It commits only when the snapshot changes. Discovery
reads this local file and never contacts NCSC. A snapshot is candidate inventory,
not proof of remediation; its commit date is not a guarantee of current coverage.

To refresh locally, run `ansible-playbook playbooks/refresh-ncsc.yml` from the
repository root (requires Git, Ansible, and HTTPS access to GitHub).
The playbook validates all documents and the license before atomically replacing
the snapshot. Failed refreshes leave the previous file intact; unchanged data is
not rewritten. The hourly workflow runs this same playbook, with no custom scripts.
