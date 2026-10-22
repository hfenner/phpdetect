# phpdetect

An operator playbook for finding PHP runtimes, assessing PHP2Shell patch status, and verifying remediation across websites, containers, and vendor products.

Start with [PLAYBOOK.md](PLAYBOOK.md). Copy [inventory.example.json](inventory.example.json) into a private working directory and create one record per site-to-runtime relationship. This repository supplies procedures and a blank evidence template; it does not automatically scan or patch systems.

The central rule: **unknown stays unknown until evidence establishes the deployed runtime's status.** A missing PHP header, updated CLI binary, successful package update, or healthy website alone is insufficient.

## Workflow

1. Reconcile your asset inventory with [NCSC's PHP-dependent product inventory](https://github.com/NCSC-NL/php2shell/tree/main/software).
2. Map each website and product to every serving runtime and replica.
3. Record full package revisions and vendor evidence for both CVEs.
4. Patch, restart or replace serving processes, and verify the running build.
5. Close only records meeting the evidence requirements in the playbook.

Baseline reviewed: **2026-10-22**. Recheck the [PHP advisory](https://www.php.net/archive/2026.php#2026-10-21-5) and relevant vendor notices before each maintenance window.

Keep real hostnames, internal addresses, customer information, configuration dumps, and investigation evidence out of this public repository. Store completed inventories in your private incident or change-management system.
