# phpdetect

Two separate operator playbooks for PHP2Shell assessment and remediation.

| Playbook | Scope | Private record template |
|---|---|---|
| [Discovery and assessment](PLAYBOOK.md) | Read-only runtime mapping, NCSC/vendor matching, assessment, prioritization, and handoff. | [Discovery inventory](inventory.example.json) |
| [Update and remediation](UPDATE-PLAYBOOK.md) | Change planning, updates, restarts, redeployment, verification, and closure. | [Remediation record](remediation.example.json) |

Start with discovery. Its output is inventory and findings. Run the update playbook separately for remediation, linking changes to discovery record IDs. Nothing in this repository automatically scans or patches systems.

**Unknown stays unknown until evidence establishes the deployed runtime's status.** Missing headers, an updated CLI binary, or a healthy website alone cannot clear a system.

Baseline reviewed: **2026-10-22**. Recheck the [PHP advisory](https://www.php.net/archive/2026.php#2026-10-21-5) and vendor notices before assessment or remediation.

Keep completed records, internal hostnames, customer information, configuration dumps, and evidence in your private incident/change-management system. Discovery inventory schema version 2 moves change-execution fields to the separate remediation template. Retain existing records as historical evidence.
