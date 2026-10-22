# phpdetect

Executable Ansible automation for PHP2Shell discovery and separately invoked remediation. No exploit probes. Discovery never installs packages, changes configuration, or restarts managed services; Ansible uses its normal temporary module transport and writes private reports on the controller.

## Run

Requires Ansible Core 2.19+ on the controller, Python 3.11+ on managed Linux hosts, and SSH access. Run from this repository root so `ansible.cfg` loads the bundled `phpdetect` module. The example inventory is intentionally empty.

```sh
# Use your private inventory, group php_targets, and host_vars.
ansible-playbook -i /private/path/hosts.yml playbooks/discover.yml

# A distinct invocation; never imported by discovery.
ansible-playbook -i /private/path/hosts.yml playbooks/update.yml --check
ansible-playbook -i /private/path/hosts.yml playbooks/update.yml
```

Use [package host variables](inventory/runtime.example.yml) or [Docker Compose host variables](inventory/container.example.yml) as the configuration schema. Replace placeholders with reviewed vendor evidence and exact package versions/image digests. Examples cannot be deployed as written. Keep inventories and results outside this public repository. When limiting discovery, include `localhost`, e.g. `--limit 'web01,localhost'`, because it prepares the NCSC snapshot and report directory.

## Discovery: `playbooks/discover.yml`

- Reads the bundled, commit-pinned NCSC product inventory from `data/ncsc/snapshot.json` and matches configured product terms without network requests. Matches are candidates, never proof of remediation; absent matches do not clear products. Missing or malformed snapshots fail discovery. The former `phpdetect_fetch_ncsc` variable is no longer used; discovery always reads local data.
- The `Update bundled NCSC lists` GitHub Action checks NCSC `main` hourly and supports manual runs. It commits refreshed data to this repository’s default branch using `GITHUB_TOKEN` with `contents: write`. Enable Actions and allow that workflow to write to the default branch; branch protection may prevent direct bot commits. Scheduled runs begin once the workflow is on the default branch, can be delayed by GitHub, and capture the latest upstream commit rather than every intervening push. No upstream workflow access or personal token is required. See [snapshot provenance and local refresh](data/ncsc/README.md).
- Inventories full PHP package revisions, common installation paths, live PHP processes, Apache PHP module candidates, web-server routing hints, and Docker containers. Running containers are checked with `php -n -v` for supporting CLI version evidence; this does not verify their web-serving runtime. Does not dump environment variables or application secrets.
- Joins inventory-defined website/runtime relationships to observed binaries, package ownership, process identities, and mapped files. `sites` and the artifact path must be supplied for authoritative mapping; it cannot infer every load-balancer route or arbitrary application layout. Unmapped candidates remain unknown.
- Gives internet-facing or unknown-exposure runtime records priority P1; internal records P2. Retains per-runtime evidence and reasons.
- Seeds a private JSON report for every scoped host before connection attempts. Unreachable/excluded hosts remain unknown. Reports use hashed inventory hostnames and mode 0600 in a unique 0700 temporary directory, whose location is printed. Copy these reports into your private evidence store before temporary-directory cleanup.

A runtime is `patched` only when operator-reviewed evidence covers **both CVEs**, matches OS release and exact full package revisions, includes the owning package, and all matching running artifacts are current. Missing visibility, missing workers, stale executables/libraries, or incomplete evidence yields `unknown`. Exact vendor evidence can classify `affected`. Host status remains unknown unless an affected runtime is found: checking a configured subset cannot establish complete host clearance. HTTP headers and upstream version numbers alone never establish clearance.

The `evidence.channel` field records the operator's reviewed vendor channel; this implementation verifies package identities, not repository signing provenance. Its conclusions rely on the correctness of the supplied vendor evidence and site-to-runtime mapping. A patched result is not an incident-response clearance.

## Updates: `playbooks/update.yml`

Independent entry point; never updates automatically from discovery results. Processes one host at a time and stops rollout after a failed change.

| Adapter | Executed actions | Verification |
|---|---|---|
| `package` (default) | Install explicitly pinned Debian/Ubuntu or RPM revisions; restart listed services. | Exact OS/vendor/package match, package ownership, every matching live executable/module and mapped file, then configured HTTPS health checks. |
| `docker_compose` | Pull an attested immutable image and recreate only the selected existing Compose service. The Compose file must already reference that digest. | New replica identities, unchanged-or-greater replica count, every replica's actual image ID matching the pulled digest, running/health state, then endpoint checks. |

`--check` performs preflight checks and package-manager planning; it does not restart services or redeploy containers, and always reports patch status unknown. A real update intentionally restarts/recreates the specified services on each run to remove stale workers. No automatic rollback to a potentially vulnerable build. Backup, traffic-draining, and recovery policies remain the responsibility of the deployment owner.

Package updates require `python3-apt` or `python3-dnf` on the target, supported signed repositories already configured, sufficient privileges, and valid service names. Docker updates require Docker Compose v2 with JSON config output. The image's security status comes from reviewed digest-specific vendor/build evidence; image identity alone is not a vulnerability scan. Full resolved Compose configurations and inspect responses are suppressed from logs.

**Supported scope:** automated Linux package discovery/remediation and Docker inventory/Compose remediation. Kubernetes, Windows/IIS, managed hosting, arbitrary source builds, and vendor appliances are not automatically remediated. Product records remain unknown pending a dedicated vendor integration; unsupported update adapters fail explicitly. NCSC's list is not a complete asset inventory. Procfs restrictions may require `phpdetect_become: true` for conclusive Linux runtime evidence.

## Validation

```sh
python3 -m unittest discover -s tests -v
ansible-playbook playbooks/discover.yml --syntax-check
ansible-playbook playbooks/update.yml --syntax-check
ansible-playbook -i tests/local.yml playbooks/discover.yml
```

The local integration inventory runs discovery only; it never authorizes updates. Tests cover vendor backports, stale/deleted workers and libraries, missing permissions/CVEs, OS mismatches, and unknown results. No production package update or container rollout has been tested by this repository.

Sources: [NCSC PHP2Shell inventory](https://github.com/NCSC-NL/php2shell), [PHP advisory](https://www.php.net/archive/2026.php#2026-10-21-5), [Ansible apt](https://docs.ansible.com/projects/ansible/latest/collections/ansible/builtin/apt_module.html), [Ansible dnf](https://docs.ansible.com/projects/ansible/latest/collections/ansible/builtin/dnf_module.html). Advisory baseline reviewed 2026-10-22; refresh vendor evidence before use.
