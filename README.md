> **Unofficial proof of concept:** This repository is not official vendor-provided code. It is an independent proof of concept (PoC) demonstrating how Ansible can be used to detect PHP installations.

# phpdetect

[Open the public lab dashboard](https://hfenner.github.io/phpdetect/) — owner-approved lab discovery snapshot; no login required. See the job number and collection time on the page. Unknown findings are not clearance.

Executable Ansible automation for PHP2Shell discovery and separately invoked remediation. No exploit probes. Discovery never installs packages, changes configuration, or restarts managed services; Ansible uses its normal temporary module transport and writes private reports on the controller.

## Ansible Automation Platform 2.7

Use the [execution environment definition](execution-environment.yml), [build and publish workflow](.github/workflows/build-ee.yml), and [AAP installation playbook and settings](aap/README.md). The custom EE is published to `ghcr.io/hfenner/phpdetect-ee`; install with an immutable digest from a successful build. The installer creates separate discovery, update-plan, and apply-update job templates. AAP job artifacts preserve evidence after the execution container is removed.

## Run

Requires Ansible Core 2.19+ on the controller, Ansible's supported Python runtime on managed Linux hosts, and SSH access. Run from this repository root so `ansible.cfg` loads the inventory defaults. The example inventory is intentionally empty. There are no project Python scripts or custom modules: collection, classification, updates, snapshot refresh, and tests are Ansible YAML tasks. A read-only Bash task uses Linux procfs and standard utilities to compare live executables and mapped files; it is embedded directly in the task file.

```sh
# Use your private inventory, group php_targets, and host_vars.
ansible-playbook -i /private/path/hosts.yml playbooks/discover.yml

# A distinct invocation; never imported by discovery. A real run must name the change
# it is confirming so a plan left in host_vars cannot restart production by accident.
ansible-playbook -i /private/path/hosts.yml playbooks/update.yml --check
ansible-playbook -i /private/path/hosts.yml playbooks/update.yml -e phpdetect_confirm_change=CHANGE_ID
```

Run from a controller account whose home directory is private; `ansible.cfg` deliberately leaves Ansible's temporary directory at its default under the home directory rather than a shared `/tmp` path, because the module payload cache lives there.

Use [package host variables](inventory/runtime.example.yml) or [Docker-alternative Compose update variables](inventory/container.example.yml) as the configuration schema. Replace placeholders with reviewed vendor evidence and exact package versions/image digests. Examples cannot be deployed as written. Keep inventories and results outside this public repository. When limiting discovery, include `localhost`, e.g. `--limit 'web01,localhost'`, because it prepares the NCSC snapshot and report directory.

## Discovery: `playbooks/discover.yml`

- Reads the bundled, commit-pinned NCSC product inventory from `data/ncsc/snapshot.json` and matches automatically identified products and configured product terms without network requests. Matches are candidates, never proof of remediation; absent matches do not clear products. Missing or malformed snapshots fail discovery. The former `phpdetect_fetch_ncsc` variable is no longer used; discovery always reads local data.
- The `Update bundled NCSC lists` GitHub Action checks NCSC `main` hourly and supports manual runs. It commits refreshed data to this repository’s default branch using `GITHUB_TOKEN` with `contents: write`. Enable Actions and allow that workflow to write to the default branch; branch protection may prevent direct bot commits. Scheduled runs begin once the workflow is on the default branch, can be delayed by GitHub, and capture the latest upstream commit rather than every intervening push. No upstream workflow access or personal token is required. See [snapshot provenance and local refresh](data/ncsc/README.md).
- Inventories full PHP package revisions, common installation paths, live PHP processes, Apache PHP module candidates, web-server routing hints, and Podman containers (Docker is an alternative). Containers are inventoried by image identity only. With `-e phpdetect_container_cli_probe=true`, running containers are additionally checked with `podman exec ... php -n -v` (or `docker exec` for Docker targets) for supporting CLI version evidence; this executes a binary from the container image and does not verify its web-serving runtime. Does not dump environment variables or application secrets.
- Joins inventory-defined website/runtime relationships to observed binaries, package ownership, process identities, and mapped files. Processes in another mount namespace (containers, chroots) are reported separately and never matched against host artifacts. Anonymous shared memory, memfd, device, and temporary-file mappings are ignored when checking for stale libraries. `sites` and the artifact path must be supplied for authoritative mapping; it cannot infer every load-balancer route or arbitrary application layout. Unmapped candidates remain unknown.
- Gives internet-facing or unknown-exposure runtime records priority P1; internal records P2. Retains per-runtime evidence and reasons.
- Seeds a private JSON report for every scoped host before connection attempts. Unreachable/excluded hosts remain unknown. Report filenames are hashed inventory hostnames; the contents name the host. Files are mode 0600 in a unique 0700 temporary directory, whose location is printed. Copy these reports into your private evidence store before temporary-directory cleanup.

A runtime is `patched` only when operator-reviewed evidence covers **both CVEs**, matches OS release and exact full package revisions, includes the owning package, and all matching running artifacts are current. Missing visibility, missing workers, stale executables/libraries, or incomplete evidence yields `unknown`. The procfs scan always covers every process: a process that cannot be inspected is recorded as a visibility gap with its PID and cause (in the runtime's `visibility_gaps`, its `reason`, and the host `gaps`) rather than aborting the scan, and any gap keeps the runtime `unknown`. Exact vendor evidence can classify `affected`. Host status remains unknown unless an affected runtime is found: checking a configured subset cannot establish complete host clearance. HTTP headers and upstream version numbers alone never establish clearance.

The `evidence.channel` field records the operator's reviewed vendor channel; this implementation verifies package identities, not repository signing provenance. Its conclusions rely on the correctness of the supplied vendor evidence and site-to-runtime mapping. A patched result is not an incident-response clearance.

## Automatic product identification

Discovery now checks **WordPress, Drupal, Joomla, Nextcloud Server, Moodle, MediaWiki, GLPI and Zabbix web frontend**. All probes are inline Ansible tasks in `playbooks/tasks/products.yml` and its included task files; no external Python scripts or application PHP files are executed.

| Product | Required files relative to installation root | Version evidence |
| --- | --- | --- |
| WordPress | `wp-includes/version.php`, `wp-settings.php` | `wp_version` |
| Drupal (modern core layout) | `core/lib/Drupal.php`, `core/modules/system/system.info.yml` | `VERSION` |
| Joomla | `administrator/manifests/files/joomla.xml`, `includes/defines.php` | XML `version` |
| Nextcloud Server | `version.php`, `occ` | `OC_VersionString` plus `nextcloud` vendor marker |
| Moodle (legacy/root layout) | `version.php`, `lib/moodlelib.php` | `release` |
| MediaWiki (modern maintenance layout) | `includes/Defines.php`, `maintenance/run.php` | `MW_VERSION` |
| GLPI 10.x layout | `inc/define.php`, `front/central.php` | `GLPI_VERSION` |
| Zabbix frontend | `include/defines.inc.php`, `zabbix.php` | `ZABBIX_VERSION` |

Linux defaults search `/var/www`, `/srv/www`, `/usr/share/webapps`, `/usr/share/zabbix`, `/usr/share/glpi` and `/opt`. Windows defaults search `C:\inetpub\wwwroot`, `C:\xampp\htdocs` and accessible IIS physical paths. Override `phpdetect_product_roots` for custom deployments. The default depth is six (allowed range 1–10); Linux depth counts path components to the marker file, while Windows depth bounds installation-root directories. Linux reads at most 256 KiB of a version marker; Windows skips larger marker files. Numeric version evidence omits prerelease/build suffixes and is not a package revision.

Optional `phpdetect_product_container_probe: true` searches running containers with the selected Podman engine (Docker alternative). Default container roots are `/var/www`, `/usr/share/nginx/html`, `/app` and `/opt`, configurable with `phpdetect_product_container_roots`. This executes a read-only shell probe in the container, not PHP. Containers without a shell/find utilities, stopped containers, other engines and other users remain unassessed.

Each `products[]` finding records the product, version evidence, installation location, identifying files, discovery check, container identity where applicable, matching NCSC product rows and snapshot commit. Exact `document_roots` on `phpdetect_runtimes` create **operator-configured associations** to assessed runtime IDs. Container findings can link to optional PHP CLI evidence from the same container. Neither association proves which build serves requests. Unmapped products remain `runtime_mapping_status: unknown`; **all product patch statuses remain unknown**. NCSC vulnerability/fix statements are advisory context, not a local vulnerability verdict. Legacy `phpdetect_products` declarations are retained as `operator_supplied` evidence.

```yaml
phpdetect_product_roots: [/var/www, /srv/customer-sites]
phpdetect_product_depth: 6
phpdetect_product_container_probe: true
phpdetect_runtimes:
  - id: storefront-fpm
    artifact: /usr/sbin/php-fpm
    document_roots: [/srv/customer-sites/storefront]
```

Rerun `ansible-playbook -i /path/to/inventory.yml playbooks/discover.yml` with the same variables to reproduce the checks. Inspect `products[]`, `ncsc_matches`, `runtime_links` and host `gaps` in the generated report. The dashboard lists these findings under product identification. Existing published reports are historical snapshots and do not acquire findings until discovery is rerun and the new report is explicitly published.

Signatures can identify inactive copies and can be spoofed; this is not vendor authentication. Custom layouts, older/newer release layouts, symlinked trees and products outside these eight integrations may be missed. Missing matches never establish absence. CI exercises the real Linux, Windows PowerShell, Podman and Docker probes against isolated fixtures, including incomplete signatures, an ownCloud lookalike, repeat scans and conservative runtime associations.

## Updates: `playbooks/update.yml`

Independent entry point; never updates automatically from discovery results. Processes one host at a time and stops rollout after a failed change.

| Adapter | Executed actions | Verification |
|---|---|---|
| `package` (default) | Install explicitly pinned Debian/Ubuntu or RPM revisions; restart listed services. | Exact OS/vendor/package match, package ownership, every matching live executable/module and mapped file, then configured HTTPS health checks. |
| `docker_compose` | Pull an attested immutable image and recreate only the selected existing Compose service. The Compose file must already reference that digest. | New replica identities, unchanged-or-greater replica count, every replica's actual image ID matching the pulled digest, running state and a healthy healthcheck (polled), then endpoint checks. |

Health checks run from the controller by default; set `run_from` on a check to run it from another inventory host, and `headers` (for example a `Host` header against a backend address) so the check reaches the backend just changed rather than whichever replica a balancer selects.

`--check` performs preflight checks and package-manager planning; it does not restart services or redeploy containers, and always reports patch status unknown. A real update intentionally restarts/recreates the specified services on each run to remove stale workers. No automatic rollback to a potentially vulnerable build. Backup, traffic-draining, and recovery policies remain the responsibility of the deployment owner.

Package updates require `python3-apt` or `python3-dnf` on the target, supported signed repositories already configured, sufficient privileges, and valid service names. Docker updates require Docker Compose v2 with JSON config output. The image's security status comes from reviewed digest-specific vendor/build evidence; image identity alone is not a vulnerability scan. Full resolved Compose configurations and inspect responses are suppressed from logs.

**Supported scope:** automated Linux package discovery/remediation and Podman-first container discovery, with Docker inventory/Compose remediation as an alternative. Podman remediation is not automated by the current update adapter. Kubernetes, Windows/IIS, managed hosting, arbitrary source builds, and vendor appliances are not automatically remediated. Product records remain unknown pending a dedicated vendor integration; unsupported update adapters fail explicitly. NCSC's list is not a complete asset inventory. Procfs restrictions may require `phpdetect_become: true` for conclusive Linux runtime evidence.

## Disposable AWS lab

Use [Build PHP lab](playbooks/build-lab-aws.yml) and the separate [teardown playbook](playbooks/destroy-lab-aws.yml) to provision an isolated AWS test host with vulnerable, fixed, and unmapped PHP fixtures. See [lab settings and AAP setup](lab/README.md). An optional exact vendor-package fixture exercises host-level classification.

## Validation

[Gitleaks](https://github.com/hfenner/phpdetect/actions/workflows/gitleaks.yml) scans commits on every pull request and push to `main`; manual dispatch scans repository history. The [official action](https://github.com/gitleaks/gitleaks-action) is pinned to a commit, with scanner version 8.30.1. Findings fail the job, secret values are redacted, and PR comments and report artifact uploads are disabled. To scan all locally available history, run `gitleaks git --redact --log-opts="--all" .` from a full clone.

[Ansible lint](https://github.com/hfenner/phpdetect/actions/workflows/ansible-lint.yml) runs on every pull request, push to `main`, and manual dispatch. It installs the required collections and runs `ansible-lint --offline --strict`; lint findings fail the job. YAML line-length limits are disabled to preserve inline shell, PowerShell, and Jinja expressions. Other lint rules remain enabled.

To reproduce the CI lint check with Python 3.12:

```sh
pip install 'ansible-core>=2.19,<2.20' 'ansible-lint==26.10.1'
ansible-galaxy collection install -r requirements.yml
ansible-lint --offline --strict
```

```sh
ansible-playbook tests/classification.yml
ansible-playbook tests/package-parsing.yml
ansible-playbook tests/live-inspection.yml
ansible-playbook tests/windows-tasks.yml
ansible-playbook playbooks/discover.yml --syntax-check
ansible-playbook playbooks/update.yml --syntax-check
ansible-playbook playbooks/refresh-ncsc.yml --syntax-check
ansible-playbook -i tests/local.yml playbooks/discover.yml
```

The local integration inventory runs discovery only; it never authorizes updates. Nineteen Ansible policy cases exercise the actual classification task, including vendor backports, stale worker evidence, missing permissions/CVEs, OS mismatches, unknown results, and the reason text that names blocking processes. Package parsing tests verify exact Debian/RPM revisions and check the embedded Bash task's syntax. The live-inspection test runs the real procfs script against a fixture process tree: anonymous shared-memory mappings are ignored, stale or replaced files block clearance, processes under another root are skipped, and uninspectable processes are named as gaps. Procfs collection requires Linux; a non-Linux integration host returns unknown. No production package update or container rollout has been tested by this repository.

Sources: [NCSC PHP2Shell inventory](https://github.com/NCSC-NL/php2shell), [PHP advisory](https://www.php.net/archive/2026.php#2026-10-21-5), [Ansible apt](https://docs.ansible.com/projects/ansible/latest/collections/ansible/builtin/apt_module.html), [Ansible dnf](https://docs.ansible.com/projects/ansible/latest/collections/ansible/builtin/dnf_module.html). Advisory baseline reviewed 2026-10-22; refresh vendor evidence before use.

## OpenShift dashboard

The [authenticated web dashboard](dashboard/README.md) shows hosts, PHP/package versions, patch status, and evidence from AAP discovery reports. Deploy or refresh it with `playbooks/deploy-dashboard.yml`. Reports remain explicit snapshots; unknown findings are never treated as cleared.

### Container engine selection

Discovery defaults to `phpdetect_container_engine: auto`: prefer the installed Podman executable, otherwise use Docker. Set `podman` or `docker` explicitly in host variables to select the engine. It does not fall back after a permission or connection failure. Each container records its actual engine. Only the selected engine and connection/become user are scanned: rootless Podman requires running as the owning user. Use separate inventory contexts for additional users or engines; an empty store is not host clearance.

New disposable labs default to rootful Podman with `podman-compose`. Set `phpdetect_lab_container_engine: docker` for the Docker alternative. `podman compose` is a provider wrapper; this lab invokes `podman-compose` explicitly. Existing Docker labs are not migrated automatically. The current public job 30 snapshot remains labeled Docker because that is how it was collected.

Container updates remain separate: the existing `docker_compose` adapter is Docker-specific and requires Compose v2 JSON configuration output. Do not run it against Podman. Podman lab fixtures include a fixed Compose file for separate testing, but no automated Podman remediation plan is generated. OCI image names beginning `docker.io/` identify the image registry, not the container engine; Podman pulls those same pinned official images.
