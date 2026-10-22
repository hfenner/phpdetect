# PHP2Shell discovery and assessment playbook

Owner: assessment lead. Execute with the application owner, platform administrator, and security responder. Record timestamps in UTC and assign an owner and next action to every unresolved record.

This is a read-only assessment procedure. Do not install updates, restart services, redeploy workloads, change configuration, or deploy diagnostics during discovery. Changes belong exclusively to [UPDATE-PLAYBOOK.md](UPDATE-PLAYBOOK.md). No exploit probes are required.

## 1. Establish scope and evidence

Create a private incident workspace and copy `inventory.example.json` there. Keep one record for each website/product → backend → runtime relationship, including every replica. Reuse `runtime_id` where multiple sites share a runtime. Record inaccessible assets too.

Use DNS, load-balancer routes, cloud inventories, hosting panels, container platforms, configuration management, and the CMDB to build the starting list. Include public sites, internal portals, staging, appliances, NAS systems, administrative interfaces, and dormant workloads that could be started again. Assign a scope owner to reconcile the list; a clean scan is not proof of complete coverage.

Consult the [NCSC software list](https://github.com/NCSC-NL/php2shell/tree/main/software). Match supplier, exact product, edition, installed version, and deployment type. Follow each entry to its original vendor advisory. Record both the NCSC reference and the vendor advisory with the date checked. An absent product, an investigation status, or a name-only match leaves patch status `unknown`.

The current [PHP advisory](https://www.php.net/archive/2026.php#2026-10-21-5) identifies two issues: CVE-2026-109618 and CVE-2026-109619. Its fixed upstream releases are:

| Branch | First fixed upstream release |
|---|---|
| 8.2 | 8.2.35 |
| 8.3 | 8.3.36 |
| 8.4 | 8.4.27 |
| 8.5 | 8.5.12 |

Older branches require a supported upgrade or a verified vendor backport. Compare distribution packages against that distribution's exact release, repository channel, and full package revision; an older upstream version can contain the fixes. Do not infer safety for an unlisted branch or prerelease. Configuration mitigations do not establish patch status.

## 2. Map sites to the runtimes actually serving them

Trace each route: **hostname → proxy/load balancer → backend host or pod → virtual host → handler/socket → process → binary/module and package/image**. Capture the configuration reference and observation time. Multiple backends require separate verification.

### Linux hosts

Start with package, process, and service inventory:

```sh
command -v php
php -v
ps -eo pid,ppid,lstart,comm
systemctl list-units --type=service --all
```

The first two commands identify only the default CLI installation. Discover additional runtimes in hosting panels and locations such as `/opt`, `/usr/local`, `/opt/plesk/php`, and `/opt/cpanel`; treat these as starting locations, not an exhaustive list.

For Debian/Ubuntu package evidence:

```sh
dpkg-query -W -f='${binary:Package}\t${Version}\t${Architecture}\n' 'php*' 'libapache2-mod-php*'
```

For RPM-based systems:

```sh
rpm -qa --qf '%{NAME}\t%{EPOCH}:%{VERSION}-%{RELEASE}\t%{ARCH}\n' | grep -i php
```

Capture the operating-system release and package source/channel as well. Missing packages do not rule out a source build or embedded runtime.

Inspect Apache virtual hosts and loaded modules (`apachectl -S`, `apachectl -M`, or the distribution equivalent). For Nginx, inspect the effective configuration with `nginx -T` and follow each `fastcgi_pass` socket/address to its FPM pool and service. Configuration output may contain secrets; retain it privately. Resolve upstream groups and reverse proxies all the way to their backends.

For an observed serving PID, substitute its numeric ID below:

```sh
readlink /proc/PID/exe
cat /proc/PID/maps
```

Map the resolved binary or loaded `libphp` module to its owning package using `dpkg-query -S /absolute/path` or `rpm -qf /absolute/path`. For mod_php, the PHP module inside Apache is the relevant runtime. For PHP-FPM, map both the pool and its worker processes. A process executable marked `(deleted)` or deleted PHP mapping is an investigation signal for the remediation owner. Absence of that signal does not prove a patched build.

### Containers and Kubernetes

List workloads and record immutable image identity:

```sh
docker ps -a --no-trunc
docker inspect --format '{{.Name}} {{.Image}}' CONTAINER_ID
kubectl get pods -A -o wide
kubectl get pod POD_NAME -n NAMESPACE -o json
```

Record container IDs, image IDs/digests, node, workload controller, and each replica. Trace ingress/service selectors to the actual pods. Include images used by scheduled jobs and scale-to-zero workloads in the inventory.

Inside a running container, use its package database and process/configuration evidence as above. `docker exec CONTAINER_ID php -v` or `kubectl exec ... -- php -v` can provide supporting CLI evidence, but cannot establish what FPM or an embedded server loaded. Inspect custom images and FrankenPHP through their build provenance, SBOM, and vendor release evidence. If tools or permissions are missing, record the gap instead of clearing the container.

### Windows, panels, appliances, and managed hosting

On IIS, inspect each site's handler mapping and FastCGI application's executable path. On Apache for Windows, inspect the loaded PHP DLL path. Record the specific binary/DLL build and its installation source; the PHP found in the interactive shell can differ.

For cPanel/Plesk and similar panels, export the domain-to-PHP-handler mapping and inspect every selected handler. Panel PHP and website PHP can be separate installations.

For appliances and managed services, request vendor confirmation identifying the installed product build, remediation for **both CVEs**, deployment/restart completion, and affected tenant/instance. Record the support case or advisory. Do not replace an appliance's bundled PHP with generic operating-system packages unless the vendor prescribes it.

Use an existing restricted runtime diagnostic or read-only process/build evidence to identify the serving runtime. Do not deploy diagnostic files during discovery. Cover every backend; if existing evidence is insufficient, retain `unknown`.

## 3. Classify and prioritize

Use these patch-status values for each CVE and for the aggregate record:

| Status | Required evidence |
|---|---|
| `unknown` | Default. Mapping, package provenance, vendor coverage, or running-build evidence is missing or conflicting. |
| `affected` | The identified deployed build falls in an affected range with no applicable verified backport. |
| `patched` | Advisory/build evidence establishes a fix and evidence ties every actual serving process to that fixed artifact; package version alone is insufficient. |
| `not_affected` | Authoritative applicability evidence explicitly excludes the exact deployed product/build from that CVE. |

Aggregate policy: any `affected` CVE makes the record `affected`; otherwise any `unknown` makes it `unknown`; both `not_affected` yield `not_affected`; otherwise all CVEs must be `patched` or `not_affected` to yield `patched`. Do not aggregate away an unknown backend. An asset is closed only when every required record is resolved.

Keep change execution in the separate remediation record. This inventory describes observed state; preserve it as the assessment baseline.

Suggested queue:

1. Suspected compromise: involve incident response immediately, preserve available evidence, and hand containment decisions to the incident responder.
2. Internet-facing affected or unknown runtimes; start vendor requests for appliances immediately. Within this group prioritize mod_php, sensitive data, and privileged management interfaces.
3. Internal affected or unknown runtimes, then dormant images/templates that could reintroduce the vulnerable build.

Unknown exposure is an urgent discovery task. A CDN/WAF or absent PHP header does not change patch status. Assign a due time and owner to blocked cases. If patching must wait, document containment and consult current vendor guidance; leave patch status unresolved.

## 4. Report and hand off

Produce a private report listing assets by exposure, patch status, owner, deadline, and evidence gap. Report unknown and affected counts separately. Reconcile coverage against the original asset inventory and NCSC product matches, including inaccessible assets and unresolved vendor investigations.

Hand the discovery record IDs and evidence to the operator of [UPDATE-PLAYBOOK.md](UPDATE-PLAYBOOK.md). This handoff does not execute or authorize production changes. Discovery is complete when scope coverage and gaps are documented, even if remediation remains open.

Re-run this read-only assessment after scaling, failover, restores, or deployment changes. Never clear an unverified backend.

## References and limitations

- [PHP security advisory](https://www.php.net/archive/2026.php#2026-10-21-5): source of the patch baseline and applicability guidance, reviewed 2026-10-22.
- [NCSC-NL operational repository](https://github.com/NCSC-NL/php2shell) and [product inventory](https://github.com/NCSC-NL/php2shell/tree/main/software): a discovery aid, not a complete list of your assets or proof of vendor remediation.
- [OpenAI version checker](https://github.com/openai/php2shell-checker): optional header/CLI triage. Hidden headers and version-only backport comparisons cannot establish clearance.

The workflow and evidence requirements here are operational recommendations. Commands are examples requiring platform-specific adaptation, not a tested deployment procedure for your environment. No production systems have been assessed by this repository.
