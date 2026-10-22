# PHP2Shell update and remediation playbook

Owner: change lead. Execute with the application owner, platform administrator, and security responder. This is a separate change procedure; running [discovery](PLAYBOOK.md) does not run these steps.

## 1. Accept the handoff and plan the change

Start with the private discovery inventory, site-to-runtime mappings, full package/image identities, advisory evidence, and evidence gaps. Copy [remediation.example.json](remediation.example.json) to a private workspace and reference exact discovery record IDs. Preserve the original assessment as pre-change evidence.

Resolve unknown runtime mappings before selecting packages or services. Recheck the [PHP advisory](https://www.php.net/archive/2026.php#2026-10-21-5) and the exact vendor release/channel for both CVEs. Follow your normal change authorization process. Record the operator, change reference, target artifact, maintenance window, and recovery plan. If the serving runtime or supported update path cannot be established, mark the change blocked and retain unknown patch status.

Track change progress separately: `not_started`, `planned`, `updated_restart_pending`, `verification_pending`, `complete`, or `blocked`. Installation success does not establish patch status. Preserve known affected status until fresh evidence supersedes it. If patching must wait, document containment using current vendor guidance; containment is not a fix.

## 2. Update and restart

Before changes, record the current package/image and process identities, confirm backup/recovery readiness, test compatibility in staging, and plan traffic draining. Confirm that the selected update covers both CVEs. Treat a rollback to a vulnerable build as renewed exposure requiring containment.

### Distribution packages

Use the verified repository/channel and update all packages belonging to each serving PHP installation, including its handler and matching extensions. These examples require replacing the package and service names with inventory-confirmed values:

```sh
# Debian/Ubuntu example: review candidates before installation.
sudo apt-get update
apt-cache policy PACKAGE_NAME
sudo apt-get install --only-upgrade PACKAGE_NAME
sudo systemctl restart ACTUAL_SERVING_SERVICE

# RPM example: select the vendor-approved package/channel first.
sudo dnf upgrade PACKAGE_NAME
sudo systemctl restart ACTUAL_SERVING_SERVICE
```

For FPM, restart every affected FPM service. For mod_php, restart Apache. For LiteSpeed, FrankenPHP, or custom services, follow the product's restart/redeploy procedure. Restart all affected workers; a graceful reload is insufficient until all old workers have drained and exited. Updating a separate CLI installation does not remediate the web handler.

### Containers

Update the Dockerfile/base image or build inputs to a verified fixed build, rebuild, and record the resulting digest. Redeploy the workload with that digest; do not rely on an unchanged mutable tag or patch only an ephemeral running container. Update scheduled workloads and deployment templates too. Observe rollout completion, confirm every serving replica uses the new digest, and ensure old replicas are no longer receiving requests.

### Vendor bundles and hosted services

Install the vendor's product update or obtain deployment confirmation from the provider. Follow required reboot/restart steps and record the resulting product build. Source builds need documented patch provenance and a reproducible build/deployment record covering both CVEs; otherwise retain `unknown`.

## 3. Verify the running build and close records

For every backend, collect fresh evidence after the change:

- Exact installed package revision, vendor channel, image digest, or appliance build, with advisory evidence for both CVEs.
- Site-to-handler mapping still points to the intended runtime.
- New serving process identities and start times; no old affected workers remain. For mod_php, verify the loaded module as well as Apache's restart. For containers, verify the running replica image IDs against the approved digest.
- Runtime identity through the serving route, or equivalent process/build evidence that conclusively ties the worker to the patched artifact. If version strings cannot distinguish a backport, use full package revision and provenance.
- Application health checks: login, representative requests, uploads where used, background work, and error logs. Health alone is not security verification.
- Verifier, timestamp, evidence references, and any remaining gap.

Mark each CVE and aggregate status using [discovery section 3](PLAYBOOK.md#3-classify-and-prioritize). Set progress to `complete` only after verification; a missing observation leaves the record unresolved. Reconcile record coverage with the original asset list and NCSC product matches. Have a second operator review exceptions and the closure evidence for critical assets.

Maintain separate incident status. A patched runtime is not proof that no compromise occurred. Review suspicious file/account changes and telemetry under your incident-response process; preserve evidence and follow that process for recovery and secret rotation when compromise is suspected.

## 4. Return results to assessment

Attach before/after artifact identities, restart/redeploy evidence, health results, verifier, timestamps, and remaining gaps to the remediation record. Return results to the assessment owner for a fresh assessment; retain the pre-change baseline. Close only when all linked backends meet verification requirements. Explicitly report blocked or unknown backends.

Reconcile coverage against the discovery inventory, including dormant deployment templates and scheduled workloads. Keep incident-response status separate from patch completion.

## References and limitations

Consult the [PHP advisory](https://www.php.net/archive/2026.php#2026-10-21-5) and the exact product/vendor security notice. Commands require platform-specific adaptation and have not been tested against your environment. No production systems have been updated by this repository. Keep completed records private.
