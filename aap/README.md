# AAP 2.7 preparation

This is an unofficial PoC, not Red Hat-provided or certified content. The custom Linux amd64 EE uses public UBI 9, Python 3.12, Ansible Core 2.19 and Ansible Runner. It does not require a Red Hat registry login. Compatibility tests run inside the image; an actual AAP 2.7 installation must still be validated in your environment.

## Verified build

[Build 39849965579](https://github.com/hfenner/phpdetect/actions/runs/39849965579) passed all in-image checks, including the Runner job-artifact test. The [public repository-linked package](https://github.com/hfenner/phpdetect/pkgs/container/phpdetect-ee) is available without registry credentials. `site.example.yml` pins this tested pair:

- Source: `f7135502d6f42d458a1a85b824151bdb5dac39d3`
- Image: `ghcr.io/hfenner/phpdetect-ee@sha256:6ad781c9268c864e6a21cb9a4c35619c68d8d0950fe107949b257ce7d5d25304`
- Architecture: Linux amd64.

This build also includes the AWS collection and SDK dependencies needed by the [AWS lab builder](../lab/README.md). Its container fixtures passed [integration testing](https://github.com/hfenner/phpdetect/actions/runs/39849965763); no live AWS resources were provisioned during validation.

## Image


The [build workflow](../.github/workflows/build-ee.yml) builds with Ansible Builder 3, runs classification, package parsing, syntax and Linux discovery checks as UID 1000, then publishes to the repository-linked GHCR package `ghcr.io/hfenner/phpdetect-ee`. Tags are `aap2.7` and `sha-<source commit>`. Use the **immutable digest** from the successful workflow summary or its `phpdetect-ee-build` artifact in AAP. The source checkout is supplied by the AAP Project, not baked into the EE. Inventory and credentials are never included in the image.

The base and dependency patch releases are resolved at build time. Rebuild to incorporate fixes; a digest identifies the exact tested image. Local build: `ansible-builder build --container-runtime podman -t ghcr.io/hfenner/phpdetect-ee:aap2.7`. Dependencies on managed hosts (Python, apt/dnf bindings, Podman/podman-compose for new labs; Docker Compose for the alternative update adapter) remain host prerequisites.

## Install configuration with Ansible

1. In AAP, prepare an organization, a Machine credential, and an inventory containing the group `php_targets` and your Linux targets. Use the repository's example runtime and update variables as schemas for private inventory host variables. Do not import `tests/local.yml` into AAP: that would scan the EE itself.
2. Copy `aap/site.example.yml` to `aap/site.yml`. Set the **platform gateway** URL and the existing organization, inventory, and Machine credential IDs. Set the published image digest and preferably the tested source commit. For a private image, set an existing Container Registry credential ID; public images need none.
3. Supply a gateway-issued token in the `AAP_TOKEN` environment variable using your secret manager or a silent shell prompt. Never place it in Git or command-line extra variables. The installer requires trusted HTTPS certificates and organization permissions to manage the resources. For a private CA, configure the installer host's trust store.
4. Run `ansible-playbook -i localhost, aap/install.yml -e @aap/site.yml` from the repository root. It uses built-in Ansible modules and the gateway's `/api/controller/v2/` API. It registers/updates the EE, synchronizes the project, attaches the existing Machine credential, and creates three independent templates. It launches no target jobs and creates no schedules or automatic discovery-to-update workflow.

Templates:

| Template | Behavior |
|---|---|
| phpdetect - Discover | Read-only discovery; saves evidence to job artifacts. |
| phpdetect - Plan updates | Separate update playbook in check mode; no restart or deployment. |
| phpdetect - Apply updates | Separate update playbook in run mode; required change-ID survey must match every targeted host's plan. |

Use a scoped inventory for each rollout. Job slicing and limit prompts are disabled because discovery must execute its localhost initialization and final aggregation. If a template is customized to accept limits, every discovery limit must include `localhost`. Keep localhost implicit/local and do not attach remote connection variables to it. Apply `phpdetect_become` to target hosts as needed; do not enable blanket template-level escalation that also affects localhost tasks.

Grant discovery access to investigators; restrict the apply-updates template to change operators. The installer does not modify your existing roles or credential permissions. A failed verification stops the serial update rollout. Hosts without valid update plans fail preflight.

## Evidence and operational checks

Templates set `phpdetect_publish_job_artifacts: true`. Discovery writes `phpdetect_discovery`, including per-host evidence and the NCSC commit, using `set_stats` with `per_host: false`. An initial incomplete/unknown artifact is written before connections. Updates append completed or blocked host results under `phpdetect_updates`; absent entries, aborted jobs, and unreachable hosts must be treated as unknown. Check-mode updates remain unknown.

These artifacts are retained with the AAP job, visible to users allowed to read that job, and may contain internal hostnames, package lists, paths, and routing hints. Apply your normal job permissions and retention policy. They are not public GitHub artifacts. Temporary JSON files inside the EE are ephemeral; copy/export job artifacts to your private evidence store before AAP job cleanup. Large inventories should be split into scoped inventories to bound job-artifact size. Discovery data is not passed automatically to an update job.

Validate a discovery job against a non-production Linux host first. Confirm the inventory connection, retained artifacts, unknown states for incomplete evidence, and the pinned EE digest. Then test the separate update-plan template before authorizing any update. No production update or live AAP installation is exercised by the public build workflow.

References: [Ansible Builder definition](https://docs.ansible.com/projects/builder/en/latest/definition/), [AAP 2.7 execution environments](https://docs.redhat.com/en/documentation/red_hat_ansible_automation_platform/2.7/administer-define__create__and_build_execution_environments), [AAP 2.7 API changes](https://docs.redhat.com/en/documentation/red_hat_ansible_automation_platform/2.7/upgrade-con_upgrade_api_changes_27).

## Install AWS lab job templates

Use [install-lab.yml](install-lab.yml) with [lab-site.example.yml](lab-site.example.yml) to register the dedicated lab EE, project, bootstrap inventory, and separate Build/Destroy templates with launch surveys. See [the automated lab setup](../lab/README.md#install-the-lab-in-aap-with-ansible). This installer does not require the discovery inventory or launch AWS jobs.
