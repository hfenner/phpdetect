# Disposable AWS PHP lab

`playbooks/build-lab-aws.yml` creates one Ubuntu 24.04 EC2 host in a dedicated CloudFormation stack, installs Docker, and deploys three fixtures. It is separate from discovery and remediation. All orchestration is Ansible YAML; there are no project Python scripts.

| Fixture | Runtime | Purpose | Expected container discovery status |
|---|---|---|---|
| vulnerable | PHP 8.4.26 Apache, pinned official image digest | Unpatched upstream PHP baseline | unknown |
| patched | PHP 8.4.27 Apache, pinned official image digest | Fixed upstream control | unknown |
| unmapped | PHP 8.4.26 Apache, pinned official image digest | Deliberately lacks a runtime mapping | unknown |

PHP's [advisory](https://www.php.net/archive/2026.php#2026-10-21-5) identifies 8.4.27 as fixed. The playbook verifies the PHP version actually serving HTTP for each fixture; fixture labels never override discovery's evidence policy. Container discovery currently inventories identities and optional CLI versions, so it intentionally retains unknown for all three. Use the optional vendor-package fixture below to test affected/patched runtime classification. No exploit payloads are included.

## Install the lab in AAP with Ansible

Run [`aap/install-lab.yml`](../aap/install-lab.yml) to configure AAP automatically. Copy [`aap/lab-site.example.yml`](../aap/lab-site.example.yml) to `aap/lab-site.yml` (gitignored) and set your gateway URL, organization ID, and existing AWS and Machine credential IDs. Supply a gateway-issued token using the `AAP_TOKEN` environment variable. The Machine credential must match the EC2 key pair you select when launching the build.

```sh
ansible-playbook -i localhost, aap/install-lab.yml -e @aap/lab-site.yml
```

The installer creates or updates:

- **phpdetect Lab EE**, using the pinned AWS-capable public image.
- **phpdetect Lab**, a separate Git project synchronized to the selected revision.
- **phpdetect Lab Bootstrap**, with a local-only bootstrap host.
- **phpdetect - Build AWS lab**, with the existing AWS and Machine credentials and a required launch survey.
- **phpdetect - Destroy AWS lab**, with only the AWS credential and its own deletion survey.

It checks credential types and that the synchronized project contains both lab playbooks. Rerunning reconciles these named resources and their credential associations. It does not create credentials, change production discovery/update templates, assign user roles, schedule jobs, launch AWS resources, or install a workflow linking creation to deletion. Grant the appropriate AAP teams Execute permission on these templates after setup. Do not launch Build and Destroy concurrently for the same lab ID; they are independent templates.

Optional `aap_lab_default_*` variables prefill the launch forms. The confirmation fields remain blank. `aap_lab_build_extra_vars` accepts only the instance type and optional reviewed vendor-package fixture. Registry credentials are optional for mirrored/private images; the public GHCR image needs none. Treat job artifacts as internal evidence.

The installer uses built-in Ansible HTTPS calls through the AAP 2.7 gateway; it needs organization resource-management permissions. Run it from a trusted workstation, or from an existing bootstrap AAP job with `AAP_TOKEN` injected by your secret-management integration. Its localhost Python path targets the supplied Python 3.12 EE. Check mode is rejected; it performs real AAP configuration changes when invoked.

## Run from AAP 2.7

Use an EE built after the AWS lab change: it includes `amazon.aws`, boto3, and botocore. Earlier pinned EE images do not include these dependencies. Update the EE digest and AAP Project revision to the lab-capable tested build.

Create a separate **Build PHP lab** job template using `playbooks/build-lab-aws.yml`, an inventory with localhost available, and both an **Amazon Web Services** credential and a **Machine** credential. The Machine credential must contain the private key matching an existing EC2 key pair in the chosen region; the guest login is `ubuntu`. No SSH private key is sent through variables or baked into an image. AWS authentication follows the normal SDK credential chain, including injected temporary session credentials.

Copy `lab/aws.example.yml` into private template extra variables, replace the key-pair name, region, and SSH CIDR, and supply `phpdetect_lab_confirm` equal to your lab ID at launch. The SSH CIDR must be the public egress address/range of the AAP execution node (/24 through /32); HTTP is not opened in the AWS security group. Do not use inventory limits or job slicing: the playbook adds its new host dynamically within the job.

The AWS credential needs permission to manage CloudFormation stacks and the EC2 resources in the inline template (VPC, subnet, route table, internet gateway, security group, instance, volume, and tags), describe key pairs/images, and read Canonical's public AMI parameter in SSM. No instance IAM role is created. Apply your organization's lab-account IAM policies; the playbook does not change IAM permissions.

For CLI use, install `requirements.yml`, supply AWS credentials and the matching SSH identity through your normal mechanisms, then run:

```sh
ansible-playbook -i localhost, playbooks/build-lab-aws.yml \
  -e @/private/path/aws-lab.yml -e phpdetect_lab_confirm=training
```

This creates billed AWS resources: one t3.small by default, a 16 GiB encrypted root disk, and a public IPv4 address. There is no NAT gateway or load balancer. The instance uses IMDSv2 and no IAM instance profile. PHP containers use an internal Docker network (172.30.77.0/24), read-only root filesystems, and resource limits. They publish no Docker host ports. A host-side nginx proxy binds only to loopback and forwards to their fixed internal addresses. Only a harmless JSON runtime endpoint is deployed.

## Discover and test updates

The build job retains the stack/instance identity before guest setup and publishes `phpdetect_lab.discovery_inventory` as an AAP job artifact when ready. Copy that inventory into a separate lab discovery inventory, use the same Machine credential, and run the existing Discover template. AAP's in-job `add_host` does not automatically persist hosts to its inventory database.

The VM also contains:

- `/opt/phpdetect-lab/discovery-vars.yml`: discovery host variables.
- `/opt/phpdetect-lab/compose.yml`: vulnerable starting fixture configuration.
- `/opt/phpdetect-lab/compose.fixed.yml`: same Compose project with the vulnerable service switched to the fixed digest.
- `/opt/phpdetect-lab/container-update-vars.yml`: separate remediation plan, with health checks delegated to the VM's loopback endpoint.

Copy the update variables to the lab host in your AAP inventory, run Plan updates, then Apply updates with change ID `lab-<your-lab-id>-fix`. This replaces only the `vulnerable` service. A later Build PHP lab run restores the vulnerable baseline deliberately. The Compose update test plan uses HTTP only on the VM loopback interface.

## Optional host package fixture

To also exercise the package classifier, supply the variables in `lab/package.example.yml` with **reviewed exact Ubuntu package revisions and vendor advisory evidence**. The placeholders are intentionally rejected before provisioning. The snapshot must contain the specified package revisions and their dependencies; unavailable versions fail rather than falling back to latest.

The builder adds a signed dated Ubuntu snapshot source, installs the explicit PHP 8.3 packages and nginx, serves PHP-FPM on `127.0.0.1:18080`, and verifies the full installed package revisions. It emits one vendor-mapped runtime and a second runtime deliberately lacking evidence. The latter must remain unknown. Patched classification also requires successful live-process verification; restricted procfs access must remain unknown. The host remains unknown unless an affected runtime is found.

The package fixture permits explicit downgrades and excludes PHP from unattended upgrades on this disposable VM. Explicit remediation still works. For package update testing, use the existing `inventory/runtime.example.yml` schema with reviewed fixed revisions and matching serving service names. The lab never fabricates vendor patch evidence from a version banner.

## Teardown

Use a separate job template for `playbooks/destroy-lab-aws.yml` with the AWS credential. Set the same region and lab ID, plus `phpdetect_lab_destroy_confirm` equal to that ID. It checks ownership tags, then deletes only `phpdetect-lab-<id>` and the stack's EC2 disk/network resources. The existing key pair is retained. There is no scheduled expiry: run teardown when finished, including after a failed guest configuration.

```sh
ansible-playbook -i localhost, playbooks/destroy-lab-aws.yml \
  -e @/private/path/aws-lab.yml -e phpdetect_lab_destroy_confirm=training
```

The CI workflow validates the CloudFormation template and exercises the actual pinned containers and discovery on an ephemeral GitHub runner. It does not create AWS resources or test the optional vendor-package installation against your selected snapshot.

Verified on source `f7135502d6f42d458a1a85b824151bdb5dac39d3`: [fixture integration and CloudFormation validation](https://github.com/hfenner/phpdetect/actions/runs/39849965763) and [EE build](https://github.com/hfenner/phpdetect/actions/runs/39849965579) passed. The matching immutable EE is `ghcr.io/hfenner/phpdetect-ee@sha256:6ad781c9268c864e6a21cb9a4c35619c68d8d0950fe107949b257ce7d5d25304`. AWS creation/teardown and your optional vendor-package snapshot have not been exercised against a live AWS account.
