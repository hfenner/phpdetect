# OpenShift dashboard

Community proof of concept, not official vendor-provided code. The dashboard displays detector evidence; it does not independently establish vulnerability or clear hosts.

`playbooks/deploy-dashboard.yml` deploys the page, report Secret, service account, OAuth proxy, service-serving certificate, and re-encrypt HTTPS Route in a dedicated `phpdetect` namespace. It uses only built-in Ansible modules and works in the existing execution environment. The namespace must be absent or labeled `app.kubernetes.io/part-of: phpdetect`; unrelated namespaces are rejected.

The page supports host/version search, patch-status and exposure filters, version aggregation, per-runtime evidence, filtered CSV export, and browser-local report import. Full package revisions are retained when provided. Container CLI versions never establish clearance. Lab intent is shown separately from assessment. Unreachable host seeds remain unknown.

## Deploy or refresh with Ansible

Supply `K8S_AUTH_HOST`, `K8S_AUTH_API_KEY`, and optionally `K8S_AUTH_SSL_CA_CERT` (path to the cluster CA) through protected credentials. TLS verification is enabled. Initial installation requires permission to create the namespace and manage its application resources. Do not commit credentials or live report files.

Choose one report source:

- `dashboard_report_file`: a private JSON file with `discovery` containing the phpdetect discovery artifact and optional `source: {job, status, finished}` and `lab` fields.
- `dashboard_aap_url` and `dashboard_aap_job_id`: an explicit discovery job. Supply `AAP_TOKEN` using a protected read credential. The playbook retrieves `artifacts.phpdetect_discovery` and its job provenance. No AAP credentials are sent to the browser.

```sh
ansible-playbook -i localhost, playbooks/deploy-dashboard.yml \
  -e dashboard_aap_url=https://controller.example.com \
  -e dashboard_aap_job_id=123
```

For AAP, use a localhost inventory and an execution environment containing ansible-core, attach protected credentials injecting those environment variables, and select `playbooks/deploy-dashboard.yml`. Launch discovery separately, then publish its explicit job ID. The resulting URL is preserved in `phpdetect_dashboard_url` job artifacts.

This is an explicitly published snapshot, not an automatic scan or live AAP API proxy. **Refresh snapshot** reloads the deployed report; rerun the deployment playbook with a newer discovery job to update it. ConfigMap updates may take approximately a minute to reach the pod. Browser imports are session-only and are never uploaded. Reports exceeding the Kubernetes ConfigMap size limit require a different storage backend.

## Access

Users sign in through OpenShift and must have permission to `get` the `phpdetect-dashboard` service in the `phpdetect` namespace. The report itself is stored in the `phpdetect-dashboard-report` Secret rather than a ConfigMap, so the namespace `view` role cannot read it through the API; only the proxy path and accounts with Secret read access in the namespace can reach it. Cluster administrators already have it. No broad reader role or anonymous access is created. The OAuth flow asks only for `user:info` and `user:check-access`. Service-serving certificates protect the router-to-pod connection. The app uses the restricted security context and does not need a privileged SCC.

The default OAuth proxy image is pinned to a digest tested on OpenShift 4.20. Override `dashboard_proxy_image` with an appropriate supported image for another cluster. The deployment needs the cluster's Red Hat registry pull access.

Run `node tests/dashboard.cjs` to verify conservative evidence handling and output escaping.

## Public GitHub Pages report

https://hfenner.github.io/phpdetect/ serves the owner-approved discovery snapshot in `demo/published-report.json`. This includes real lab host addresses, versions and detection evidence from AAP job 30. It is public, with no login required, and is not a live feed from AAP.

The `deploy-demo.yml` workflow rebuilds the page when dashboard files change on main. Its build copies only index.html, app.js, styles.css and the explicitly approved report into `_site`. It has no AAP or OpenShift credentials and does not fetch fresh reports. Updating discovery data requires an intentional update of the published snapshot. Lab provisioning output and credentials are excluded.

The fictional fixture remains in `demo/sample.json` for testing and examples. JSON imports stay local to the browser session; refresh restores the published report.
