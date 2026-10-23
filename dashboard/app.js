'use strict';
const statusOf = x => ['affected','patched','unknown'].includes(x) ? x : 'unknown';
const array = x => Array.isArray(x) ? x : [];
const text = x => x == null ? '' : typeof x === 'object' ? JSON.stringify(x) : String(x);
const esc = x => text(x).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

const detectionChecks = [
 ['Linux package inventory', 'Reads dpkg/RPM package names and full revisions. A package record alone is not a separate running PHP instance.'],
 ['Linux common-path scan', 'Finds PHP-named ELF files in standard binary directories, selected Plesk/cPanel directories, and Apache module directories. Does not execute candidates.'],
 ['Linux process-name scan', 'Records PHP, Apache, httpd and FrankenPHP process-name clues; a web-server process alone does not prove PHP is loaded.'],
 ['Linux foreign-root scan', 'Finds PHP/FrankenPHP executable paths in processes whose root differs from the host, such as containers or chroots.'],
 ['Explicit runtime mapping and package ownership', 'Uses inventory-supplied artifact paths, resolves symlinks, and queries dpkg/RPM ownership. This is a configured mapping, not an automatic site mapping.'],
 ['Linux live-file inspection', 'Checks mapped executables/modules and loaded file identities through /proc for current files, stale/deleted files and visibility gaps.'],
 ['Nginx and Apache configuration', 'Collects routing and virtual-host clues; does not prove a complete site-to-PHP mapping.'],
 ['Podman container inventory', 'Uses Podman first; Docker is a supported alternative. Records image identity and running state in the selected user context. A container alone does not prove PHP is installed.'],
 ['Optional container PHP CLI probe', 'Runs php -n -v in running containers when enabled. Confirms CLI version evidence, not the serving build.'],
 ['Windows process-path discovery', 'Reads executable paths for running php.exe and php-cgi.exe processes using CIM.'],
 ['Windows common-path scan', 'Searches C:\\PHP, Program Files PHP directories, C:\\tools\\php and C:\\xampp\\php for php*.exe, to a bounded depth of two.'],
 ['Windows file inspection', 'Reads product/file versions and SHA-256 hashes without executing discovered binaries.'],
 ['IIS website inventory', 'Reads website names, physical paths and bindings. PHP handler and loaded-build verification are not implemented.'],
 ['NCSC product matching', 'Matches inventory-supplied product terms against the bundled snapshot. Does not automatically discover products or establish patch status.'],
 ['Vendor-evidence classification', 'Checks supplied advisory metadata, exact OS and package revisions, ownership and configured CVEs. Patched also requires verified live files. No automatic vendor-advisory retrieval.'],
 ['Coverage and connection checks', 'Preserves unreachable hosts, missing evidence and collection gaps as unknown. Discovery never establishes complete host clearance.']
];
const liveInspection = "set -o pipefail\n[ \"$(id -u)\" = 0 ] || { echo 'gap|-|not running as root'; exit 3; }\n[ -f \"$PHPDETECT_ARTIFACT\" ] || { echo 'gap|-|artifact is not a regular file'; exit 3; }\nhost_root=$(stat -Lc '%d:%i' /) || { echo 'gap|-|cannot stat host root'; exit 3; }\ngaps=0\nfor proc in /proc/[0-9]*; do\n  pid=${proc##*/}\n  exe=$(readlink \"$proc/exe\" 2>/dev/null) || {\n    [ -d \"$proc\" ] || continue\n    command_line=$(tr '\\0' ' ' < \"$proc/cmdline\" 2>/dev/null) || {\n      [ -d \"$proc\" ] || continue\n      printf 'gap|%s|cannot read cmdline\\n' \"$pid\"; gaps=1; continue\n    }\n    [ -n \"$command_line\" ] || continue\n    comm=$(tr -d '|\\n' < \"$proc/comm\" 2>/dev/null)\n    printf 'gap|%s|cannot read executable link (%s)\\n' \"$pid\" \"${comm:-unknown}\"; gaps=1; continue\n  }\n  process_root=$(stat -Lc '%d:%i' \"$proc/root\" 2>/dev/null) || {\n    [ -d \"$proc\" ] || continue\n    printf 'gap|%s|cannot stat process root\\n' \"$pid\"; gaps=1; continue\n  }\n  [ \"$process_root\" = \"$host_root\" ] || continue\n  maps=$(cat \"$proc/maps\" 2>/dev/null) || {\n    [ -d \"$proc\" ] || continue\n    printf 'gap|%s|cannot read memory maps\\n' \"$pid\"; gaps=1; continue\n  }\n  matched=0\n  [ \"${exe% (deleted)}\" = \"$PHPDETECT_ARTIFACT\" ] && matched=1\n  awk -v path=\"$PHPDETECT_ARTIFACT\" '$6 == path { found=1 } END { exit !found }' <<< \"$maps\" && matched=1\n  [ \"$matched\" = 1 ] || continue\n  current=true\n  if [ \"${exe% (deleted)}\" = \"$PHPDETECT_ARTIFACT\" ]; then\n    [ \"$exe\" = \"$PHPDETECT_ARTIFACT\" ] || current=false\n    [ \"$(stat -Lc '%d:%i' \"$proc/exe\")\" = \"$(stat -Lc '%d:%i' \"$PHPDETECT_ARTIFACT\")\" ] || current=false\n  fi\n  while read -r region perms offset dev inode path; do\n    case \"$path\" in\n      /memfd:*|/dev/*|/SYSV*|/anon_hugepage*|/\\[*|/i915*|/drm*|/tmp/*|/var/tmp/*|/run/*) continue ;;\n      /*)\n        case \"$path\" in *' (deleted)') current=false; continue ;; esac\n        major=$((16#${dev%:*})); minor=$((16#${dev#*:}))\n        device=$(( (minor & 255) | ((major & 4095) << 8) | ((minor & ~255) << 12) | ((major & ~4095) << 32) ))\n        [ \"$(stat -Lc '%d:%i' \"$proc/root$path\" 2>/dev/null)\" = \"$device:$inode\" ] || current=false\n        ;;\n    esac\n  done <<< \"$maps\"\n  printf '%s|%s\\n' \"$pid\" \"$current\"\ndone\n[ \"$gaps\" = 0 ] || exit 3\nexit 0\n";
const windowsCollector = "$ErrorActionPreference = 'Stop'\n$gaps = [System.Collections.Generic.List[string]]::new()\n$processes = @(Get-CimInstance Win32_Process -Filter \"Name = 'php.exe' OR Name = 'php-cgi.exe'\" | Select-Object ProcessId,Name,ExecutablePath)\n$files = [System.Collections.Generic.List[string]]::new()\nforeach ($p in $processes) { if ($p.ExecutablePath) { $files.Add($p.ExecutablePath) } else { $gaps.Add('A PHP process executable path was inaccessible') } }\nforeach ($root in @('C:\\PHP','C:\\Program Files\\PHP','C:\\Program Files (x86)\\PHP','C:\\tools\\php','C:\\xampp\\php')) {\n  if (Test-Path $root) {\n    try { Get-ChildItem $root -Filter 'php*.exe' -File -Recurse -Depth 2 -ErrorAction Stop | ForEach-Object { $files.Add($_.FullName) } }\n    catch { $gaps.Add(\"Cannot enumerate $root\") }\n  }\n}\n$sites = @()\nif (Get-Module -ListAvailable WebAdministration) {\n  try {\n    Import-Module WebAdministration\n    $sites = @(Get-Website | ForEach-Object { @{name=$_.Name;path=$_.PhysicalPath;bindings=@($_.Bindings.Collection | ForEach-Object { $_.bindingInformation })} })\n  } catch { $gaps.Add('IIS configuration could not be read') }\n}\n$runtimes = @($files | Sort-Object -Unique | ForEach-Object {\n  $path = $_\n  try {\n    $f = Get-Item -LiteralPath $path\n    $live = @($processes | Where-Object { $_.ExecutablePath -eq $path } | ForEach-Object { @{pid=$_.ProcessId;executable=$_.ExecutablePath} })\n    @{id=$path;artifact=$path;version=$f.VersionInfo.ProductVersion;package_owner='';patch_status='unknown';exposure='unknown';priority='P1';running_build_verified=$false;processes=$live;sites=@();evidence=@{sha256=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLower();file_version=$f.VersionInfo.FileVersion};reason='Native Windows PHP found. Vendor patch evidence, serving-site mapping, and loaded-build identity are not verified.'}\n  } catch { $gaps.Add(\"Cannot inspect $path\") }\n})\n$gaps.Add('Windows discovery covers running PHP executables and common installation paths only; bundled products and arbitrary paths may be missed')\n$os = Get-CimInstance Win32_OperatingSystem\n@{platform='Windows';os_release=@{ID='windows';VERSION_ID=$os.Version;PRETTY_NAME=$os.Caption};package_manager='unknown';php_packages=@{};runtimes=$runtimes;containers=@();container_cli_evidence=@();products=@();routing_hints=$sites;patch_status='unknown';gaps=@($gaps.ToArray());scope_note='Windows native file/process inventory is evidence only; it does not establish patch status or complete host coverage.'} | ConvertTo-Json -Depth 12 -Compress\n";
const manualChecks = [
  [
    "Linux shell; package-query access",
    "cat /etc/os-release\nif command -v dpkg-query >/dev/null; then\n  dpkg-query -W '-f=${binary:Package}|${Version}|${db:Status-Status}\\n'\nelse\n  rpm -qa --qf '%{NAME}|%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\\n'\nfi",
    "Look for PHP package records. The collector reads the full database to establish ownership and approved package revisions."
  ],
  [
    "Bash on the Linux target",
    "(\nset -o pipefail\nfor directory in /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin \\\n  /opt/plesk/php/*/sbin /opt/cpanel/ea-php*/root/usr/sbin \\\n  /usr/lib/apache2/modules /usr/lib64/httpd/modules; do\n  [ -d \"$directory\" ] || continue\n  find \"$directory\" -maxdepth 1 \\( -type f -o -type l \\) -iname '*php*' -print |\n    while IFS= read -r candidate; do\n      magic=$(od -An -tx1 -N4 \"$candidate\" 2>/dev/null | tr -d ' \\n')\n      [ \"$magic\" != '7f454c46' ] || printf '%s\\n' \"$candidate\"\n    done\ndone\n)",
    "Each output line is a PHP-named ELF candidate path; no output does not prove PHP is absent."
  ],
  [
    "Linux shell",
    "ps -eo 'pid=,comm=' | grep -Ei 'php|apache|httpd|franken'",
    "PID and process-name clues; Apache/httpd alone does not establish PHP presence."
  ],
  [
    "Root Bash on the Linux target",
    "(\nset -o pipefail\nhost_root=$(stat -Lc '%d:%i' /) || exit 3\nfor proc in /proc/[0-9]*; do\n  exe=$(readlink \"$proc/exe\" 2>/dev/null) || continue\n  case \"$exe\" in\n    *php*|*franken*)\n      process_root=$(stat -Lc '%d:%i' \"$proc/root\" 2>/dev/null) || continue\n      [ \"$process_root\" = \"$host_root\" ] || printf '%s|%s\\n' \"${proc##*/}\" \"$exe\"\n      ;;\n  esac\ndone\n)",
    "Output PID|path identifies another process root; correlate with containers or chroots separately."
  ],
  [
    "Linux shell; replace the artifact path",
    "artifact='/absolute/path/to/php'\nresolved=$(readlink -f -- \"$artifact\")\nprintf '%s\\n' \"$resolved\"\nif command -v dpkg-query >/dev/null; then dpkg-query -S \"$resolved\"; else rpm -qf --qf '%{NAME}\\n' \"$resolved\"; fi",
    "Returns the package owner for the configured artifact, not an automatically discovered website mapping."
  ],
  [
    "Root Bash on the Linux target; replace PHPDETECT_ARTIFACT",
    "PHPDETECT_ARTIFACT='/absolute/path/to/php'\n(\n" + liveInspection + ")",
    "Exact live-file loop from the playbook, run in a subshell so its exit codes end the subshell rather than your session. PID|true means current files; PID|false means stale/mismatched files; gap lines or exit 3 mean incomplete visibility. This is not vendor patch confirmation."
  ],
  [
    "Privileged Linux shell",
    "sudo nginx -T 2>/dev/null | grep -E '^\\s*(server_name|fastcgi_pass|proxy_pass)\\s' | grep -v '@'\nfor tool in apachectl apache2ctl httpd; do\n  command -v \"$tool\" >/dev/null && sudo \"$tool\" -S\ndone",
    "Routing/virtual-host clues. Missing tools or access failures are gaps, not absence of PHP."
  ],
  [
    "Shell on the container host, as the account owning the containers",
    "engine=podman # Docker alternative: engine=docker\n\"$engine\" ps -aq --no-trunc | while IFS= read -r id; do\n  \"$engine\" inspect --format '{{.Id}} {{.Name}} {{.Image}} {{.Config.Image}} {{.State.Running}}' \"$id\"\ndone",
    "Lists container identity, image and running state. Use the same engine and user as discovery. Rootless Podman containers are visible only to their owning user. This does not establish PHP presence."
  ],
  [
    "Shell on the container host, as the container owner; replace container ID",
    "engine=podman # Docker alternative: engine=docker\n\"$engine\" exec 'CONTAINER_ID' php -n -v",
    "Executes PHP CLI in the selected running container. This is supporting evidence, not serving-build or patch verification."
  ],
  [
    "Elevated Windows PowerShell",
    "Get-CimInstance Win32_Process -Filter \"Name = 'php.exe' OR Name = 'php-cgi.exe'\" | Select-Object ProcessId,Name,ExecutablePath",
    "Lists current PHP process paths and IDs. Empty/inaccessible paths are visibility gaps."
  ],
  [
    "Elevated Windows PowerShell",
    "foreach ($root in @('C:\\PHP','C:\\Program Files\\PHP','C:\\Program Files (x86)\\PHP','C:\\tools\\php','C:\\xampp\\php')) {\n  if (Test-Path $root) { Get-ChildItem $root -Filter 'php*.exe' -File -Recurse -Depth 2 -ErrorAction Continue | Select-Object -ExpandProperty FullName }\n}",
    "Bounded common-path scan; arbitrary and bundled locations can be missed."
  ],
  [
    "Elevated Windows PowerShell; replace the file path",
    "$path = 'C:\\PHP\\php.exe'\n(Get-Item -LiteralPath $path).VersionInfo | Select-Object ProductVersion,FileVersion\nGet-FileHash -LiteralPath $path -Algorithm SHA256",
    "Reads file metadata and hash without executing the candidate. Does not establish the loaded build or vendor patch status."
  ],
  [
    "Elevated Windows PowerShell with WebAdministration",
    "Import-Module WebAdministration\nGet-Website | ForEach-Object { [pscustomobject]@{ Name=$_.Name; Path=$_.PhysicalPath; Bindings=@($_.Bindings.Collection | ForEach-Object { $_.bindingInformation }) } } | ConvertTo-Json -Depth 5",
    "IIS site paths and bindings; this does not verify a PHP handler mapping."
  ],
  [
    "Ansible control node / project checkout with the existing inventory",
    "ansible-playbook -i /path/to/inventory.yml playbooks/discover.yml",
    "Use the same phpdetect_products inventory entries and bundled NCSC snapshot. Inspect products[].ncsc_matches in summary.json. This reruns discovery, not remediation."
  ],
  [
    "Ansible control node / project checkout with vendor evidence in inventory",
    "ansible-playbook -i /path/to/inventory.yml playbooks/discover.yml",
    "Use the same phpdetect_runtimes evidence. Inspect runtimes[].patch_status, reason, processes and visibility_gaps. No standalone version command can reproduce this policy decision."
  ],
  [
    "Ansible control node / project checkout with the complete target inventory",
    "ansible-playbook -i /path/to/inventory.yml playbooks/discover.yml",
    "Inspect every host result and gaps, including unreachable seeded hosts. This reruns all applicable discovery checks; output is saved to the private report directory printed by Ansible."
  ]
];

const shQuote = value => "'" + text(value).replace(/'/g, "'\"'\"'") + "'";
const psQuote = value => "'" + text(value).replace(/'/g, "''") + "'";
function manualFinding(h,location,check,containerId,containerEngine) {
  if(h.platform==='Windows')return {where:'Elevated PowerShell on '+h.host,command:'& {\n'+windowsCollector+'}\n# Inspect the recorded file directly (it may have moved since discovery).\n$path = '+psQuote(location)+'\n(Get-Item -LiteralPath $path).VersionInfo | Select-Object ProductVersion,FileVersion\nGet-FileHash -LiteralPath $path -Algorithm SHA256',expect:'Reruns the complete native collector and inspects this file. Compare JSON runtimes, processes, version and hash; per-file original discovery provenance remains unavailable in older reports.'};
  const engine=['podman','docker'].includes(containerEngine)?containerEngine:(check.startsWith('Docker')?'docker':'podman');
  if(check.startsWith('Docker') || check.startsWith('Podman') || check.startsWith('Container'))return {where:'Shell with '+engine+' access on '+h.host+' as the container owner',command:engine+' inspect --format '+shQuote('{{.Id}} {{.Name}} {{.Image}} {{.Config.Image}} {{.State.Running}}')+' '+shQuote(containerId)+'\n'+(check.includes('probe')?engine+' exec '+shQuote(containerId)+' php -n -v':'# No PHP CLI probe was recorded for this container.'),expect:'Compare identity and optional CLI version with the snapshot. A removed/replaced container ID will fail; do not silently substitute another container.'};
  if(check.includes('foreign-root'))return {where:'Root Bash on '+h.host,command:manualChecks[3][1],expect:'Find the recorded PID/path again if it is still running. PIDs may change or be reused.'};
  const ownership='artifact='+shQuote(location)+'\nresolved=$(readlink -f -- "$artifact")\nprintf "%s\\n" "$resolved"\nif command -v dpkg-query >/dev/null; then dpkg-query -S "$resolved"; else rpm -qf --qf \'%{NAME}\\n\' "$resolved"; fi\n';
  return {where:(check.startsWith('Explicit')?'Root Bash':'Bash')+' on '+h.host,command:manualChecks[1][1]+'\n# Inspect the recorded artifact.\n'+ownership+(check.startsWith('Explicit')?'PHPDETECT_ARTIFACT="$resolved"\n(\n'+liveInspection+')\n':''),expect:check.startsWith('Explicit')?'Compare the located path, package owner and PID|current results. Current files alone do not establish patch status.':'Find this path in the scan output. Ownership is supplemental evidence; no serving-runtime or version classification is inferred.'};
}
function detectionFindings(hosts) {
  const findings=[];
  for (const h of hosts) {
    const add=(location,version,check,detail,containerId,containerEngine)=>findings.push({host:h.host,address:h.address || 'Not recorded',location,version:version || 'Not recorded',check,detail,manual:manualFinding(h,location,check,containerId,containerEngine)});
    for (const r of array(h.runtimes)) {
      const location=r.artifact || r.id;
      if(h.platform==='Windows') {
        const live=array(r.processes).length>0;
        add(location,r.version,'Windows native file collector',live ? 'Process-path match recorded; directory scan may also have found this file. File version and SHA-256 recorded.' : 'Common-path/process collector result; original per-file discovery source was not recorded. No matching live process recorded.');
      } else {
        const pkg=h.php_packages?.[r.package_owner];
        add(location,typeof pkg==='string'?pkg:pkg?.version,'Explicit runtime mapping' + (array(h.candidates).includes(location)?' + common-path scan':''), 'Package owner: '+(r.package_owner || 'unverified')+'. Live-file inspection: '+array(r.processes).length+' matching processes.');
      }
    }
    for(const path of array(h.candidates)) {
      if(array(h.runtimes).some(r=>r.artifact===path))continue;
      add(path,'','Linux common-path scan','PHP-named ELF candidate. Not mapped or assessed as a serving runtime; may be a symlink/alias.');
    }
    for(const c of array(h.containers)) {
      const e=array(h.container_cli_evidence).find(e=>e.container_id===c.id);
      add(c.name || c.id,text(e?.php_cli_version).match(/^PHP\s+(\S+)/)?.[1],(c.engine==='docker'?'Docker alternative':c.engine==='podman'?'Podman':'Container')+(e?' inventory + PHP CLI probe':' inventory only'),e?'CLI PHP found inside container. Executable path and serving build not recorded.':'Container candidate; no PHP CLI evidence recorded. PHP presence unverified.',c.id,c.engine || h.container_engine);
    }
    for(const c of array(h.foreign_runtime_candidates))add(c.process_and_artifact,'','Linux foreign-root scan','PID and executable path in another process root. May overlap container findings; not a distinct confirmed installation.');
  }
  return findings;
}

function normalize(input) {
  const d = input.discovery || input.artifacts?.phpdetect_discovery || input.phpdetect_discovery || input;
  if (!Array.isArray(d.hosts) || !d.hosts.every(h => h && typeof h === 'object' && typeof h.host === 'string')) throw Error('Expected a phpdetect discovery report with a hosts array.');
  const lab = input.lab || {}; const rows=[];
  for (const h of d.hosts) {
    const host = h.host; const hostStatus = statusOf(h.patch_status);
    const common = {host, hostStatus, address: h.address || lab.discovery_inventory?.all?.children?.php_targets?.hosts?.[host]?.ansible_host || 'Not recorded', hostEvidence:h};
    for (const r of array(h.runtimes)) {
      const pkg = h.php_packages?.[r.package_owner];
      const version = pkg?.version || pkg?.Version || (typeof pkg==='string' ? pkg : '') || r.version || r.evidence?.packages?.[r.package_owner] || 'Not recorded';
      rows.push({...common,id:text(r.id || r.artifact || 'Mapped runtime'),kind:h.platform==='Windows'?'Native executable':'Mapped runtime',version:text(version),status:statusOf(r.patch_status),exposure:['internet','internal'].includes(r.exposure)?r.exposure:'unknown',reason:r.reason || 'No assessment reason recorded',evidence:r});
    }
    for (const c of array(h.containers)) {
      const evidence=array(h.container_cli_evidence).find(e=>e.container_id===c.id);
      const version=text(evidence?.php_cli_version).match(/^PHP\s+(\S+)/)?.[1] || 'Not recorded';
      const fixture=array(lab.fixtures).find(f=>text(c.name).includes('-'+f.name+'-'));
      rows.push({...common,id:text(c.name || c.id),kind:'Container',version,status:'unknown',exposure:'unknown',reason:'CLI version is supporting evidence only. Serving runtime mapping and vendor patch evidence are not verified.',fixture:fixture?.intent,evidence:{...c,...evidence}});
    }
    if (!array(h.runtimes).length && !array(h.containers).length) rows.push({...common,id:'Host assessment',kind:'Host',version:'Not recorded',status:hostStatus==='affected'?'affected':'unknown',exposure:'unknown',reason:array(h.gaps).join('; ') || 'No mapped runtime evidence; coverage remains unknown.',evidence:h});
  }
  const order={internet:0,unknown:1,internal:2}; rows.sort((a,b)=>order[a.exposure]-order[b.exposure] || (a.status==='affected'?-1:0)-(b.status==='affected'?-1:0) || a.host.localeCompare(b.host));
  return {hosts:d.hosts,rows,discovery:d,source:input.source || {job:input.job || input.id,status:input.status,finished:input.finished},generated_at:input.generated_at};
}
if (typeof module!=='undefined') module.exports={normalize,statusOf,esc,detectionFindings,detectionChecks,manualChecks,manualFinding,shQuote,psQuote};
if (typeof document!=='undefined') {
let model,filtered=[];const $=id=>document.getElementById(id);
function badge(s){return `<span class="badge ${s}">● ${s[0].toUpperCase()+s.slice(1)}</span>`}
function setReport(data,imported=false){model=normalize(data);$('hosts-count').textContent=model.hosts.length;$('affected-count').textContent=model.hosts.filter(h=>h.patch_status==='affected').length;$('unknown-count').textContent=model.hosts.filter(h=>h.patch_status!=='affected').length;$('runtime-count').textContent=model.rows.filter(r=>r.kind!=='Host').length;
const source=model.source;const date=source.finished || model.generated_at; const stamp=date && !Number.isNaN(Date.parse(date))?new Date(date).toLocaleString(): 'Time not recorded';
$('source').textContent=imported?'Browser-local report · '+stamp:`AAP discovery${source.job?' · Job '+source.job:''} · ${source.status || model.discovery.status || 'Status not recorded'} · ${stamp}`;
$('age').textContent=date && Date.now()-Date.parse(date)>86400000?'Older than 24 hours · Refresh evidence':'Snapshot, not a live scan';
$('provenance').innerHTML=[['Discovery job',source.job || 'Not recorded'],['Job status',source.status || model.discovery.status || 'Not recorded'],['Completed',stamp],['Report coverage',model.discovery.status || 'Not recorded'],['NCSC snapshot',model.discovery.ncsc_commit || 'Not recorded']].map(([k,v])=>`<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`).join('');
$('message').textContent=source.status && source.status!=='successful'?'This discovery job did not finish successfully. Results may be incomplete; unassessed hosts remain unknown.':'';
render();renderVersions();renderDetection();}
function manualMarkup(m){return `<details><summary>Manual reproduction</summary><p><b>Run in:</b> ${esc(m.where)}</p><pre tabindex="0">${esc(m.command)}</pre><p>${esc(m.expect)}</p></details>`;}
function renderDetection(){
const findings=detectionFindings(model.hosts);
$('detection-count').textContent=findings.length+' finding records';
$('detections').innerHTML=findings.map(r=>`<tr><td><b>${esc(r.host)}</b><span class="sub mono">${esc(r.address)}</span></td><td class="mono">${esc(r.location)}</td><td class="mono">${esc(r.version)}</td><td>${esc(r.check)}</td><td>${esc(r.detail)}${manualMarkup(r.manual)}</td></tr>`).join('') || '<tr><td colspan="5">No PHP location evidence recorded. Unassessed hosts remain unknown.</td></tr>';
$('detection-checks').innerHTML=detectionChecks.map(([name,description],i)=>`<tr><td><b>${esc(name)}</b></td><td>${esc(description)}${manualMarkup({where:manualChecks[i][0],command:manualChecks[i][1],expect:manualChecks[i][2]})}</td></tr>`).join('');
}
function render(){if(!model)return;const q=$('search').value.toLowerCase();filtered=model.rows.filter(r=>(!q || [r.host,r.address,r.id,r.version,r.kind].join(' ').toLowerCase().includes(q)) && ($('status').value==='all'||r.status===$('status').value) && ($('exposure').value==='all'||r.exposure===$('exposure').value));$('result-count').textContent=filtered.length+' records';$('empty').hidden=filtered.length>0;
$('rows').innerHTML=filtered.map((r,i)=>`<tr><td><div class="hostname">${esc(r.host)}</div><span class="sub mono">${esc(r.address)}</span><span class="sub">${esc(r.id)}</span></td><td><span class="mono">${esc(r.version)}</span><span class="sub">${esc(r.kind)}${r.fixture?' · Lab fixture':''}</span></td><td>${badge(r.status)}</td><td>${r.exposure==='internet'?'Internet-facing':r.exposure==='internal'?'Internal':'Unknown'}<span class="sub">${r.kind==='Container'?'Mapping unverified':esc(r.kind)}</span></td><td><button class="linkbutton" data-detail="${i}">View evidence ↗</button></td></tr>`).join('');}
function renderVersions(){const groups=new Map();for(const r of model.rows){if(!groups.has(r.version))groups.set(r.version,{hosts:new Set(),count:0,affected:0,unknown:0,patched:0});const g=groups.get(r.version);g.hosts.add(r.host);g.count++;g[r.status]++;}$('versions').innerHTML=[...groups].map(([v,g])=>`<tr><td class="mono">${esc(v)}</td><td>${g.hosts.size}</td><td>${g.count}</td><td>${g.affected}</td><td>${g.unknown}</td><td>${g.patched}</td></tr>`).join('') || '<tr><td colspan="6">No versions recorded.</td></tr>';}
async function refresh(){const b=$('refresh');b.disabled=true;try{const response=await fetch('data.json',{cache:'no-store',credentials:'same-origin'});if(!response.ok)throw Error('Could not load deployed report ('+response.status+').');setReport(await response.json());$('import-status').textContent='';}catch(e){$('message').textContent=e.message+' The last displayed snapshot has been retained.';}finally{b.disabled=false;}}
$('refresh').onclick=refresh;['search','status','exposure'].forEach(id=>$(id).addEventListener('input',render));
document.querySelectorAll('[data-view]').forEach(b=>b.onclick=()=>{document.querySelectorAll('.view').forEach(v=>v.hidden=v.id!==b.dataset.view+'-view');document.querySelectorAll('.nav').forEach(n=>n.classList.toggle('active',n===b));});
$('rows').onclick=e=>{const b=e.target.closest('[data-detail]');if(!b)return;const r=filtered[Number(b.dataset.detail)];$('detail-content').innerHTML=`<h3>${esc(r.host)} / ${esc(r.id)}</h3>${badge(r.status)}<p>${esc(r.reason)}</p>${r.fixture?`<p>Lab intent: ${esc(r.fixture)}. This label does not establish patch status.</p>`:''}<dl><dt>Host status</dt><dd>${esc(r.hostStatus)}</dd><dt>Version evidence</dt><dd>${esc(r.version)}</dd><dt>Coverage gaps</dt><dd>${esc(array(r.hostEvidence.gaps).join('; ') || 'No collector gaps recorded; full runtime coverage is still not proven.')}</dd></dl><h3>Recorded evidence</h3><pre>${esc(JSON.stringify(r.evidence,null,2))}</pre>`;$('details').showModal();};$('close').onclick=()=>$('details').close();
$('import').onchange=async e=>{try{const f=e.target.files[0];if(!f)return;if(f.size>10000000)throw Error('Report exceeds the 10 MB browser import limit.');setReport(JSON.parse(await f.text()),true);$('import-status').textContent='Loaded in this browser session only.';}catch(e){$('import-status').textContent=e.message;}};
$('export').onclick=()=>{if(!model)return;const cell=x=>'"'+text(x).replace(/^[=+@\-\t\r]/,"'$&").replace(/"/g,'""')+'"';const csv=[['Host','Address','Runtime','Version','Patch status','Exposure','Reason'],...filtered.map(r=>[r.host,r.address,r.id,r.version,r.status,r.exposure,r.reason])].map(row=>row.map(cell).join(',')).join('\r\n');const a=document.createElement('a');a.href=URL.createObjectURL(new Blob([csv],{type:'text/csv;charset=utf-8'}));a.download='phpdetect-inventory.csv';a.click();setTimeout(()=>URL.revokeObjectURL(a.href),500);};refresh();
}
