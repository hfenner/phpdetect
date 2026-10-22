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
 ['Docker inventory', 'Enumerates containers and inspects image identity and running state. A container alone does not prove PHP is installed.'],
 ['Optional container PHP CLI probe', 'Runs php -n -v in running containers when enabled. Confirms CLI version evidence, not the serving build.'],
 ['Windows process-path discovery', 'Reads executable paths for running php.exe and php-cgi.exe processes using CIM.'],
 ['Windows common-path scan', 'Searches C:\\PHP, Program Files PHP directories, C:\\tools\\php and C:\\xampp\\php for php*.exe, to a bounded depth of two.'],
 ['Windows file inspection', 'Reads product/file versions and SHA-256 hashes without executing discovered binaries.'],
 ['IIS website inventory', 'Reads website names, physical paths and bindings. PHP handler and loaded-build verification are not implemented.'],
 ['NCSC product matching', 'Matches inventory-supplied product terms against the bundled snapshot. Does not automatically discover products or establish patch status.'],
 ['Vendor-evidence classification', 'Checks supplied advisory metadata, exact OS and package revisions, ownership and configured CVEs. Patched also requires verified live files. No automatic vendor-advisory retrieval.'],
 ['Coverage and connection checks', 'Preserves unreachable hosts, missing evidence and collection gaps as unknown. Discovery never establishes complete host clearance.']
];
function detectionFindings(hosts) {
  const findings=[];
  for (const h of hosts) {
    const add=(location,version,check,detail)=>findings.push({host:h.host,address:h.address || 'Not recorded',location,version:version || 'Not recorded',check,detail});
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
      add(c.name || c.id,text(e?.php_cli_version).match(/^PHP\s+(\S+)/)?.[1],e?'Docker inventory + PHP CLI probe':'Docker inventory only',e?'CLI PHP found inside container. Executable path and serving build not recorded.':'Container candidate; no PHP CLI evidence recorded. PHP presence unverified.');
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
if (typeof module!=='undefined') module.exports={normalize,statusOf,esc,detectionFindings,detectionChecks};
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
function renderDetection(){
const findings=detectionFindings(model.hosts);
$('detection-count').textContent=findings.length+' finding records';
$('detections').innerHTML=findings.map(r=>`<tr><td><b>${esc(r.host)}</b><span class="sub mono">${esc(r.address)}</span></td><td class="mono">${esc(r.location)}</td><td class="mono">${esc(r.version)}</td><td>${esc(r.check)}</td><td>${esc(r.detail)}</td></tr>`).join('') || '<tr><td colspan="5">No PHP location evidence recorded. Unassessed hosts remain unknown.</td></tr>';
$('detection-checks').innerHTML=detectionChecks.map(([name,description])=>`<tr><td><b>${esc(name)}</b></td><td>${esc(description)}</td></tr>`).join('');
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
