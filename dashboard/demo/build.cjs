// Publish only this explicit asset allowlist and the fictional demo fixture.
const fs=require('node:fs');
const path=require('node:path');
const assert=require('node:assert/strict');
const dashboard=path.resolve(__dirname,'..');
const out=path.resolve(dashboard,'../_site');
const sample=JSON.parse(fs.readFileSync(path.join(__dirname,'sample.json'),'utf8'));
assert.equal(sample.demo,true);
for(const host of sample.discovery.hosts){
  assert.match(host.host,/^demo-/);
  assert.match(host.address,/^192\.0\.2\.[0-9]+$/);
}
fs.mkdirSync(out,{recursive:true});
assert.equal(fs.readdirSync(out).length,0,'Build destination must be empty');
let html=fs.readFileSync(path.join(dashboard,'index.html'),'utf8');
html=html.replace('OpenShift authenticated','Public demo · Fictional data')
 .replace('OpenShift deployment','GitHub Pages demo')
 .replace('<main>','<main><div class="notice" role="note"><b>PUBLIC DEMO — FICTIONAL DATA.</b> Hosts, versions, findings and patch-status examples are illustrative, not vendor advisories or live assessments. <a href="https://github.com/hfenner/phpdetect">View repository</a>.</div>')
 .replace('Exposure overview</title>','Public demo</title>');

// Render the reference directly into the front page, without a tab or disclosure.
const {detectionChecks,manualChecks,esc}=require('../app.js');
assert.equal(detectionChecks.length,manualChecks.length);
const targetFor=i=>i>=13 ? 'Ansible control node or AAP execution environment — project checkout and your inventory' :
 i>=9 ? 'Windows target — sample: demo-windows-01 (192.0.2.21)' :
 i===7 || i===8 ? 'Docker host — sample: demo-containers-01 (192.0.2.31)' :
 'Linux target — samples: demo-linux-01 (192.0.2.11), demo-linux-02 (192.0.2.12)';
const checkRows=detectionChecks.map(([name,description],i)=>`<tr><td><strong>${esc(name)}</strong><p>${esc(description)}</p></td><td>${esc(targetFor(i))}<p><b>Shell / access:</b> ${esc(manualChecks[i][0])}</p></td><td><pre tabindex="0">${esc(manualChecks[i][1])}</pre><p>${esc(manualChecks[i][2])}</p></td></tr>`).join('');
const reference=`<section id="manual-check-reference" class="public-reference"><h2>Checks, targets and manual commands</h2><p>All ${detectionChecks.length} checks are listed below. Sample hosts and addresses are fictional: run commands on your own corresponding target, not on GitHub Pages. Replace example artifact paths, CONTAINER_ID and /path/to/inventory.yml before running. Root Bash means a root shell on the target; elevated PowerShell means Run as administrator. For Ansible commands, start in the phpdetect repository with its dependencies and target credentials available.</p><p>These commands collect evidence; they do not patch targets. The optional Docker probe executes PHP CLI inside the selected container. Advisory and coverage checks rerun the full discovery playbook with your inventory. Results can change between runs.</p><div class="table-wrap"><table><thead><tr><th>CHECK / PURPOSE</th><th>TARGET / REQUIRED ACCESS</th><th>MANUAL COMMAND / EXPECTED RESULT</th></tr></thead><tbody>${checkRows}</tbody></table></div></section>`;
html=html.replace('<main>',`<main><section class="public-repo"><h1>phpdetect on GitHub</h1><p>Source code, Ansible playbooks, execution environment and deployment workflows.</p><a class="repo-url" href="https://github.com/hfenner/phpdetect">github.com/hfenner/phpdetect ↗</a><p><a href="#manual-check-reference">Jump to all ${detectionChecks.length} checks, targets and manual commands ↓</a></p></section>`)
 .replace('<footer>',reference+'<footer>')
 .replace('</head>',`<style>.public-repo{margin:24px 0;padding:24px;background:#e0f2e9;border:1px solid #a7cfc1;border-radius:10px}.public-repo h1{font-size:26px}.repo-url{display:inline-block;font-size:22px;font-weight:700;margin:12px 0;overflow-wrap:anywhere}.public-reference{margin:30px 0;background:white;border:1px solid var(--line);border-radius:10px;padding:24px;scroll-margin-top:20px}.public-reference>p{margin:12px 0}.public-reference table{table-layout:fixed;white-space:normal;min-width:850px}.public-reference th:nth-child(1){width:23%}.public-reference th:nth-child(2){width:25%}.public-reference td{vertical-align:top;overflow-wrap:anywhere}.public-reference pre{max-height:300px;overflow:auto;white-space:pre-wrap}.public-reference th,.public-reference td{padding:16px}</style></head>`);
assert.equal((reference.match(/<pre /g)||[]).length,16);
// Keep the initial page focused on the host rollup; the reference remains available.
html=html.replace('<section class="public-repo"><h1>phpdetect on GitHub</h1><p>Source code, Ansible playbooks, execution environment and deployment workflows.</p>', '<section class="public-repo"><b>phpdetect · Community proof of concept</b>')
 .replace(/<p><a href="#manual-check-reference">Jump to all .*?<\/a><\/p>/, '')
 .replace('<h1>Exposure overview</h1>','<h1>PHP detection by host</h1>')
 .replace('Know where PHP runs. See what still needs attention.','Expand a host to inspect each detection check, its evidence and manual command.')
 .replace(/<section class="metrics"[\s\S]*?<\/section>/,'')
 .replace('<h2>Hosts &amp; runtimes</h2>','<h2>Hosts</h2>')
 .replace('<h2>Hosts & runtimes</h2>','<h2>Hosts</h2>')
 .replace('Internet-facing records are shown first.','One row per host. Use the + control to expand its detection checks.')
 .replace('<th>HOST / RUNTIME</th><th>PHP / PACKAGE VERSION</th><th>PATCH STATUS</th><th>EXPOSURE</th><th>EVIDENCE</th>','<th>HOST / ADDRESS</th><th>HOST STATUS</th><th>RUNTIMES</th><th>OBSERVED VERSIONS</th><th>CHECK COVERAGE</th>')
 .replace('<option value="patched">Patched runtime</option>','')
 .replace(reference,'<details id="manual-check-reference" class="reference-disclosure"><summary>All checks and manual commands — reference</summary>'+reference.replace('id="manual-check-reference"','id="full-check-reference"')+'</details>')
 .replace('</head>','<style>.public-repo{margin:16px 0;padding:12px 18px;display:flex;flex-wrap:wrap;align-items:center;gap:16px}.repo-url{font-size:17px;margin:0}.heading{margin:20px 0}.host-summary td{white-space:normal;overflow-wrap:anywhere}.host-summary td:first-child{min-width:210px}.host-check-cell{white-space:normal;background:#f7fafa;padding:24px}.host-check-table{table-layout:fixed;white-space:normal;min-width:800px}.host-check-table td{vertical-align:top;overflow-wrap:anywhere}.host-check-table th:nth-child(1){width:24%}.host-check-table th:nth-child(2){width:36%}.host-check-table pre{max-height:300px;overflow:auto}.host-check-table details{margin-top:12px}.host-check-table summary,.reference-disclosure>summary{cursor:pointer;color:var(--teal);font-weight:600}.reference-disclosure{margin:25px 0}.host-expand{font-size:14px;text-align:left}.host-check-cell>p{margin-bottom:15px}</style></head>');

html=html.replace('<footer>','<div hidden><span id="hosts-count"></span><span id="affected-count"></span><span id="unknown-count"></span><span id="runtime-count"></span></div><footer>');
let js=fs.readFileSync(path.join(dashboard,'app.js'),'utf8');
js=js.replace('`AAP discovery${','`Demo snapshot${')
 .replace("source.status && source.status!=='successful'", "source.status && source.status!=='fictional sample' && source.status!=='successful'");
const start=js.indexOf('function render(){');
const end=js.indexOf('function renderVersions()',start);
assert.ok(start>=0 && end>start);
js=js.slice(0,start)+fs.readFileSync(path.join(__dirname,'host-view.js'),'utf8')+'\n'+js.slice(end);
fs.writeFileSync(path.join(out,'app.js'),js);
const version=require('node:crypto').createHash('sha256').update(js).digest('hex').slice(0,12);
html=html.replace('src="app.js"','src="app.js?v='+version+'"');
fs.writeFileSync(path.join(out,'index.html'),html);
fs.copyFileSync(path.join(dashboard,'styles.css'),path.join(out,'styles.css'));
fs.writeFileSync(path.join(out,'data.json'),JSON.stringify(sample,null,2)+'\n');
fs.writeFileSync(path.join(out,'.nojekyll'),'');
console.log('Built public demo with fictional data only.');
