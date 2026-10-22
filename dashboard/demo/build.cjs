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

let js=fs.readFileSync(path.join(dashboard,'app.js'),'utf8');
js=js.replace('`AAP discovery${','`Demo snapshot${')
 .replace("source.status && source.status!=='successful'", "source.status && source.status!=='fictional sample' && source.status!=='successful'");
fs.writeFileSync(path.join(out,'app.js'),js);
const version=require('node:crypto').createHash('sha256').update(js).digest('hex').slice(0,12);
html=html.replace('src="app.js"','src="app.js?v='+version+'"');
fs.writeFileSync(path.join(out,'index.html'),html);
fs.copyFileSync(path.join(dashboard,'styles.css'),path.join(out,'styles.css'));
fs.writeFileSync(path.join(out,'data.json'),JSON.stringify(sample,null,2)+'\n');
fs.writeFileSync(path.join(out,'.nojekyll'),'');
console.log('Built public demo with fictional data only.');
