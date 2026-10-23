// Publish only this explicit asset allowlist and the explicitly approved report snapshot.
const fs=require('node:fs');
const path=require('node:path');
const assert=require('node:assert/strict');
const dashboard=path.resolve(__dirname,'..');
const out=path.resolve(dashboard,'../_site');
// Every presentation change must find its anchor; a silent no-op would publish the authenticated page's wording.
const must=(s,from,to)=>{assert.ok(s.includes(from),'Missing replacement anchor: '+String(from).slice(0,70));return s.replace(from,to);};
const sample=JSON.parse(fs.readFileSync(path.join(__dirname,'published-report.json'),'utf8'));
assert.equal(sample.publication,'user-approved-lab-snapshot');
assert.ok(sample.discovery.hosts.length>0);
assert.equal(sample.source.status,'successful');
fs.mkdirSync(out,{recursive:true});
assert.equal(fs.readdirSync(out).length,0,'Build destination must be empty');
let html=fs.readFileSync(path.join(dashboard,'index.html'),'utf8');
html=must(html,'OpenShift authenticated','Public lab report');
html=must(html,'OpenShift deployment','GitHub Pages report');
html=must(html,'<main>','<main><div class="notice" role="note"><b>PUBLIC LAB SNAPSHOT.</b> Real lab discovery evidence published with owner approval. This is a saved snapshot, not a live connection to AAP. Unknown findings are not cleared. <a href="https://github.com/hfenner/phpdetect">View repository</a>.</div>');
html=must(html,'Exposure overview</title>','Public lab report</title>');

// Render the reference directly into the front page, without a tab or disclosure.
const {detectionChecks,manualChecks,esc}=require('../app.js');
assert.equal(detectionChecks.length,manualChecks.length);
const {groups,guides}=require('./check-guides.cjs');
assert.equal(guides.length,detectionChecks.length);
assert.deepEqual(groups.flatMap(g=>g.indices).sort((a,b)=>a-b),detectionChecks.map((_,i)=>i));
const explain=i=>`<div class="script-guide"><b>How it works</b><ol>${guides[i].steps.map(step=>`<li>${esc(step)}</li>`).join('')}</ol><p><b>Limits:</b> ${esc(guides[i].limits)}</p></div>`;
const hostList=predicate=>sample.discovery.hosts.filter(predicate).map(h=>h.host+' ('+h.address+')').join('; ') || 'No target of this type in the snapshot';
const targetFor=i=>i>=13 ? 'Ansible control node or AAP execution environment — project checkout and your inventory' :
 i>=9 ? 'Windows target: '+hostList(h=>h.platform==='Windows') :
 i===7 || i===8 ? 'Container host (Podman preferred; engine recorded in evidence): '+hostList(h=>(h.containers || []).length>0) :
 'Linux target: '+hostList(h=>h.platform!=='Windows');
const checkRows=groups.map(g=>`<tr class="check-group"><th colspan="3" scope="colgroup"><h3>${esc(g.name)}</h3><p>${esc(g.intro)}</p></th></tr>`+g.indices.map(i=>`<tr><td><strong>${esc(detectionChecks[i][0])}</strong><p>${esc(detectionChecks[i][1])}</p></td><td>${esc(targetFor(i))}<p><b>Shell / access:</b> ${esc(manualChecks[i][0])}</p></td><td>${explain(i)}<b>Command to run</b><pre tabindex="0">${esc(manualChecks[i][1])}</pre><p><b>Expected output:</b> ${esc(manualChecks[i][2])}</p></td></tr>`).join('')).join('');
const reference=`<section id="manual-check-reference" class="public-reference"><h2>Checks, targets and manual commands</h2><p>All ${detectionChecks.length} checks are listed below. Run commands on the listed target using your authorized access, not on GitHub Pages. Hosts may have changed since collection. Replace example artifact paths, CONTAINER_ID and /path/to/inventory.yml before running. Root Bash means a root shell on the target; elevated PowerShell means Run as administrator. For Ansible commands, start in the phpdetect repository with its dependencies and target credentials available.</p><p>These commands collect evidence; they do not patch targets. The optional container probe executes PHP CLI inside the selected container. Advisory and coverage checks rerun the full discovery playbook with your inventory. Results can change between runs.</p><div class="table-wrap"><table><thead><tr><th>CHECK / PURPOSE</th><th>TARGET / REQUIRED ACCESS</th><th>MANUAL COMMAND / EXPECTED RESULT</th></tr></thead><tbody>${checkRows}</tbody></table></div></section>`;
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

const walkthroughRevision=process.env.GITHUB_SHA || 'main';
assert.match(walkthroughRevision,/^(main|[0-9a-f]{40})$/);
html=must(html,'<button class="nav" data-view="evidence">','<button class="nav" data-view="walkthrough">☷ <span>Playbook walkthrough</span></button><button class="nav" data-view="evidence">');
html=must(html,'<footer>',require('./walkthrough.cjs')(walkthroughRevision)+'<footer>');
html=html.replace('</head>','<style>.walk-intro{padding:12px 24px;font-size:14px}.walk-intro p{margin:12px 0}.walk-phase{border-top:1px solid var(--line);padding:18px 24px}.walk-phase>summary{font-size:17px;font-weight:650;color:var(--teal);cursor:pointer}.walk-steps{padding-left:25px;max-width:1100px}.walk-steps>li{padding:12px 0 20px 8px;border-bottom:1px solid var(--line)}.walk-steps h4{font-size:15px;margin:0 0 8px}.walk-steps p{line-height:1.7}.walk-source{display:inline-block;font-size:12px;margin-top:9px}.walk-branch{padding:15px;background:#f4f8f7;margin-top:15px}.walk-branch>summary{cursor:pointer;font-weight:600}.sidebar nav{overflow:auto}@media(max-width:720px){.sidebar nav{flex-wrap:wrap}.nav{width:auto;flex:1 1 28%}}</style></head>');

html=must(html,'<footer>','<div hidden><span id="hosts-count"></span><span id="affected-count"></span><span id="unknown-count"></span><span id="runtime-count"></span></div><footer>');
let js=fs.readFileSync(path.join(dashboard,'app.js'),'utf8');
js=must(js,"source.status && source.status!=='successful'", "source.status && source.status!=='fictional sample' && source.status!=='successful'");
const start=js.indexOf('function render(){');
const end=js.indexOf('function renderVersions()',start);
assert.ok(start>=0 && end>start);
js=js.slice(0,start)+'const checkGroups='+JSON.stringify(groups)+';\nconst checkGuides='+JSON.stringify(guides)+';\n'+fs.readFileSync(path.join(__dirname,'host-view.js'),'utf8')+'\n'+js.slice(end);
// Apply the same grouping and explanations to the Detection methods catalog.
const catalogStart=js.indexOf("$('detection-checks').innerHTML=");
const catalogEnd=js.indexOf("\n}",catalogStart);
assert.ok(catalogStart>=0 && catalogEnd>catalogStart);
js=js.slice(0,catalogStart)+"$('detection-checks').innerHTML=checkGroups.map(g=>`<tr class=\"check-group\"><th colspan=\"2\"><h3>${esc(g.name)}</h3><p>${esc(g.intro)}</p></th></tr>`+g.indices.map(i=>`<tr><td><b>${esc(detectionChecks[i][0])}</b></td><td>${guideMarkup(i)}${manualMarkup({where:manualChecks[i][0],command:manualChecks[i][1],expect:manualChecks[i][2]})}</td></tr>`).join('')).join('');"+js.slice(catalogEnd);
html=html.replace('</head>','<style>.check-group th{background:#e0f2e9!important;white-space:normal;letter-spacing:normal;text-transform:none}.check-group h3{font-size:18px;margin:0 0 6px}.check-group p{font-size:13px}.script-guide{font-size:13px;line-height:1.65}.script-guide ol{padding-left:22px;margin:10px 0}.script-guide li{margin:8px 0}.script-guide p{margin:12px 0}</style></head>');
fs.writeFileSync(path.join(out,'app.js'),js);
const version=require('node:crypto').createHash('sha256').update(js).digest('hex').slice(0,12);
html=must(html,'src="app.js"','src="app.js?v='+version+'"');
fs.writeFileSync(path.join(out,'index.html'),html);
fs.copyFileSync(path.join(dashboard,'styles.css'),path.join(out,'styles.css'));
fs.writeFileSync(path.join(out,'data.json'),JSON.stringify(sample,null,2)+'\n');
fs.writeFileSync(path.join(out,'.nojekyll'),'');
console.log('Built public report from the owner-approved discovery snapshot only.');
