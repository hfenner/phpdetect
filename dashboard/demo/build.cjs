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
fs.writeFileSync(path.join(out,'index.html'),html);
let js=fs.readFileSync(path.join(dashboard,'app.js'),'utf8');
js=js.replace('`AAP discovery${','`Demo snapshot${');
fs.writeFileSync(path.join(out,'app.js'),js);
fs.copyFileSync(path.join(dashboard,'styles.css'),path.join(out,'styles.css'));
fs.writeFileSync(path.join(out,'data.json'),JSON.stringify(sample,null,2)+'\n');
fs.writeFileSync(path.join(out,'.nojekyll'),'');
console.log('Built public demo with fictional data only.');
