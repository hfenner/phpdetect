const assert = require('node:assert/strict');
const {normalize,esc}=require('../dashboard/app.js');
const host={host:'web01',patch_status:'affected',php_packages:{'php-fpm':{version:'8.3.6-0ubuntu0.24.04.1'}},runtimes:[{id:'main',package_owner:'php-fpm',patch_status:'affected',exposure:'internet'}],containers:[{id:'container1',name:'php',patch_status:'patched'}],container_cli_evidence:[{container_id:'container1',php_cli_version:'PHP 8.4.27 (cli)'}]};
const result=normalize({artifacts:{phpdetect_discovery:{hosts:[host]}}});
assert.equal(result.rows[0].status,'affected');
assert.equal(result.rows[0].version,'8.3.6-0ubuntu0.24.04.1');
assert.equal(result.rows[1].status,'unknown','Container version must never establish clearance');
assert.equal(result.rows[1].version,'8.4.27');
const missing=normalize({hosts:[{host:'unreachable',gaps:['Connection failed']}]});
assert.equal(missing.rows[0].status,'unknown');
assert.match(missing.rows[0].reason,/Connection failed/);
assert.equal(normalize({hosts:[{host:'empty',patch_status:'patched'}]}).rows[0].status,'unknown','Host-wide clearance cannot be inferred');
assert.throws(()=>normalize({fixtures:[]}),/discovery report/);
assert.equal(esc('<img src=x onerror=alert(1)>'),'&lt;img src=x onerror=alert(1)&gt;');
console.log('Dashboard evidence handling checks passed.');
const windows=normalize({hosts:[{host:'windows01',platform:'Windows',patch_status:'unknown',runtimes:[{id:'C:\\PHP\\php-cgi.exe',version:'8.4.27',patch_status:'unknown'}]}]});
assert.equal(windows.rows[0].version,'8.4.27');
assert.equal(windows.rows[0].status,'unknown');
const {detectionFindings,detectionChecks}=require('../dashboard/app.js');
const findings=detectionFindings([{host:'rhel',runtimes:[{artifact:'/usr/sbin/php-fpm',processes:[{pid:1}]}],candidates:['/usr/bin/php','/usr/sbin/php-fpm'],containers:[{id:'no-probe',name:'unverified'}]}]);
assert.equal(findings.length,3,'Mapped path is not duplicated as a candidate');
assert.match(findings[0].check,/mapping.*common-path/);
assert.match(findings[1].detail,/candidate/);
assert.match(findings[2].detail,/PHP presence unverified/);
assert.match(detectionFindings([{host:'win',platform:'Windows',runtimes:[{artifact:'C:\\PHP\\php.exe',processes:[]}]}])[0].detail,/source was not recorded/);
assert.ok(detectionChecks.length>=16);
const {manualChecks,manualFinding,shQuote,psQuote}=require('../dashboard/app.js');
const {spawnSync}=require('node:child_process');
assert.equal(manualChecks.length,detectionChecks.length,'Every check needs reproduction instructions');
for (const i of [0,1,2,3,4,5,6,7,8,13,14,15]) {
  const result=spawnSync('bash',['-n'],{input:manualChecks[i][1],encoding:'utf8'});
  assert.equal(result.status,0,result.stderr);
}
const hostile="/opt/php'; $(touch /tmp/should-not-run) #";
const quoted=spawnSync('bash',['-c','printf %s '+shQuote(hostile)],{encoding:'utf8'});
assert.equal(quoted.stdout,hostile,'Report paths must stay literal shell data');
assert.equal(psQuote("C:\\Bob's\\php.exe"),"'C:\\Bob''s\\php.exe'");
const mapped=manualFinding({host:'rhel'},hostile,'Explicit runtime mapping');
assert.equal(spawnSync('bash',['-n'],{input:mapped.command,encoding:'utf8'}).status,0);
const container=manualFinding({host:'linux'},'/display-name','Docker inventory + PHP CLI probe','abc123');
assert.match(container.command,/docker exec 'abc123' php -n -v/);
assert.doesNotMatch(container.command,/display-name/);
assert.ok(detectionFindings([host]).every(f=>f.manual.command));
// Pasting a command into an interactive shell must never end the session. With an empty PATH every
// external command fails, so each exit path is exercised; the trailing echo proves the shell survived.
const survives=command=>spawnSync('bash',['-c','PATH=/nonexistent; eval "$1" >/dev/null 2>&1; echo alive','_',command],{encoding:'utf8'}).stdout.includes('alive');
for (const i of [0,1,2,3,4,5,6,7,8,13,14,15]) assert.ok(survives(manualChecks[i][1]),'manual check '+i+' ended the shell');
for (const check of ['Explicit runtime mapping','Linux common-path scan','Linux foreign-root scan']) assert.ok(survives(manualFinding({host:'h'},'/usr/sbin/php-fpm',check).command),check+' finding ended the shell');
assert.ok(survives(manualFinding({host:'h'},'/x','Docker inventory + PHP CLI probe','abc').command));
assert.match(manualFinding({host:'w',platform:'Windows'},'C:\\PHP\\php.exe','x').command,/^& \{\n/,'Windows collector runs in a script block so preferences do not leak');
console.log('Manual reproduction coverage, quoting and Bash syntax checks passed.');

const podman=manualFinding({host:'linux'},'/php','Podman inventory + PHP CLI probe','xyz','podman');
assert.match(podman.command,/podman exec 'xyz' php -n -v/);
const legacyDocker=manualFinding({host:'linux'},'/php','Docker alternative inventory + PHP CLI probe','xyz','docker');
assert.match(legacyDocker.command,/docker exec 'xyz' php -n -v/);
assert.match(manualChecks[7][1],/engine=podman/);

const productHost={host:'products',platform:'Windows',products:[{identity_status:'file_signature_match',product:{name:'WordPress',version:'6.8.1'},location:'C:\\inetpub\\wwwroot',check:'Windows product file signatures',evidence_files:['wp-includes/version.php','wp-settings.php'],patch_status:'patched'}]};
const productFinding=detectionFindings([productHost])[0];
assert.match(productFinding.detail,/PHP patch status: unknown/);
assert.match(productFinding.manual.command,/ansible-playbook/);
assert.match(productFinding.detail,/not a separate PHP runtime/);
assert.equal(normalize({hosts:[productHost]}).rows.length,1,'Product identity must not inflate PHP runtime counts');

// The scripts the dashboard tells operators to run must be byte-identical to the scripts the playbooks run.
const fs=require('node:fs');
const path=require('node:path');
const {liveInspection,windowsCollector}=require('../dashboard/app.js');
const taskBlock=(file,taskName,key)=>{
  const lines=fs.readFileSync(path.join(__dirname,'..',file),'utf8').split('\n');
  const task=lines.findIndex(l=>l.trim().startsWith('- name: '+taskName));
  assert.ok(task>=0,taskName+' not found in '+file);
  const start=lines.findIndex((l,i)=>i>task && l.trim()===key+': |');
  assert.ok(start>=0,key+' block scalar missing for '+taskName);
  const indent=lines[start].search(/\S/)+2;
  const body=[];
  for(const l of lines.slice(start+1)){ if(l.trim()==='' || l.startsWith(' '.repeat(indent))) body.push(l.slice(indent)); else break; }
  while(body.length && body[body.length-1]==='') body.pop();
  return body.join('\n')+'\n';
};
assert.equal(liveInspection,taskBlock('playbooks/tasks/assess-runtime.yml','Inspect all live instances','ansible.builtin.shell'),'liveInspection drifted from assess-runtime.yml');
assert.equal(windowsCollector,taskBlock('playbooks/tasks/collect-windows.yml','Collect native Windows PHP','ansible.builtin.raw'),'windowsCollector drifted from collect-windows.yml');
assert.equal(manualChecks[1][1],'(\n'+taskBlock('playbooks/tasks/collect.yml','Find common PHP installations','ansible.builtin.shell')+')','common-path manual command drifted from collect.yml');
assert.equal(manualChecks[3][1],'(\n'+taskBlock('playbooks/tasks/collect.yml','Identify PHP executables under a different process root','ansible.builtin.shell')+')','foreign-root manual command drifted from collect.yml');
console.log('Embedded scripts match the playbook task files.');
