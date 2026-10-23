const fs=require('node:fs');
const path=require('node:path');
const assert=require('node:assert/strict');
const files=require('./walkthrough.json');
const {esc}=require('../app.js');
module.exports=function walkthrough(revision){
  // Fail the build if task names or source lines drift from the documented version.
  for(const [name,file] of Object.entries(files)){
    const lines=fs.readFileSync(path.join(__dirname,'../..',file.path),'utf8').split('\n');
    const tasks=lines.filter(line=>(name==='discover.yml'?/^ +\- name:/:/^\s*- name:/).test(line));
    assert.equal(tasks.length,file.tasks.length,'Walkthrough task count: '+name);
    for(const task of file.tasks)assert.equal(lines[task.line-1].trim(),'- name: '+task.name,'Walkthrough source drift: '+task.name);
  }
  function source(file,task){return `https://github.com/hfenner/phpdetect/blob/${revision}/${file.path}#L${task.line}`;}
  function taskList(name,start=0,end=files[name].tasks.length){
    const file=files[name];
    return `<ol class="walk-steps">${file.tasks.slice(start,end).map(task=>{
      let children='';
      if(task.name==='Discover products and attach NCSC advisory references')children=taskList('products.yml');
      if(task.name==='Inspect each supported product signature without executing application files')children=taskList('product-files.yml');
      if(task.name==='Normalize each container product probe')children=taskList('product-container.yml');
      if(task.name==='Attach NCSC references and runtime associations to discovered products')children=taskList('product-match.yml');
      if(task.name==='Parse the installed package database')children=taskList('parse-packages.yml');
      if(task.name==='Assess each explicitly mapped runtime')children=taskList('assess-runtime.yml');
      if(task.name==='Evaluate vendor and running-build evidence')children=taskList('classify.yml');
      if(task.name==='Collect package, process, runtime, and container evidence')children='<details class="walk-branch" open><summary>Linux branch — expand included tasks</summary>'+taskList('collect.yml')+'</details>';
      if(task.name==='Collect native Windows PHP evidence')children='<details class="walk-branch" open><summary>Windows branch — alternative collector</summary>'+taskList('collect-windows.yml')+'</details>';
      return `<li><h4>${esc(task.name)}</h4><p>${esc(task.description)}</p><a class="walk-source" href="${source(file,task)}">${esc(file.path)} · line ${task.line} ↗</a>${children}</li>`;
    }).join('')}</ol>`;
  }
  const total=Object.values(files).reduce((n,f)=>n+f.tasks.length,0);
  return `<section id="walkthrough-view" class="view" hidden><div class="section-title"><div><h2>Discovery playbook walkthrough</h2><p>${total} named tasks, including nested collectors and classification, in playbook order.</p></div></div><div class="walk-intro"><p><b>Entry point:</b> <a href="https://github.com/hfenner/phpdetect/blob/${revision}/playbooks/discover.yml">playbooks/discover.yml</a>. This explains the repository revision used to build this page, not a task-by-task execution trace of the published AAP job.</p><p><b>Flow:</b> Prepare reports on the controller → collect evidence on each target through its Linux or Windows branch → match products and save each host → assemble the controller report.</p><p><b>Inputs:</b> php_targets inventory, connection settings, optional phpdetect_runtimes mappings and vendor evidence, product roots and optional phpdetect_products declarations, and the bundled NCSC snapshot. Enable phpdetect_publish_job_artifacts to retain results in AAP; phpdetect_container_cli_probe enables the optional container PHP command; phpdetect_product_container_probe enables read-only product file checks inside running containers.</p><p>Branches and loops run only when their conditions apply. Tasks are ordered per host, while Ansible can work on multiple hosts concurrently. Discovery performs no patch installation or service restart; it uses normal temporary Ansible transport and writes reports on the controller. Remediation remains a separate playbook.</p></div><details class="walk-phase" open><summary>1. Prepare the run — controller / AAP execution environment</summary>${taskList('discover.yml',0,6)}</details><details class="walk-phase"><summary>2. Collect and assess — each host in php_targets</summary><p class="walk-intro">The Linux and Windows collectors below are alternatives. Product matching and saving the host result follow the selected collector.</p>${taskList('discover.yml',6,10)}</details><details class="walk-phase"><summary>3. Assemble and retain the report — controller</summary>${taskList('discover.yml',10)}</details><div class="walk-intro"><b>Result interpretation:</b> affected requires matching vendor evidence; patched additionally requires verified live Linux files. Incomplete evidence stays unknown. Windows and container inventory currently cannot establish patched status, and a patched runtime never clears its entire host.</div></section>`;
};
