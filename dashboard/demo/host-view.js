function guideMarkup(i){return `<div class="script-guide"><b>How it works</b><ol>${checkGuides[i].steps.map(step=>`<li>${esc(step)}</li>`).join('')}</ol><p><b>Limits:</b> ${esc(checkGuides[i].limits)}</p></div>`;}
// Inserted into the dashboard's browser scope by the public demo builder.
function hostChecks(h) {
  const windows=h.platform==='Windows';
  const indices=windows?[9,10,11,12,13,14,15]:[0,1,2,3,4,5,6,7,8,13,14,15];
  return indices.map(i=>{
    let records=[];
    if(i===0) records=Object.entries(h.php_packages || {}).map(([k,v])=>k+': '+text(v));
    if(i===1) records=array(h.candidates);
    if(i===2) records=array(h.process_candidates);
    if(i===3) records=array(h.foreign_runtime_candidates).map(x=>x.process_and_artifact);
    if(i===4) records=array(h.runtimes).map(r=>(r.artifact || r.id)+' → '+(r.package_owner || 'Owner not recorded'));
    if(i===5) records=array(h.runtimes).flatMap(r=>array(r.processes).map(p=>(r.artifact || r.id)+' · PID '+p.pid+' · current: '+text(p.current)));
    if(i===6 || i===12) records=array(h.routing_hints).map(text);
    if(i===7) records=array(h.containers).map(c=>(c.name || c.id)+' · '+c.image_reference);
    if(i===8) records=array(h.container_cli_evidence).map(c=>c.container_id+' · '+c.php_cli_version);
    if(i===9) records=array(h.runtimes).flatMap(r=>array(r.processes).map(p=>(r.artifact || r.id)+' · PID '+p.pid));
    if(i===10) records=array(h.runtimes).map(r=>(r.artifact || r.id)+' · Original directory/process discovery source not recorded');
    if(i===11) records=array(h.runtimes).map(r=>(r.artifact || r.id)+' · '+(r.version || 'Version not recorded')+' · SHA-256: '+(r.evidence?.sha256 || 'Not recorded'));
    if(i===13) records=array(h.products).map(text);
    if(i===14) records=array(h.runtimes).map(r=>(r.artifact || r.id)+' · '+statusOf(r.patch_status)+' · '+(r.reason || 'No assessment reason recorded'));
    if(i===15) records=array(h.gaps);
    return {i,records,target:i>=13?'Control node / AAP execution environment; inventory scope: '+h.host:h.host+' · '+(h.address || 'Address not recorded')};
  });
}
function render(){
  if(!model)return;
  const q=$('search').value.toLowerCase();
  const selected=model.hosts.filter(h=>{
    const rows=model.rows.filter(r=>r.host===h.host);
    return (!q || [h.host,h.address,...rows.flatMap(r=>[r.id,r.version,r.kind])].join(' ').toLowerCase().includes(q)) &&
      ($('status').value==='all' || statusOf(h.patch_status)===$('status').value) &&
      ($('exposure').value==='all' || rows.some(r=>r.exposure===$('exposure').value));
  });
  filtered=model.rows.filter(r=>selected.some(h=>h.host===r.host));
  $('result-count').textContent=selected.length+' hosts';
  $('empty').hidden=selected.length>0;
  $('rows').innerHTML=selected.map((h,index)=>{
    const rows=model.rows.filter(r=>r.host===h.host && r.kind!=='Host');
    const checks=hostChecks(h);
    const id='host-checks-'+index;
    const nested=checkGroups.map(g=>{
      const members=checks.filter(c=>g.indices.includes(c.i));
      if(!members.length)return '';
      return `<tr class="check-group"><th colspan="3"><h3>${esc(g.name)}</h3><p>${esc(g.intro)}</p></th></tr>`+members.map(c=>`<tr><td><b>${esc(detectionChecks[c.i][0])}</b><p>${esc(detectionChecks[c.i][1])}</p></td><td>${c.records.length?c.records.map(r=>`<p>${esc(r)}</p>`).join(''):'<p>No evidence recorded for this check. This does not establish that it ran or that PHP is absent.</p>'}</td><td>${esc(c.target)}${guideMarkup(c.i)}${manualMarkup({where:manualChecks[c.i][0],command:manualChecks[c.i][1],expect:manualChecks[c.i][2]})}</td></tr>`).join('');
    }).join('');
    return `<tr class="host-summary"><td><button class="host-expand linkbutton" aria-expanded="false" aria-controls="${id}">＋ ${esc(h.host)}</button><span class="sub mono">${esc(h.address || 'Not recorded')}</span></td><td>${badge(statusOf(h.patch_status))}</td><td>${rows.length}</td><td class="mono">${esc([...new Set(rows.map(r=>r.version))].join(', ') || 'Not recorded')}</td><td>${checks.filter(c=>c.records.length).length} / ${checks.length}<span class="sub">checks with recorded evidence</span></td></tr><tr id="${id}" hidden><td colspan="5" class="host-check-cell"><h3>Detection checks for ${esc(h.host)}</h3><p>Applicable checks are listed individually. Recorded evidence is not a pass result. All bundled sample results are fictional.</p><table class="host-check-table"><thead><tr><th>CHECK</th><th>RECORDED EVIDENCE</th><th>TARGET / MANUAL COMMAND</th></tr></thead><tbody>${nested}</tbody></table></td></tr>`;
  }).join('');
}
$('rows').addEventListener('click',event=>{
  const button=event.target.closest('.host-expand');
  if(!button)return;
  const panel=document.getElementById(button.getAttribute('aria-controls'));
  const expanded=button.getAttribute('aria-expanded')!=='true';
  button.setAttribute('aria-expanded',String(expanded));
  button.textContent=(expanded?'− ':'＋ ')+button.textContent.slice(2);
  panel.hidden=!expanded;
});
