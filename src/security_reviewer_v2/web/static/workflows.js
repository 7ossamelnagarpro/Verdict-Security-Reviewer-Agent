'use strict';
let workflowDraft={version:1,accounts:[],workflows:[],allow_mutation:false,reset:'fresh_stack',max_requests:100,max_seconds:300,timeout_seconds:5};
let lastApplicationMap=null;
let wizardStep=0;
const cloneDraft=x=>JSON.parse(JSON.stringify(x));
function wfInput(label,key,val,type='text'){return `<label>${esc(label)}<input data-key="${key}" type="${type}" value="${esc(val??'')}" ${type==='password'?'autocomplete="new-password"':''}></label>`;}
function wfSelect(label,key,val,choices){const values=choices.includes(val)?choices:[val,...choices];return `<label>${esc(label)}<select data-key="${key}">${values.map(x=>`<option value="${esc(x)}" ${x===val?'selected':''}>${esc(x)}${choices.includes(x)?'':' (select a valid value)'}</option>`).join('')}</select></label>`;}
function wfRender(){
  $('#wf-accounts').innerHTML=workflowDraft.accounts.map((a,i)=>`<details class="wf-card" data-account="${i}"><summary><span class="step-number">${i+1}</span><strong>${esc(a.id)}</strong><span class="summary-note">${esc(a.role)} · ${esc(a.session)}</span></summary><div class="grid">${wfInput('Alias (used by steps)','id',a.id)}${wfInput('Role label','role',a.role)}${wfInput('Login path','login_path',a.login_path)}${wfSelect('Login request format','encoding',a.encoding,['json','form'])}${wfSelect('Session type','session',a.session,['bearer','cookie'])}${wfInput('Username field','username_field',a.username_field)}${wfInput('Password field','password_field',a.password_field)}${wfInput('Token JSON field (bearer only)','token_path',a.token_path)}${wfInput('Identity verification GET path','verify_path',a.verify_path)}${wfInput('Username JSON field in identity response','identity_path',a.identity_path)}</div><details><summary>Save this test account securely</summary><div class="grid"><label>Test username<input data-secret="username" autocomplete="off"></label><label>Test password<input data-secret="password" type="password" autocomplete="new-password"></label></div><button type="button" data-save-actor="${i}" class="secondary">Save credentials in OS vault</button></details><button type="button" data-remove-actor="${i}" class="secondary">Remove account</button></details>`).join('');
  wfRenderWorkflows();
  $('#wf-max-requests').value=workflowDraft.max_requests;$('#wf-max-seconds').value=workflowDraft.max_seconds;$('#wf-timeout').value=workflowDraft.timeout_seconds;
  $('#wf-reset').value=workflowDraft.reset;
  wfPreview();
}
function wfRenderWorkflows(){
  $('#wf-workflows').innerHTML=workflowDraft.workflows.map((w,wi)=>`<details class="wf-card" data-workflow="${wi}"><summary><span class="step-number">${wi+1}</span><strong>${esc(w.title)}</strong><span class="summary-note">${w.steps.length} steps</span></summary><div class="grid">${wfInput('Workflow ID','id',w.id)}${wfInput('Expected business rule','title',w.title)}${wfSelect('Severity if violated','severity',w.severity,['low','medium','high','critical'])}</div>${w.steps.map((s,si)=>`<div class="wf-step" data-step="${si}"><h4>Step ${si+1}</h4><div class="grid">${wfSelect('Account','actor',s.actor||'anonymous',['anonymous',...workflowDraft.accounts.map(a=>a.id)])}${wfSelect('HTTP method','method',s.method,['GET','POST','PUT','PATCH','DELETE','HEAD'])}${wfInput('Path (capture variables allowed)','path',s.path)}${wfInput('Expected status codes, comma-separated','expect_status',s.expect_status.join(','))}</div><label class="check"><input type="checkbox" data-key="security_check" ${s.security_check?'checked':''}>Security assertion (unchecked = setup step)</label><details><summary>Request body, captures and JSON assertions</summary><label>JSON request body<textarea data-key="body" rows="3" placeholder='{"quantity":1}'>${esc(s.body?JSON.stringify(s.body,null,2):'')}</textarea></label><label>Capture response fields<textarea data-key="capture" rows="2" placeholder='{"order_id":"id"}'>${esc(s.capture?JSON.stringify(s.capture,null,2):'')}</textarea></label><label>JSON assertions<textarea data-key="assertions" rows="3" placeholder='[{"path":"status","op":"eq","value":"new"}]'>${esc(s.assertions?JSON.stringify(s.assertions,null,2):'')}</textarea></label><small>Supported operations: eq, ne, present, absent, gte, lte. Use dots for nested fields; list indexes are numeric.</small></details><button type="button" data-remove-step="${si}" class="secondary">Remove step</button></div>`).join('')}<div class="actions"><button type="button" data-add-step="${wi}" class="secondary">+ Add step</button><button type="button" data-remove-workflow="${wi}" class="secondary">Remove workflow</button></div></details>`).join('');
  $('#wf-workflows').querySelectorAll('[data-workflow]').forEach((card,wi)=>{
    card.querySelectorAll('[data-step]').forEach((step,si)=>{
      const assertions=workflowDraft.workflows[wi].steps[si].response_assertions;
      step.querySelector('details').insertAdjacentHTML('beforeend',`<label>Response header / text assertions (advanced)<textarea data-key="response_assertions" rows="3" placeholder='[{"op":"header_present","name":"Content-Security-Policy"}]'>${esc(assertions?JSON.stringify(assertions,null,2):'')}</textarea></label><small>Literal-only checks: header_present, header_absent, header_contains, header_not_contains, body_contains, body_not_contains. Raw responses are never saved.</small>`);
      const part=workflowDraft.workflows[wi].steps[si].multipart;
      step.querySelector('details').insertAdjacentHTML('beforeend',`<label>Multipart test file (disposable Compose only)<textarea data-key="multipart" rows="3" placeholder='{"field":"file","filename":"probe.html","content_type":"text/html","content":"inert test marker"}'>${esc(part?JSON.stringify(part,null,2):'')}</textarea></label><small>One inline file, at most 4 KiB. Requires approved mutation; no local file paths or real secrets.</small>`);
      const configured=workflowDraft.workflows[wi].steps[si];
      step.querySelector('details').insertAdjacentHTML('beforeend',`<div class="grid">${wfInput('Wait before read request (seconds, 0–10)','wait_before_seconds',configured.wait_before_seconds??'','number')}${wfInput('Lockout after prior failed logins (2–10)','lockout_after_failures',configured.lockout_after_failures??'','number')}</div><small>Wait is for an asynchronous GET/HEAD. Lockout applies only to an anonymous POST after identical 401 login attempts, with expected status 423/429.</small>`);
      step.querySelector('details').insertAdjacentHTML('beforeend',`<label>Synthetic authentication probe (disposable Compose only)<textarea data-key="auth_probe" rows="3" placeholder='{"kind":"numbered_cookie","name":"session","prefix":"session-","number":3}'>${esc(configured.auth_probe?JSON.stringify(configured.auth_probe,null,2):'')}</textarea></label><small>Advanced: generate a numbered test cookie or unsigned JWT from test claims. Never paste a real credential. Requires explicit disposable-target approval.</small>`);
    });
  });
}
function wfCollect(){
  $('#wf-accounts').querySelectorAll('[data-account]').forEach(card=>{const a=workflowDraft.accounts[Number(card.dataset.account)];card.querySelectorAll('[data-key]').forEach(el=>a[el.dataset.key]=el.value.trim());});
  $('#wf-workflows').querySelectorAll('[data-workflow]').forEach(card=>{
    const w=workflowDraft.workflows[Number(card.dataset.workflow)];
    card.querySelectorAll('[data-key]').forEach(el=>{const step=el.closest('[data-step]'),target=step?w.steps[Number(step.dataset.step)]:w,key=el.dataset.key;
      if(el.type==='checkbox'){target[key]=el.checked;return;}
      if(['body','multipart','capture','assertions','response_assertions','auth_probe'].includes(key)){if(!el.value.trim()){delete target[key];return;}try{target[key]=JSON.parse(el.value);}catch{throw Error(`Invalid JSON in ${w.id}, step ${Number(step.dataset.step)+1}: ${key}`);}return;}
      if(['wait_before_seconds','lockout_after_failures'].includes(key)){if(!el.value.trim()){delete target[key];return;}target[key]=Number(el.value);return;}
      target[key]=key==='expect_status'?el.value.split(',').map(x=>Number(x.trim())):el.value.trim();
    });
  });
  workflowDraft.max_requests=Number($('#wf-max-requests').value);workflowDraft.max_seconds=Number($('#wf-max-seconds').value);workflowDraft.timeout_seconds=Number($('#wf-timeout').value);workflowDraft.reset=$('#wf-reset').value;
  workflowDraft.allow_mutation=value('runtime_method')==='trusted_compose'&&workflowDraft.workflows.some(w=>w.steps.some(s=>['POST','PUT','PATCH','DELETE'].includes(s.method)));
  if(workflowDraft.allow_mutation)workflowDraft.reset='fresh_stack';
  return cloneDraft(workflowDraft);
}
function wfPreview(){ $('#wf-preview').textContent=JSON.stringify(workflowDraft,null,2); }
function wfGo(n){wfCollect();wizardStep=Math.max(0,Math.min(4,n));document.querySelectorAll('[data-panel]').forEach(el=>el.hidden=Number(el.dataset.panel)!==wizardStep);document.querySelectorAll('[data-wizard]').forEach(el=>{if(Number(el.dataset.wizard)===wizardStep)el.setAttribute('aria-current','step');else el.removeAttribute('aria-current');});$('#wf-back').disabled=wizardStep===0;$('#wf-next').disabled=wizardStep===4;wfPreview();}
window.workflowPayload=()=>wfCollect();
window.workflowLoad=suite=>{workflowDraft=cloneDraft(suite||{version:1,accounts:[],workflows:[],allow_mutation:false,reset:'fresh_stack',max_requests:100,max_seconds:300,timeout_seconds:5});wfRender();wfGo(0);};
window.workflowSync=()=>{const visible=value('mode')==='project-full'&&value('runtime_method')!=='recipe';$('#workflow-fields').hidden=!visible;form.elements.workflow_enabled.disabled=!visible;$('#workflow-builder').hidden=!visible||!form.elements.workflow_enabled.checked;};
window.workflowMap=map=>{
  if(!map)return;
  lastApplicationMap=map;
  $('#wf-map').innerHTML=(map.endpoints||[]).map(e=>`<div class="wf-map-row"><code>${esc(e.method)} ${esc(e.path)}</code> <small>${esc(e.source)} · ${esc(e.confidence)}</small></div>`).join('')+bullets(map.notes||[]);
  if(map.health_path)form.elements.health_path.value=map.health_path;
  const gets=(map.endpoints||[]).filter(e=>e.method==='GET'&&!e.path.includes('{')).map(e=>e.path);
  if(gets.length)form.elements.endpoints.value=[...new Set(gets)].join('\n');
  if(map.login_path)form.elements.login_path.value=map.login_path;
  if(map.login){for(const key of ['username_field','password_field'])if(map.login[key]&&form.elements[key])form.elements[key].value=map.login[key];}
};
function generateDraftFromMap(){
  const map=lastApplicationMap||{};
  const gets=[...new Set((map.endpoints||[]).filter(e=>e.method==='GET'&&!e.path.includes('{')).map(e=>e.path))];
  if(map.health_path&&!gets.includes(map.health_path))gets.unshift(map.health_path);
  if(!gets.length)throw Error('No static GET routes were discovered. Add a route or OpenAPI file first.');
  if(workflowDraft.workflows.length&&!confirm('Replace the current workflow draft with discovered GET checks?'))return;
  workflowDraft.workflows=gets.slice(0,30).map((path,i)=>({id:`discovered_${i+1}`,title:`Review discovered GET ${path}`,severity:'medium',steps:[{actor:'anonymous',method:'GET',path,expect_status:[200],security_check:false}]}));
  workflowDraft.accounts=[];workflowDraft.allow_mutation=false;workflowDraft.reset='none';workflowDraft.max_requests=Math.max(100,gets.length*4);
  form.elements.workflow_enabled.checked=true;wfRender();window.workflowSync();notice('Draft created from source routes. Review every status and add accounts/business rules before running.');
}
document.querySelectorAll('[data-wizard]').forEach(b=>b.onclick=act(()=>wfGo(Number(b.dataset.wizard))));
$('#wf-next').onclick=act(()=>wfGo(wizardStep+1));$('#wf-back').onclick=act(()=>wfGo(wizardStep-1));
$('#wf-discover').onclick=act(detect);
$('#wf-generate-draft').onclick=act(generateDraftFromMap);
$('#wf-example').onclick=act(async()=>{if(workflowDraft.workflows.length&&!confirm('Replace this workflow draft with the editable example?'))return;window.workflowLoad(await api('/api/runtime/example'));form.elements.workflow_enabled.checked=true;window.workflowSync();notice('Example loaded. Confirm every expected rule; add your test credentials in Accounts.');});
$('#wf-add-account').onclick=act(()=>{wfCollect();workflowDraft.accounts.push({id:'user_'+(workflowDraft.accounts.length+1),role:'user',login_path:'/auth/login',encoding:'json',username_field:'username',password_field:'password',session:'bearer',token_path:'access_token',verify_path:'/me',identity_path:'username'});wfRender();});
const wfNewStep=()=>({actor:'anonymous',method:'GET',path:'/',expect_status:[200],security_check:false});
$('#wf-add-workflow').onclick=act(()=>{wfCollect();workflowDraft.workflows.push({id:'workflow_'+(workflowDraft.workflows.length+1),title:'Describe the expected behaviour',severity:'medium',steps:[wfNewStep()]});wfRenderWorkflows();});
$('#wf-accounts').onclick=act(async ev=>{
  if(ev.target.dataset.removeActor!==undefined){wfCollect();workflowDraft.accounts.splice(Number(ev.target.dataset.removeActor),1);wfRender();}
  if(ev.target.dataset.saveActor!==undefined){const i=Number(ev.target.dataset.saveActor),card=ev.target.closest('[data-account]');wfCollect();await saveProject();await api('/api/credentials',{kind:'workflow',project_id:value('project_id'),actor:workflowDraft.accounts[i].id,username:card.querySelector('[data-secret="username"]').value,password:card.querySelector('[data-secret="password"]').value});card.querySelectorAll('[data-secret]').forEach(el=>el.value='');notice('Test credentials saved in OS vault.');}
});
$('#wf-workflows').onclick=act(ev=>{const t=ev.target;if(!t.matches('button'))return;wfCollect();const wi=Number(t.closest('[data-workflow]').dataset.workflow);if(t.dataset.addStep!==undefined)workflowDraft.workflows[wi].steps.push(wfNewStep());if(t.dataset.removeWorkflow!==undefined)workflowDraft.workflows.splice(wi,1);if(t.dataset.removeStep!==undefined)workflowDraft.workflows[wi].steps.splice(Number(t.dataset.removeStep),1);wfRenderWorkflows();});
$('#wf-accounts').addEventListener('change',act(ev=>{if(ev.target.dataset.key==='id'){wfCollect();wfRenderWorkflows();}}));
$('#wf-validate').onclick=act(async()=>{const result=await api('/api/runtime/validate',payload());$('#wf-validation').textContent=`Valid structure: ${result.accounts} accounts, ${result.workflows} workflows, ${result.steps} steps. ${result.note}`;wfPreview();});
$('#wf-save').onclick=act(async()=>{await api('/api/runtime/validate',payload());await saveProject();notice('Contract saved with project. Save each account credential, then Start review.');});
$('#wf-export').onclick=act(async()=>{const response=await fetch('/api/runtime/export',{method:'POST',headers:{'Content-Type':'application/json','X-Verdict-Token':token},body:JSON.stringify(payload())});if(!response.ok)throw Error((await response.json()).error);const url=URL.createObjectURL(await response.blob()),a=document.createElement('a');a.href=url;a.download='runtime-contract.json';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);});
window.renderWorkflowCoverage=e=>{if(!e)return '';return '<div class="workflow-coverage"><h4>Declared workflow coverage</h4><p>'+esc(e.status)+' · '+esc(e.coverage.executed)+' / '+esc(e.coverage.declared)+' steps executed · '+esc(e.coverage.violations)+' rule violations · '+esc(e.coverage.unresolved)+' unresolved</p>'+bullets(e.accounts.map(a=>`${a.actor}: ${a.status}`))+'<table><thead><tr><th>Workflow</th><th>Step / account</th><th>Request</th><th>Outcome</th></tr></thead><tbody>'+e.workflows.flatMap(w=>w.steps.map(s=>'<tr><td>'+esc(w.title)+'</td><td>'+esc(s.step)+' · '+esc(s.actor)+'</td><td>'+esc(s.method)+' '+esc(s.path)+'</td><td>'+esc(s.status)+(s.http_status?' · HTTP '+esc(s.http_status):'')+'</td></tr>')).join('')+'</tbody></table></div>';};
const originalEvidencePanels=evidencePanels;
evidencePanels=function(){originalEvidencePanels();if(report?.runtime?.workflow_evidence)$('#runtime-result').insertAdjacentHTML('afterbegin',window.renderWorkflowCoverage(report.runtime.workflow_evidence));};
wfRender();wfGo(0);window.workflowSync();
