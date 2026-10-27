'use strict';
const workspacePages={
  projects:['My projects','Saved configurations, ready for your next security review.'],
  review:['New review','Choose your project, configure its runtime, then start your review.'],
  runs:['Review history','Follow progress, revisit evidence and manage your past reviews.'],
  results:['Review results','Findings, evidence and coverage from the selected review.'],
  setup:['System setup','Connect your tools and AI provider once for this computer.']
};
function renderWorkspace(){
  let page=location.hash.slice(1)||'review';
  if(!(page in workspacePages))page='review';
  if(page==='results'&&!report)page='runs';
  document.querySelectorAll('main > section[data-page]').forEach(el=>el.hidden=el.id!==page);
  document.querySelectorAll('aside nav a').forEach(a=>{if(a.hash==='#'+page)a.setAttribute('aria-current','page');else a.removeAttribute('aria-current');});
  $('#results-nav').hidden=!report;
  $('#page-title').textContent=workspacePages[page][0];
  $('#page-description').textContent=workspacePages[page][1];
  document.title=workspacePages[page][0]+' · Verdict';
}
window.navigateWorkspace=page=>{if(location.hash!=='#'+page)location.hash=page;renderWorkspace();window.scrollTo({top:0,behavior:'auto'});};
window.addEventListener('hashchange',()=>{renderWorkspace();window.scrollTo({top:0,behavior:'auto'});});
$('#history-current').onclick=act(async()=>{showRemovedHistory=false;await refresh();});
$('#history-removed').onclick=act(async()=>{showRemovedHistory=true;await refresh();});
window.confirmHistory=message=>new Promise(resolve=>{
  const dialog=$('#history-confirm');
  if(dialog.open){resolve(false);return;}
  $('#history-confirm-message').textContent=message;
  dialog.returnValue='';
  dialog.addEventListener('close',()=>resolve(dialog.returnValue==='remove'),{once:true});
  dialog.showModal();
});
$('#clear-history').onclick=act(async()=>{
  if(!await window.confirmHistory('Remove all finished reviews from your history list?'))return;
  const result=await api('/api/history/clear',{});
  await refresh();notice(result.changed+' review(s) removed from history. Reports are preserved.');
});
// Reveal advanced settings when a browser validation error needs attention.
form.addEventListener('invalid',event=>{let node=event.target.parentElement;while(node&&node!==form){if(node.tagName==='DETAILS')node.open=true;node=node.parentElement;}},true);
renderWorkspace();
