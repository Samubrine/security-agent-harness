const $ = selector => document.querySelector(selector);
const escape = value => String(value ?? '').replace(/[&<>"']/g, char => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char]));
const levels = ['critical','high','medium','low','info'];
let data, view = 'overview', loadId = 0;
const nice = value => String(value ?? '').replaceAll('_',' ').replaceAll('.', ' · ');
const date = value => value ? new Date(value).toLocaleString([], {dateStyle:'medium',timeStyle:'short'}) : 'Not recorded';
const empty = text => `<div class="empty">${escape(text)}</div>`;
const panel = (title, subtitle, body, action='') => `<section class="panel"><div class="panel-header"><div><h2>${escape(title)}</h2>${subtitle ? `<p>${escape(subtitle)}</p>` : ''}</div>${action}</div>${body}</section>`;
async function request(url) {
  const response = await fetch(url);
  if (!response.ok) throw new Error('Could not load investigation records. Check the server and refresh.');
  return response.json();
}
async function loadRuns() {
  $('#refresh').disabled = true;
  $('#message').textContent = '';
  try {
    const previous = $('#run-select').value;
    const runs = await request('/api/runs');
    $('#run-select').innerHTML = runs.map(r => `<option value="${escape(r.directory)}">${escape(r.directory)} · ${escape(nice(r.skill))}</option>`).join('');
    if (runs.some(r => r.directory === previous)) $('#run-select').value = previous;
    if (!runs.length) {
      data = null;
      $('#run-status').textContent = 'No records';
      $('#content').innerHTML = panel('Your workspace is ready', '', empty('Run an investigation with the CLI, then refresh to explore its findings here.'));
      return;
    }
    await loadRun();
  } catch (error) { $('#message').textContent = error.message; }
  finally { $('#refresh').disabled = false; }
}
async function loadRun() {
  const current = ++loadId;
  $('#message').textContent = 'Loading investigation…';
  data = null;
  $('#content').replaceChildren();
  try {
    const result = await request(`/api/runs/${encodeURIComponent($('#run-select').value)}`);
    if (current !== loadId) return;
    data = result;
    $('#message').textContent = '';
    $('#run-status').textContent = data.run.status || 'Unknown';
    render();
  } catch (error) { if (current === loadId) $('#message').textContent = error.message; }
}
function findingRows(findings) {
  return findings.map(f => `<button class="finding-row" data-finding="${escape(f.id)}"><span class="severity-dot ${levels.includes(f.severity)?f.severity:'info'}"></span><span class="finding-info"><strong>${escape(f.title)}</strong><small>${escape(f.id)} &nbsp; · &nbsp; ${escape(f.status)} &nbsp; · &nbsp; ${(f.claims||[]).length} claims</small></span><span class="severity ${levels.includes(f.severity)?f.severity:'info'}">${escape(f.severity)}</span><span class="arrow">↗</span></button>`).join('') || empty('No findings match this view.');
}
function sortedFindings() {
  return [...data.findings].sort((a,b) => (levels.indexOf(a.severity)+1||99)-(levels.indexOf(b.severity)+1||99));
}
function activities(events) {
  return events.map(e => `<div class="activity-row"><time>${escape(new Date(e.at).toLocaleTimeString())}</time><div><strong>${escape(nice(e.type).toLowerCase())}</strong><small>Event ${escape(e.seq)}${e.data?.provider ? ' · '+escape(e.data.provider) : ''}</small></div></div>`).join('') || empty('No activity recorded.');
}
function render() {
  if (!data) return;
  const titles = {overview:'A clearer view of your security.',findings:'Findings, with the full picture.',evidence:'Every claim starts with evidence.',activity:'An investigation you can follow.',report:'The investigation, documented.'};
  $('#page-title').textContent = titles[view];
  $('#breadcrumb').textContent = view === 'activity' ? 'Activity log' : view[0].toUpperCase()+view.slice(1);
  document.querySelectorAll('.nav').forEach(button => button.classList.toggle('active',button.dataset.view===view));
  const counts = Object.fromEntries(levels.map(level => [level,data.findings.filter(f=>f.severity===level).length]));
  if (view === 'overview') {
    const stats = [['Total findings',data.findings.length,'Across this investigation','◎'],['Critical findings',counts.critical,'Prioritize for review','↗'],['Evidence records',data.observations.length,'Observations captured','▤'],['Provider calls',data.run.summary?.provider_calls ?? '—','Recorded tool executions','⇄']];
    $('#content').innerHTML = `<div class="stats">${stats.map(([label,value,foot,icon],i)=>`<section class="stat"><div class="stat-label">${label}<span>${icon}</span></div><div class="stat-number ${i===1?'critical-text':''}">${value}</div><div class="stat-foot">${foot}</div></section>`).join('')}</div><div class="grid"><div>${panel('Findings to review','Prioritized by severity. Open a finding to inspect its claims.',findingRows(sortedFindings()),'<button class="text-button" data-go="findings">View all ↗</button>')}${panel('Recent activity','A recorded trail of decisions and observations.',activities(data.events.slice(-4).reverse()),'<button class="text-button" data-go="activity">Full log ↗</button>')}</div><div><section class="panel overview-card"><span class="eyebrow">INVESTIGATION BRIEF</span><h2>Small details.<br>Clearer decisions.</h2><p>${escape(data.run.objective)}</p><button class="button" data-go="report">Read full report ↗</button></section>${panel('Severity breakdown','',`<div class="distribution"><div class="bar">${levels.filter(l=>counts[l]).map(l=>`<span class="${l}"></span>`).join('')}</div><div class="legend">${levels.filter(l=>counts[l]).map(l=>`<span>${nice(l)} <b>${counts[l]}</b></span>`).join('') || 'No findings'}</div></div>`)}${panel('Run context','',`<div class="scope"><div>Skill <b>${escape(nice(data.run.skill))}</b></div><div>Model <b>${escape(data.run.model?.model_id || 'Unknown')}</b></div><div>Authority <b>${escape(data.run.authority || 'Unknown')}</b></div><div>Created <b>${escape(date(data.run.created_at))}</b></div><div>Coverage gaps <b>${data.gaps.length}</b></div></div>`)}</div></div>`;
    const segments = document.querySelectorAll('.bar span');
    segments.forEach(segment => {segment.style.flexGrow = counts[segment.className];});
  } else if (view === 'findings') {
    $('#content').innerHTML = panel('Investigation findings',`${data.findings.length} findings · filter to focus your review.`,`<div class="filterbar"><input id="search" type="search" placeholder="Search findings…" aria-label="Search findings"><select id="severity" aria-label="Filter severity"><option value="">All severities</option>${levels.map(l=>`<option>${l}</option>`).join('')}</select></div><div id="finding-results"></div>`);
    const filter = () => {const query = $('#search').value.toLowerCase();$('#finding-results').innerHTML = findingRows(sortedFindings().filter(f=>(!$('#severity').value || f.severity===$('#severity').value) && JSON.stringify(f).toLowerCase().includes(query)));};
    $('#search').addEventListener('input',filter);$('#severity').addEventListener('change',filter);filter();
  } else if (view === 'evidence') {
    $('#content').innerHTML = panel('Evidence records',`${data.observations.length} observations · expand to inspect the recorded values and provenance.`,data.observations.map(o=>`<details class="record"><summary>${escape(nice(o.kind))} · ${escape(o.provider)}<br><span class="small-label">${escape(o.id)}</span></summary><pre>${escape(JSON.stringify(o,null,2))}</pre></details>`).join('') || empty('No evidence recorded.'));
  } else if (view === 'activity') {
    $('#content').innerHTML = panel('Activity log',`${data.events.length} recorded events · newest first.`,activities([...data.events].reverse()));
  } else {
    $('#content').innerHTML = panel('Investigation report','The original Markdown report generated by Harness.',`<pre class="report">${escape(data.report)}</pre>`,'<button class="button" id="download">Download .md ↓</button>');
    $('#download').addEventListener('click',()=>{const url=URL.createObjectURL(new Blob([data.report],{type:'text/markdown'}));const a=document.createElement('a');a.href=url;a.download='investigation-report.md';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);});
  }
}
document.addEventListener('click', event => {
  const target=event.target.closest('[data-view],[data-go],[data-finding]');
  if (!target) return;
  if (target.dataset.view || target.dataset.go) { view=target.dataset.view || target.dataset.go;render();return; }
  const finding=data?.findings.find(f=>f.id===target.dataset.finding);
  if (!finding) return;
  const ids=new Set((finding.claims||[]).flatMap(c=>c.supports||[]));
  const evidence=data.observations.filter(o=>ids.has(o.id));
  $('#detail-content').innerHTML=`<h2 class="detail-title">${escape(finding.title)}</h2><p><span class="badge">${escape(finding.severity)}</span> <span class="badge">${escape(finding.status)}</span></p>${(finding.claims||[]).map(c=>`<div class="claim">${escape(c.statement)}<small>Confidence: ${escape(c.confidence)} · ${escape(c.confidence_basis)}</small></div>`).join('')}<h3>Supporting observations</h3>${evidence.map(o=>`<details class="record"><summary>${escape(o.id)} · ${escape(nice(o.kind))}</summary><pre>${escape(JSON.stringify(o,null,2))}</pre></details>`).join('') || '<p>No linked observations recorded.</p>'}`;
  $('#detail').showModal();
});
$('#close-detail').addEventListener('click',()=>$('#detail').close());
$('#refresh').addEventListener('click',loadRuns);
$('#run-select').addEventListener('change',loadRun);
loadRuns();
