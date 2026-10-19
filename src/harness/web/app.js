const $ = selector => document.querySelector(selector);
const escape = value => String(value ?? '').replace(/[&<>"']/g, char => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char]));
const levels = ['critical','high','medium','low','info'];
let data, view = 'overview', loadId = 0;
let traceCursor = 0, traceTimer = null, traceSpeed = 1;
const systemTheme = window.matchMedia('(prefers-color-scheme: dark)');
let themeChoice = 'system';
try { themeChoice = localStorage.getItem('aegis-theme') || 'system'; } catch {}
if (!['light','dark','system'].includes(themeChoice)) themeChoice = 'system';
function applyTheme() {
  document.documentElement.dataset.theme = themeChoice === 'system' ? (systemTheme.matches ? 'dark' : 'light') : themeChoice;
}
$('#theme').value = themeChoice;
$('#theme').addEventListener('change', () => {
  themeChoice = $('#theme').value;
  try { localStorage.setItem('aegis-theme', themeChoice); } catch {}
  applyTheme();
});
systemTheme.addEventListener('change', applyTheme);
applyTheme();
const nice = value => String(value ?? '').replaceAll('_',' ').replaceAll('.', ' · ');
const date = value => value ? new Date(value).toLocaleString([], {dateStyle:'medium',timeStyle:'short'}) : 'Not recorded';
const empty = text => `<div class="empty">${escape(text)}</div>`;
const panel = (title, subtitle, body, action='') => `<section class="panel"><div class="panel-header"><div><h2>${escape(title)}</h2>${subtitle ? `<p>${escape(subtitle)}</p>` : ''}</div>${action}</div>${body}</section>`;
// Render the report's Markdown vocabulary; raw HTML stays escaped.
function markdownInline(source) {
  const tokens = [];
  const token = html => { tokens.push(html); return `\u0000${tokens.length-1}\u0000`; };
  let text = String(source).replace(/\u0000/g, '').replace(/`([^`]+)`/g, (_, code) => token(`<code>${escape(code)}</code>`));
  text = text.replace(/\[([^\]\n]+)\]\(([^\s)]+)\)/g, (_, label, href) => {
    // Only explicit web links and in-document anchors are navigable.
    if (!/^(https?:\/\/|#[\w-])/i.test(href)) return label;
    return token(`<a href="${escape(href)}" rel="noreferrer noopener">${escape(label)}</a>`);
  });
  text = escape(text).replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
    .replace(/\*([^*\n]+)\*/g, '<em>$1</em>').replace(/\b_([^_\n]+)_\b/g, '<em>$1</em>');
  return text.replace(/\u0000(\d+)\u0000/g, (_, index) => tokens[Number(index)]);
}
function renderMarkdown(source) {
  const lines = String(source ?? '').replace(/\r\n?/g, '\n').split('\n');
  const output = [];
  const cells = line => line.trim().replace(/^\|/, '').replace(/\|$/, '').split('|').map(cell=>cell.trim());
  const listMatch = line => /^(\s*)([-+*]|\d+[.)])\s+(.+)$/.exec(line);
  const isTable = index => index+1 < lines.length && lines[index].includes('|') && /^\s*\|?\s*:?-{3,}:?\s*(\|\s*:?-{3,}:?\s*)+\|?\s*$/.test(lines[index+1]);
  function list(index, indent) {
    const ordered = /^\d/.test(listMatch(lines[index])[2]);
    const tag = ordered ? 'ol' : 'ul';
    const start = ordered ? ` start="${parseInt(listMatch(lines[index])[2],10)}"` : '';
    let html = `<${tag}${start}>`;
    while (index < lines.length) {
      const match = listMatch(lines[index]);
      if (!match || match[1].length !== indent || /^\d/.test(match[2]) !== ordered) break;
      html += `<li>${markdownInline(match[3])}`;
      index++;
      while (index < lines.length) {
        const nested = listMatch(lines[index]);
        if (nested && nested[1].length > indent) {
          const result = list(index,nested[1].length); html += result.html; index = result.index;
        } else if (lines[index].trim() && !nested && /^\s+/.test(lines[index])) {
          html += ' ' + markdownInline(lines[index].trim()); index++;
        } else break;
      }
      html += '</li>';
    }
    return {html:html+`</${tag}>`, index};
  }
  for (let i=0;i<lines.length;) {
    const line = lines[i];
    if (!line.trim()) {i++;continue;}
    if (/^\s*```/.test(line)) {
      const block=[];i++;
      while(i<lines.length && !/^\s*```/.test(lines[i])) block.push(lines[i++]);
      if(i<lines.length)i++;
      output.push(`<pre><code>${escape(block.join('\n'))}</code></pre>`);continue;
    }
    const heading=/^(#{1,6})\s+(.+)$/.exec(line);
    if(heading){output.push(`<h${heading[1].length}>${markdownInline(heading[2])}</h${heading[1].length}>`);i++;continue;}
    if(/^\s*(---+|\*\*\*+)\s*$/.test(line)){output.push('<hr>');i++;continue;}
    if(isTable(i)) {
      const headers=cells(line);i+=2;const rows=[];
      while(i<lines.length && lines[i].includes('|') && lines[i].trim()) rows.push(cells(lines[i++]));
      output.push(`<div class="report-table"><table><thead><tr>${headers.map(c=>`<th scope="col">${markdownInline(c)}</th>`).join('')}</tr></thead><tbody>${rows.map(row=>`<tr>${headers.map((_,n)=>`<td>${markdownInline(row[n]||'')}</td>`).join('')}</tr>`).join('')}</tbody></table></div>`);continue;
    }
    const match=listMatch(line);
    if(match){const result=list(i,match[1].length);output.push(result.html);i=result.index;continue;}
    if(/^>\s?/.test(line)) {
      const quote=[];while(i<lines.length && /^>\s?/.test(lines[i]))quote.push(lines[i++].replace(/^>\s?/,''));
      output.push(`<blockquote>${renderMarkdown(quote.join('\n'))}</blockquote>`);continue;
    }
    const paragraph=[line];i++;
    while(i<lines.length && lines[i].trim() && !/^(#{1,6}\s|\s*```|>|\s*---+\s*$)/.test(lines[i]) && !listMatch(lines[i]) && !isTable(i)) paragraph.push(lines[i++]);
    output.push(`<p>${markdownInline(paragraph.join(' '))}</p>`);
  }
  return output.join('\n');
}
async function request(url) {
  const response = await fetch(url);
  if (!response.ok) throw new Error('Could not load investigation records. Check the server and refresh.');
  return response.json();
}
async function loadRuns() {
  pauseTrace();
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
  pauseTrace();
  traceCursor = 0;
  const current = ++loadId;
  $('#message').textContent = 'Loading investigation…';
  data = null;
  $('#content').replaceChildren();
  try {
    const result = await request(`/api/runs/${encodeURIComponent($('#run-select').value)}`);
    if (current !== loadId) return;
    data = result;
    traceCursor = view === 'trace' ? 0 : data.events.length;
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
  const titles = {overview:'Security investigation overview',findings:'Investigation findings',evidence:'Evidence records',trace:'Investigation trace',activity:'Activity log',report:'Investigation report'};
  $('#page-title').textContent = titles[view];
  $('#breadcrumb').textContent = view === 'activity' ? 'Activity log' : view[0].toUpperCase()+view.slice(1);
  document.querySelectorAll('.nav').forEach(button => button.classList.toggle('active',button.dataset.view===view));
  const counts = Object.fromEntries(levels.map(level => [level,data.findings.filter(f=>f.severity===level).length]));
  if (view === 'overview') { renderOverview(counts); return; }
  if (view === 'trace') { renderTrace(); return; }
  if (view === 'findings') {
    $('#content').innerHTML = panel('Investigation findings',`${data.findings.length} findings · filter to focus your review.`,`<div class="filterbar"><input id="search" type="search" placeholder="Search findings…" aria-label="Search findings"><select id="severity" aria-label="Filter severity"><option value="">All severities</option>${levels.map(l=>`<option>${l}</option>`).join('')}</select></div><div id="finding-results"></div>`);
    const filter = () => {const query = $('#search').value.toLowerCase();$('#finding-results').innerHTML = findingRows(sortedFindings().filter(f=>(!$('#severity').value || f.severity===$('#severity').value) && JSON.stringify(f).toLowerCase().includes(query)));};
    $('#search').addEventListener('input',filter);$('#severity').addEventListener('change',filter);filter();
  } else if (view === 'evidence') {
    $('#content').innerHTML = panel('Evidence records',`${data.observations.length} observations · expand to inspect the recorded values and provenance.`,data.observations.map(o=>`<details class="record"><summary>${escape(nice(o.kind))} · ${escape(o.provider)}<br><span class="small-label">${escape(o.id)}</span></summary><pre>${escape(JSON.stringify(o,null,2))}</pre></details>`).join('') || empty('No evidence recorded.'));
  } else if (view === 'activity') {
    $('#content').innerHTML = panel('Activity log',`${data.events.length} recorded events · newest first.`,activities([...data.events].reverse()));
  } else {
    $('#content').innerHTML = panel('Investigation report','Rendered investigation report.',`<article class="report rendered-report">${renderMarkdown(data.report)}</article>`,'<button class="button" id="download">Download .md ↓</button>');
    $('#download').addEventListener('click',()=>{const url=URL.createObjectURL(new Blob([data.report],{type:'text/markdown'}));const a=document.createElement('a');a.href=url;a.download='investigation-report.md';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);});
  }
}
function milestoneMarkup() {
  const stages = [['Run started','RUN_STARTED'],['Authority verified','AUTHORITY_VERIFIED'],['Evidence collection started','PROVIDER_STARTED'],['Findings recorded','FINDING_ADDED'],['Run ended','RUN_ENDED']];
  const start = data.events.find(e => e.type === 'RUN_STARTED');
  return `<ol class="milestones">${stages.map(([label,type]) => {
    const event = data.events.find(e => e.type === type);
    const elapsed = event && start ? (new Date(event.at)-new Date(start.at))/1000 : null;
    return `<li class="milestone ${event?'':'missing'}"><div><strong>${label}</strong><time>${event ? `${escape(date(event.at))} · ${escape(new Date(event.at).toLocaleTimeString([], {hour12:false}))}${elapsed !== null ? ` · +${elapsed.toFixed(3)}s` : ''}` : 'Not recorded'}</time></div></li>`;
  }).join('')}</ol>`;
}
function renderOverview(counts) {
  const confirmed = data.findings.filter(f => f.status === 'confirmed').length;
  const possible = data.findings.filter(f => f.status === 'possible').length;
  const other = data.findings.length-confirmed-possible;
  const stats = [['Total findings',data.findings.length,`${counts.critical} critical · ${counts.high} high`],['Confirmed / possible',`${confirmed} / ${possible}`,other ? `${other} with other statuses` : 'Finding confidence status'],['Evidence records',data.observations.length,'Recorded observations'],['Provider calls',data.run.summary?.provider_calls ?? '—',`${data.gaps.length} coverage gaps`]];
  const targets = [...new Set(data.events.flatMap(e => e.type === 'CONTEXT_RESOLVED' ? (e.data?.grants || []).map(g=>g.alias).filter(Boolean) : []))];
  const context = [['Target',targets.join(', ') || 'Not recorded'],['Scope',data.run.scope_id || 'Not recorded'],['Skill',nice(data.run.skill)],['Model',data.run.model?.model_id || 'Unknown'],['Authority',data.run.authority || 'Unknown'],['Started',date(data.run.summary?.started_at || data.run.created_at)],['Ended',date(data.run.summary?.ended_at)],['Status',data.run.status || 'Unknown']];
  const chart = `<div class="distribution" role="img" aria-label="Findings by severity: ${escape(levels.map(l=>`${l} ${counts[l]}`).join(', '))}">${levels.map(l=>`<div class="chart-row ${l}"><span>${l}</span><meter min="0" max="${Math.max(1,...Object.values(counts))}" value="${counts[l]}" aria-label="${l}: ${counts[l]} findings"></meter><b>${counts[l]}</b></div>`).join('')}</div>`;
  $('#content').innerHTML = `<div class="stats">${stats.map(([label,value,foot])=>`<section class="stat"><div class="stat-label">${label}</div><div class="stat-number">${value}</div><div class="stat-foot">${foot}</div></section>`).join('')}</div><div class="grid"><div>${panel('Investigation objective','',`<p class="objective">${escape(data.run.objective || 'Not recorded')}</p>`, '<button class="text-button" data-go="report">Read report ↗</button>')}${panel('Findings to review','Ordered by severity. Possible findings require further validation.',findingRows(sortedFindings()),'<button class="text-button" data-go="findings">All findings ↗</button>')}${panel('Investigation milestones','First recorded occurrence of each stage; elapsed time from run start.',milestoneMarkup(),'<button class="text-button" data-go="trace">Explore trace ↗</button>')}</div><div>${panel('Findings by severity','Counts for this investigation.',chart)}${panel('Run context','',`<div class="scope">${context.map(([label,value])=>`<div>${label}<b>${escape(value)}</b></div>`).join('')}</div>`)}</div></div>`;
}
function pauseTrace() {
  if (traceTimer !== null) clearTimeout(traceTimer);
  traceTimer = null;
}
function traceRows() {
  return data.events.slice(0,traceCursor).reverse().map(e => {
    const details = e.data || {};
    const explanation = details.reason ?? details.reasons ?? details.evidence_needed ?? details.stop_reason;
    return `<details class="record"><summary><span class="trace-type">${escape(nice(e.type))}</span> <span class="small-label">#${escape(e.seq)}</span><br><time>${escape(e.at)}</time>${details.provider ? `<span class="badge">${escape(details.provider)}</span>` : ''}</summary>${explanation ? `<p class="trace-reason">${escape(typeof explanation === 'string' ? explanation : JSON.stringify(explanation))}</p>` : ''}<pre>${escape(JSON.stringify(e,null,2))}</pre></details>`;
  }).join('') || empty('Playback is at the beginning. Press Play or Next event.');
}
function updateTrace() {
  $('#trace-events').innerHTML = traceRows();
  $('#trace-progress').value = traceCursor;
  $('#trace-count').textContent = `${traceCursor} / ${data.events.length} events · ${traceCursor === data.events.length ? 'End of recording' : 'Recorded playback'} · newest revealed event first`;
  $('#trace-play').textContent = traceTimer !== null ? 'Pause' : 'Play';
  $('#trace-next').disabled = traceCursor >= data.events.length;
  $('#trace-play').disabled = !data.events.length;
}
function scheduleTrace() {
  if (traceCursor >= data.events.length) { pauseTrace(); updateTrace(); return; }
  const previous = data.events[traceCursor-1];
  const next = data.events[traceCursor];
  const recordedGap = previous ? new Date(next.at)-new Date(previous.at) : 0;
  const delay = Math.min(3000, Math.max(350, Number.isFinite(recordedGap) ? recordedGap : 350))/traceSpeed;
  traceTimer = setTimeout(() => { traceTimer = null; traceCursor++; scheduleTrace(); updateTrace(); },delay);
}
function renderTrace() {
  $('#content').innerHTML = panel('Recorded playback', 'Replay saved events for review. This does not execute tools or run a new investigation.',`<div class="playback-controls"><button class="button" id="trace-play">Play</button><button class="button" id="trace-next">Next event</button><button class="button" id="trace-reset">Reset</button><label for="trace-speed">Speed</label><select id="trace-speed"><option value="0.5">0.5×</option><option value="1">1×</option><option value="2">2×</option><option value="4">4×</option></select><input id="trace-progress" type="range" min="0" max="${data.events.length}" value="${traceCursor}" aria-label="Revealed event count"></div><div id="trace-count" class="trace-state" role="status" aria-live="polite"></div><p class="trace-note">Original timestamps are preserved. Playback spacing is adjusted to 0.35–3 seconds per event at 1× for readability; it is not execution timing. Expand an event to inspect recorded decisions and references.</p><div id="trace-events" class="trace-list"></div>`);
  $('#trace-speed').value = String(traceSpeed);
  $('#trace-play').addEventListener('click', () => {
    if (traceTimer !== null) pauseTrace();
    else { if (traceCursor >= data.events.length) traceCursor=0; scheduleTrace(); }
    updateTrace();
  });
  $('#trace-next').addEventListener('click', () => {pauseTrace(); traceCursor=Math.min(data.events.length,traceCursor+1);updateTrace();});
  $('#trace-reset').addEventListener('click', () => {pauseTrace();traceCursor=0;updateTrace();});
  $('#trace-progress').addEventListener('input', () => {pauseTrace();traceCursor=Number($('#trace-progress').value);updateTrace();});
  $('#trace-speed').addEventListener('change', () => {const playing=traceTimer!==null;pauseTrace();traceSpeed=Number($('#trace-speed').value);if(playing)scheduleTrace();updateTrace();});
  updateTrace();
}
document.addEventListener('click', event => {
  const target=event.target.closest('[data-view],[data-go],[data-finding]');
  if (!target) return;
  if (target.dataset.view || target.dataset.go) { pauseTrace(); view=target.dataset.view || target.dataset.go;render();return; }
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
