(() => {
  'use strict';
  const $ = id => document.getElementById(id);
  const token = new URLSearchParams(location.hash.slice(1)).get('token') || '';
  history.replaceState(null, '', location.pathname);
  $('inventory-link').href = '/' + (token ? `#token=${encodeURIComponent(token)}` : '');
  let catalog = {runs: [], scans: []};
  let cursors = [null];
  let nextCursor = null;
  let preview = null;
  let currentJob = null;
  let handledJob = null;
  let requestSequence = 0;

  async function api(path, payload) {
    const headers = token ? {Authorization: `Bearer ${token}`} : {};
    const options = {headers};
    if (payload !== undefined) {
      options.method = 'POST';
      headers['Content-Type'] = 'application/json';
      headers['X-Shrawler-Request'] = '1';
      options.body = JSON.stringify(payload);
    }
    const response = await fetch(path, options);
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || `Request failed (${response.status})`);
    return data;
  }
  function error(message) {
    $('ranking-error').textContent = message;
    $('ranking-error').hidden = !message;
  }
  function node(tag, text, className) {
    const item = document.createElement(tag);
    if (text !== undefined) item.textContent = text;
    if (className) item.className = className;
    return item;
  }
  function option(value, text) {
    const item = node('option', text); item.value = value; return item;
  }
  function busy(active) {
    $('preview-rules').disabled = active;
    $('save-ranking').disabled = active;
    $('cancel-job').hidden = !active;
  }
  function resetPages() { cursors = [null]; nextCursor = null; }
  function updateCategories() {
    const run = catalog.runs.find(item => item.id === $('ranking-run').value);
    $('ranking-category').replaceChildren(option('', 'Highest category score'));
    (run ? run.categories : []).forEach(category => $('ranking-category').append(option(category, category)));
  }
  async function refreshCatalog(preferred) {
    catalog = await api('/api/triage/catalog');
    const scan = $('scan').value;
    $('scan').replaceChildren(option('', 'Latest completed inventory scan'));
    catalog.scans.forEach(item => $('scan').append(option(item.id, `${item.short_id} · ${item.status} · ${item.started_at_utc} · ${item.domain}/${item.username}`)));
    if (catalog.scans.some(item => item.id === scan)) $('scan').value = scan;
    const selected = preferred || $('ranking-run').value;
    $('ranking-run').replaceChildren(option('', 'Select a saved ranking'));
    catalog.runs.filter(item => item.status === 'completed').forEach(item => {
      $('ranking-run').append(option(item.id, `${item.started_at} · ${item.file_count.toLocaleString()} files · scan ${item.scan_id.slice(0, 8)} (${item.source_scan_status})`));
    });
    if (catalog.runs.some(item => item.id === selected && item.status === 'completed')) $('ranking-run').value = selected;
    else if ($('ranking-run').options.length > 1) $('ranking-run').selectedIndex = 1;
    updateCategories();
  }
  function summaryDetails(summary) {
    $('match-counts').hidden = !summary || !summary.rule_matches;
    $('counts-body').replaceChildren();
    if (!summary || !summary.rule_matches) return;
    const counts = node('ul');
    Object.entries(summary.rule_matches).sort().forEach(([id, count]) => counts.append(node('li', `${id}: ${count.toLocaleString()} matches`)));
    $('counts-body').append(counts, node('p', 'Examples from up to 20 different observed directories (not a statistical sample):'));
    const samples = node('ul');
    (summary.samples || []).forEach(item => samples.append(node('li', `${item.priority} · ${item.unc_path}`)));
    $('counts-body').append(samples);
  }
  async function showExplanation(item, isPreview) {
    $('explanation-title').textContent = item.file_name;
    $('explanation-path').textContent = item.unc_path;
    $('explanation-body').replaceChildren(node('p', 'Loading explanation…'));
    $('explanation-dialog').showModal();
    try {
      const params = new URLSearchParams({run: $('ranking-run').value, file_id: item.file_id});
      const detail = isPreview ? item : await api(`/api/triage/explain?${params}`);
      const body = $('explanation-body');
      body.replaceChildren(node('p', `Overall priority ${detail.priority}. Metadata evidence only.`));
      body.append(node('pre', JSON.stringify(detail.category_scores, null, 2)));
      if (!detail.signals.length) body.append(node('p', 'No ranking rule matched this file.'));
      detail.signals.forEach(signal => {
        const section = node('section');
        section.append(node('strong', `+${signal.credited_points} · ${signal.description}`));
        section.append(node('p', `${signal.category} / ${signal.signal_group} · ${signal.rule_id}${signal.capped_by_rule ? ` · contribution capped by ${signal.capped_by_rule}` : ''}`));
        section.append(node('pre', JSON.stringify(signal.evidence, null, 2)));
        body.append(section);
      });
      if (detail.rule_diagnostics) {
        const section = node('details'); section.append(node('summary', 'Why other rules did not match'));
        const failures = detail.rule_diagnostics.filter(rule => !rule.matched);
        section.append(node('pre', failures.map(rule => `${rule.rule_id}: ${rule.failed_conditions.join(', ')}`).join('\n') || 'Every rule matched.'));
        body.append(section);
      }
    } catch (exception) { $('explanation-body').replaceChildren(node('p', exception.message)); }
  }
  function render(data, isPreview = false) {
    $('ranked-files').replaceChildren();
    data.items.forEach(item => {
      const row = node('tr');
      row.append(node('td', String(item.review_score), 'ranking-score'), node('td', item.file_name), node('td', item.unc_path, 'ranking-path'));
      row.append(node('td', item.signals.filter(signal => signal.credited_points > 0).map(signal => signal.description).join('; ') || 'No supporting signals', 'ranking-reasons'));
      const cell = node('td'); const button = node('button', 'Explain', 'button');
      button.type = 'button'; button.addEventListener('click', () => showExplanation(item, isPreview)); cell.append(button); row.append(cell);
      $('ranked-files').append(row);
    });
    if (!data.items.length) { const row = node('tr'); const cell = node('td', 'No files match this ranking filter.'); cell.colSpan = 5; row.append(cell); $('ranked-files').append(row); }
    $('ranking-category').disabled = isPreview;
    $('ranking-min').disabled = isPreview;
    nextCursor = isPreview ? null : data.next_cursor;
    $('ranking-prev').disabled = isPreview || cursors.length === 1;
    $('ranking-next').disabled = !nextCursor;
    $('ranking-page').textContent = isPreview ? 'Preview · first 100 candidates' : `Page ${cursors.length}`;
    $('ranking-summary').textContent = `${isPreview ? 'Unsaved preview' : 'Saved ranking'} · ${data.files_scored.toLocaleString()} observed files scored${data.summary && data.summary.positive_files !== undefined ? ` · ${data.summary.positive_files.toLocaleString()} with positive priority` : ''}.`;
    summaryDetails(data.summary);
  }
  async function loadResults() {
    const sequence = ++requestSequence;
    if (preview) { render(preview, true); return; }
    const run = $('ranking-run').value;
    if (!run) return;
    const minimum = Number($('ranking-min').value);
    if (!Number.isInteger(minimum) || minimum < 0) { error('Minimum score must be a nonnegative integer.'); return; }
    const params = new URLSearchParams({run, category: $('ranking-category').value, min_score: String(minimum)});
    const cursor = cursors[cursors.length - 1];
    if (cursor) { params.set('after_score', String(cursor[0])); params.set('after_id', cursor[1]); }
    try { const data = await api(`/api/triage/files?${params}`); if (sequence === requestSequence) { render(data); error(''); } }
    catch (exception) { if (sequence === requestSequence) error(exception.message); }
  }
  async function startJob(isPreview) {
    error(''); busy(true); $('job-summary').hidden = true;
    try {
      const job = await api('/api/triage/jobs', {scan_id: $('scan').value || null, rules_toml: $('rules-toml').value, builtins: $('builtins').checked, preview: isPreview});
      currentJob = job.id; handledJob = null;
      $('job-status').textContent = 'Starting offline ranking…';
      await pollJob();
    } catch (exception) { error(exception.message); busy(false); }
  }
  async function pollJob() {
    try {
      const {job} = await api('/api/triage/job');
      if (!job) return;
      currentJob = job.id;
      busy(job.status === 'running');
      $('job-status').textContent = `${job.phase} · ${job.processed.toLocaleString()} files`;
      if (job.status === 'failed') error(job.error);
      if (job.status === 'completed' && handledJob !== currentJob) {
        handledJob = currentJob;
        resetPages();
        $('job-summary').hidden = false;
        $('job-summary').textContent = `${job.preview ? 'Preview finished; no ranking saved.' : 'Ranking saved.'} Source scan status: ${job.result.scan_status}.`;
        if (job.preview) {
          preview = job.candidates; ++requestSequence;
          if (!$('ranking-run').querySelector('option[value="__preview"]')) $('ranking-run').append(option('__preview', 'Unsaved preview (first 100 candidates)'));
          $('ranking-run').value = '__preview'; updateCategories(); render(preview, true);
        }
        else { preview = null; await refreshCatalog(job.result.run_id); await loadResults(); }
      }
    } catch (exception) { error(exception.message); }
  }
  const split = id => $(id).value.split(',').map(value => value.trim()).filter(Boolean);
  const quoted = value => JSON.stringify(value);
  const array = values => `[${values.map(quoted).join(', ')}]`;
  $('builder-context').addEventListener('change', () => {
    const mode = $('builder-context').value;
    $('builder-depth-label').hidden = mode === 'none';
    $('builder-names-label').hidden = mode !== 'named';
    ['siblings', 'minimum'].forEach(id => $(`builder-${id}-label`).hidden = mode !== 'siblings');
    ['host', 'share', 'path'].forEach(id => $(`builder-${id}-label`).hidden = mode !== 'subtree');
  });
  $('builder-form').addEventListener('submit', event => {
    event.preventDefault();
    const id = $('builder-id').value.trim();
    const mode = $('builder-context').value;
    const fragments = split('builder-fragments'); const extensions = split('builder-extensions');
    if (!fragments.length && !extensions.length && mode === 'none') { error('Choose a filename, extension, or context condition.'); return; }
    let text = '\n'; const tag = `${id}.context`;
    if (mode !== 'none') {
      text += `[[contexts]]\nid = ${quoted(tag)}\ntag = ${quoted(tag)}\napply_to_descendants = ${Number($('builder-depth').value)}\n`;
      if (mode === 'named') text += `directory_name_any = ${array(split('builder-names'))}\n`;
      if (mode === 'siblings') text += `sibling_name_any = ${array(split('builder-siblings'))}\nminimum_distinct_patterns = ${Number($('builder-minimum').value)}\n`;
      if (mode === 'subtree') text += ['host', 'share', 'path'].map(key => `${key} = ${quoted($(`builder-${key}`).value.trim())}`).join('\n') + '\n';
    }
    text += `\n[[rules]]\nid = ${quoted(id)}\ndescription = ${quoted(`Custom review rule: ${id}`)}\ncategory = ${quoted($('builder-category').value.trim())}\nsignal_group = ${quoted($('builder-group').value.trim())}\npoints = ${Number($('builder-points').value)}\n[rules.when]\n`;
    if (fragments.length) text += `filename_contains_any = ${array(fragments)}\n`;
    if (extensions.length) text += `extension_any = ${array(extensions)}\n`;
    if (mode !== 'none') text += `context_any = [${quoted(tag)}]\n`;
    $('rules-toml').value += text;
    $('rules-toml').focus(); error('');
  });
  $('export-rules').addEventListener('click', () => {
    const url = URL.createObjectURL(new Blob([$('rules-toml').value], {type: 'text/plain'}));
    const link = node('a'); link.href = url; link.download = 'shrawler-triage-rules.toml'; link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  });
  $('import-rules').addEventListener('change', async event => {
    const file = event.target.files[0];
    if (!file) return;
    if (file.size > 65536) { error('Custom rules must be at most 64 KiB.'); return; }
    $('rules-toml').value = await file.text();
  });
  $('preview-rules').addEventListener('click', () => startJob(true));
  $('save-ranking').addEventListener('click', () => startJob(false));
  $('cancel-job').addEventListener('click', async () => { try { await api('/api/triage/cancel', {}); $('job-status').textContent = 'Cancellation requested…'; } catch (exception) { error(exception.message); } });
  $('ranking-run').addEventListener('change', () => {
    if ($('ranking-run').value === '__preview') return;
    preview = null; $('ranking-run').querySelector('option[value="__preview"]')?.remove();
    resetPages(); updateCategories(); loadResults();
  });
  ['ranking-category', 'ranking-min'].forEach(id => $(id).addEventListener('change', () => { preview = null; resetPages(); loadResults(); }));
  $('ranking-prev').addEventListener('click', () => { if (cursors.length > 1) { cursors.pop(); loadResults(); } });
  $('ranking-next').addEventListener('click', () => { if (nextCursor) { cursors.push(nextCursor); loadResults(); } });
  $('refresh-rankings').addEventListener('click', async () => { try { preview = null; resetPages(); await refreshCatalog(); await loadResults(); } catch (exception) { error(exception.message); } });
  $('close-explanation').addEventListener('click', () => $('explanation-dialog').close());
  $('explanation-dialog').addEventListener('click', event => { if (event.target === $('explanation-dialog')) $('explanation-dialog').close(); });
  (async () => {
    try {
      const status = await api('/api/status');
      $('mode').textContent = status.retrieval_enabled ? 'Scoring is offline' : 'Offline session';
      await refreshCatalog(); await loadResults(); await pollJob();
      setInterval(pollJob, 1500);
    } catch (exception) { error(exception.message); busy(true); $('cancel-job').hidden = true; }
  })();
})();
