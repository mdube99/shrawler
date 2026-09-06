(() => {
  'use strict';
  const $ = id => document.getElementById(id);
  const token = new URLSearchParams(location.hash.slice(1)).get('token') || '';
  history.replaceState(null, '', location.pathname);
  $('inventory-link').href = '/' + (token ? `#token=${encodeURIComponent(token)}` : '');
  const selectedFiles = new Set();
  let manifests = [];
  let retrievalEnabled = false;
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
  function resetPages() { selectedFiles.clear(); cursors = [null]; nextCursor = null; }
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
      const positiveReasons = item.signals.filter(signal => signal.credited_points > 0).map(signal => signal.description);
      const fallbackReasons = item.signals.filter(signal => signal.category === 'extension-fallback').map(signal => signal.description);
      row.append(node('td', (positiveReasons.length ? positiveReasons : fallbackReasons).join('; ') || 'No supporting signals', 'ranking-reasons'));
      const cell = node('td');
      const fileActions = node('a', 'View / download / Nemesis', 'button');
      fileActions.href = `/#file=${encodeURIComponent(item.file_id)}${token ? `&token=${encodeURIComponent(token)}` : ''}`;
      cell.append(fileActions);
      if (!isPreview) {
        const label = node('label', ' Collect ');
        const select = node('input'); select.type = 'checkbox'; select.checked = selectedFiles.has(item.file_id);
        select.addEventListener('change', () => { if (select.checked) selectedFiles.add(item.file_id); else selectedFiles.delete(item.file_id); });
        label.prepend(select); cell.append(label);
      }
      const button = node('button', 'Explain', 'button');
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
  ['ranking-category', 'ranking-min'].forEach(id => $(id).addEventListener('change', () => {
    if (id === 'ranking-category' && $('ranking-category').value === 'extension-fallback') $('ranking-min').value = '0';
    preview = null; resetPages(); loadResults();
  }));
  $('ranking-prev').addEventListener('click', () => { if (cursors.length > 1) { cursors.pop(); loadResults(); } });
  $('ranking-next').addEventListener('click', () => { if (nextCursor) { cursors.push(nextCursor); loadResults(); } });
  $('refresh-rankings').addEventListener('click', async () => { try { preview = null; resetPages(); await refreshCatalog(); await loadResults(); } catch (exception) { error(exception.message); } });
  $('close-explanation').addEventListener('click', () => $('explanation-dialog').close());
  $('explanation-dialog').addEventListener('click', event => { if (event.target === $('explanation-dialog')) $('explanation-dialog').close(); });
  function showCollection() {
    const manifest = manifests.find(item => item.id === $('collection-manifest').value);
    $('collection-items').replaceChildren();
    $('collection-run').disabled = !manifest || !retrievalEnabled;
    $('collection-export').disabled = !manifest;
    if (!manifest) { $('collection-status').textContent = 'No saved collection manifests.'; return; }
    $('collection-status').textContent = `${manifest.expected_files} planned files · ${manifest.expected_bytes} expected bytes · ${manifest.consumed_bytes} received bytes · limits: ${manifest.max_file_size} per file / ${manifest.max_total_bytes} total. Previously collected files are skipped; status does not establish freshness.${retrievalEnabled ? '' : ' Offline session: retrieval disabled.'}`;
    manifest.items.forEach(item => {
      const row = node('tr');
      [item.unc_path, item.size_bytes, item.reasons.join('; '), item.status, item.error || item.local_path || ''].forEach(value => row.append(node('td', String(value))));
      $('collection-items').append(row);
    });
  }
  async function refreshCollection(preferred) {
    const selected = preferred || $('collection-manifest').value;
    manifests = (await api('/api/collection')).items;
    $('collection-manifest').replaceChildren(...manifests.map(item => option(item.id, `${item.name} · ${item.created_at}`)));
    if (manifests.some(item => item.id === selected)) $('collection-manifest').value = selected;
    showCollection();
  }
  $('collection-manifest').addEventListener('change', showCollection);
  $('collection-refresh').addEventListener('click', () => refreshCollection().catch(exception => error(exception.message)));
  $('collection-create').addEventListener('click', async () => {
    try {
      if (preview || !selectedFiles.size) throw new Error('Select candidates from a saved ranking first.');
      const manifest = await api('/api/collection/create', {
        run_id: $('ranking-run').value, category: $('ranking-category').value || null,
        min_score: Number($('ranking-min').value), limit: 10000,
        file_ids: [...selectedFiles], name: $('collection-name').value,
        max_file_size: Number($('collection-file-limit').value), max_total_bytes: Number($('collection-total-limit').value)
      });
      await refreshCollection(manifest.id); error('');
    } catch (exception) { error(exception.message); }
  });
  $('collection-run').addEventListener('click', async () => {
    $('collection-run').disabled = true;
    $('collection-status').textContent = 'Collecting exact paths from SMB. Outcomes are saved after each file.';
    try { await api('/api/collection/run', {id: $('collection-manifest').value}); await refreshCollection(); error(''); }
    catch (exception) { error(exception.message); $('collection-run').disabled = !retrievalEnabled; }
  });
  $('collection-export').addEventListener('click', () => {
    const manifest = manifests.find(item => item.id === $('collection-manifest').value);
    if (!manifest) return;
    const url = URL.createObjectURL(new Blob([JSON.stringify(manifest, null, 2)], {type: 'application/json'}));
    const link = node('a'); link.href = url; link.download = `collection-${manifest.id}.json`; link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  });
  let familyScan = null;
  let familyOffset = 0;
  function reviewControls(scope, target) {
    const controls = node('div', undefined, 'ranking-controls');
    const disposition = node('select');
    disposition.setAttribute('aria-label', 'Review disposition');
    ['reviewed', 'relevant', 'defer', 'exclude'].forEach(value => disposition.append(option(value, value)));
    const note = node('input'); note.placeholder = 'Review note'; note.maxLength = 4000;
    note.setAttribute('aria-label', 'Review note');
    const save = node('button', `Save ${scope} decision`, 'button'); save.type = 'button';
    save.addEventListener('click', async () => {
      try {
        const event = await api('/api/review/decide', {scope, target, disposition: disposition.value, note: note.value});
        $('review-undo-id').value = event.event_id;
        $('families-status').textContent = `Saved ${scope} decision ${event.event_id}: ${event.disposition}. Run a new ranking to apply it. Existing manifests retain their reviewed selection.`;
        error('');
      } catch (exception) { error(exception.message); }
    });
    controls.append(disposition, note, save); return controls;
  }
  async function loadFamilies() {
    familyScan = $('scan').value || familyScan || catalog.scans.find(item => item.status === 'completed')?.id;
    if (!familyScan) throw new Error('Select a scan first.');
    const result = await api(`/api/review/families?${new URLSearchParams({scan: familyScan, offset: String(familyOffset)})}`);
    $('families-list').replaceChildren();
    $('families-prev').disabled = familyOffset === 0;
    $('families-next').disabled = result.items.length < 100;
    result.items.forEach(family => {
      const section = node('details');
      section.append(node('summary', `${family.file_count} files · ${family.representative} · ${family.first_mtime} — ${family.last_mtime}${family.review ? ` · ${family.review.disposition} (event ${family.review.id})` : ''}`));
      section.append(reviewControls('family', family.family_id));
      const members = node('div'); const more = node('button', 'Load members', 'button'); more.type = 'button';
      let offset = 0;
      more.addEventListener('click', async () => {
        try {
          const page = await api(`/api/review/families?${new URLSearchParams({scan: familyScan, family: family.family_id, offset: String(offset)})}`);
          page.items.forEach(item => { const member = node('div'); member.append(node('p', item.unc_path), reviewControls('file', item.file_id)); members.append(member); });
          offset += page.items.length; more.disabled = page.items.length < 100; more.textContent = 'Load more members';
        } catch (exception) { error(exception.message); }
      });
      section.append(members, more); $('families-list').append(section);
    });
  }
  $('families-build').addEventListener('click', async () => {
    $('families-build').disabled = true; $('families-status').textContent = 'Grouping saved metadata…';
    try {
      const result = await api('/api/review/build', {scan_id: $('scan').value || null});
      familyScan = result.scan_id; familyOffset = 0; await loadFamilies();
      $('families-status').textContent = `${result.files} files in ${result.families} provisional families.`;
    } catch (exception) { error(exception.message); }
    finally { $('families-build').disabled = false; }
  });
  $('families-refresh').addEventListener('click', () => loadFamilies().catch(exception => error(exception.message)));
  $('families-prev').addEventListener('click', () => { familyOffset = Math.max(0, familyOffset - 100); loadFamilies().catch(exception => error(exception.message)); });
  $('families-next').addEventListener('click', () => { familyOffset += 100; loadFamilies().catch(exception => error(exception.message)); });
  $('review-undo').addEventListener('click', async () => {
    try { await api('/api/review/undo', {event_id: Number($('review-undo-id').value)}); $('families-status').textContent = 'Decision undone. Run a new ranking to apply the change.'; await loadFamilies(); }
    catch (exception) { error(exception.message); }
  });
  $('families-hash').addEventListener('click', async () => {
    try {
      $('families-status').textContent = 'Hashing local collected evidence…';
      const result = await api('/api/review/hashes', {});
      $('families-status').textContent = `${result.hashed_files} local files hashed; ${result.duplicates.length} confirmed duplicate groups.`;
      $('families-list').replaceChildren(node('pre', JSON.stringify(result.duplicates, null, 2)));
    } catch (exception) { error(exception.message); }
  });
  (async () => {
    try {
      const status = await api('/api/status');
      retrievalEnabled = status.retrieval_enabled;
      await refreshCollection();
      $('mode').textContent = status.retrieval_enabled ? 'Scoring is offline' : 'Offline session';
      await refreshCatalog(); await loadResults(); await pollJob();
      setInterval(pollJob, 1500);
    } catch (exception) { error(exception.message); busy(true); $('cancel-job').hidden = true; }
  })();
})();
