(() => {
  'use strict';
  const $ = id => document.getElementById(id);
  const token = new URLSearchParams(location.hash.slice(1)).get('token') || '';
  history.replaceState(null, '', location.pathname);
  $('ranking-link').href = '/triage' + (token ? `#token=${encodeURIComponent(token)}` : '');

  let catalog = {runs: [], scans: []};
  let currentJob = null;
  let handledJob = null;
  let offset = 0;
  const pageSize = 100;

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
    $('assessment-error').textContent = message;
    $('assessment-error').hidden = !message;
  }
  function node(tag, text, className) {
    const item = document.createElement(tag);
    if (text !== undefined) item.textContent = text;
    if (className) item.className = className;
    return item;
  }
  function option(value, text) { const item = node('option', text); item.value = value; return item; }
  function selectedRun() { return $('assessment-run').value || null; }
  function busy(active) {
    $('start-assessment').disabled = active;
    $('check-gateway').disabled = active;
    $('cancel-assessment').hidden = !active;
  }

  async function loadCatalog(preferred) {
    catalog = await api('/api/assessment/catalog');
    const scan = $('scan').value;
    $('scan').replaceChildren(option('', 'Latest completed inventory scan'));
    catalog.scans.forEach(item => $('scan').append(option(item.id, `${item.short_id} · ${item.status} · ${Number(item.file_count || 0).toLocaleString()} files · ${item.started_at_utc}`)));
    if (catalog.scans.some(item => item.id === scan)) $('scan').value = scan;
    const chosen = preferred || selectedRun();
    $('assessment-run').replaceChildren(option('', 'Latest assessment run'));
    catalog.runs.forEach(item => $('assessment-run').append(option(item.id, `${item.created_at} · ${Number(item.total_observed || 0).toLocaleString()} files · ${item.status}`)));
    if (catalog.runs.some(item => item.id === chosen)) $('assessment-run').value = chosen;
    else if ($('assessment-run').options.length > 1) $('assessment-run').selectedIndex = 1;
    $('gateway-summary').textContent = `Endpoint: ${catalog.endpoint} · model: ${catalog.model}`;
  }

  async function checkGateway() {
    error('');
    try {
      const report = await api('/api/assessment/check');
      if (!report.reachable) { $('gateway-summary').textContent = `Endpoint unreachable: ${report.error}`; return; }
      $('gateway-summary').textContent = `Endpoint HTTP ${report.http_status} in ${report.latency_ms} ms · resolved model ${report.resolved_model} · answers ${report.returns_answers} · usage ${report.returns_usage}`;
    } catch (exception) { error(exception.message); }
  }

  async function startAssessment() {
    error(''); busy(true); $('job-detail').hidden = true;
    try {
      const budget = Number($('budget').value || 0);
      const job = await api('/api/assessment/jobs', {
        scan_id: $('scan').value || null,
        prepare: $('prepare').checked,
        budget_seconds: Number.isFinite(budget) ? budget : 0,
        max_questions: Number($('max-questions').value || 200)
      });
      currentJob = job.id; handledJob = null;
      $('job-status').textContent = 'Starting assessment…';
      pollJob();
    } catch (exception) { error(exception.message); busy(false); }
  }

  async function pollJob() {
    try {
      const {job} = await api('/api/assessment/job');
      if (!job) { busy(false); return; }
      currentJob = job.id;
      const running = job.status === 'running';
      busy(running);
      const processed = Number(job.processed || 0);
      const total = Number(job.total || 0);
      const finished = !running && handledJob === currentJob;
      $('job-status').textContent = running
        ? `${job.phase} · ${processed.toLocaleString()}${total ? ` / ${total.toLocaleString()}` : ''} files`
        : (job.status === 'completed' ? `Completed · ${processed.toLocaleString()} assessed` : `Job ${job.status}`);
      if (job.error) error(job.error);
      if (running) {
        $('job-detail').hidden = false;
        $('job-detail').textContent = `pending ${Number(job.pending||0).toLocaleString()} · failed ${Number(job.failed||0).toLocaleString()}`;
        return;
      }
      $('job-detail').hidden = true;
      if (handledJob !== currentJob) {
        handledJob = currentJob;
        busy(false);
        if (job.assessment_run_id) {
          await loadCatalog(job.assessment_run_id);
          await loadCoverage();
          await loadResults();
        }
      }
    } catch (exception) { error(exception.message); }
  }

  async function loadCoverage() {
    const run = selectedRun();
    const params = new URLSearchParams();
    if (run) params.set('run', run);
    const status = await api(`/api/assessment/status?${params}`);
    $('coverage-summary').textContent = `${status.total_observed.toLocaleString()} observed · ${status.assessed.toLocaleString()} assessed · ${status.in_flight.toLocaleString()} in-flight · ${status.pending.toLocaleString()} pending · ${status.failed.toLocaleString()} failed · reconciled ${status.reconciled ? 'yes' : 'NO'}`;
  }

  async function loadDirectoryCoverage() {
    const run = selectedRun();
    const params = new URLSearchParams();
    if (run) params.set('run', run);
    const data = await api(`/api/assessment/coverage?${params}`);
    const list = $('coverage-directories');
    list.replaceChildren();
    data.directories.slice(0, 500).forEach(entry => {
      const counts = Object.entries(entry.counts).map(([key, value]) => `${key} ${value}`).join(', ');
      list.append(node('p', `${entry.host || ''}\\\\${entry.share || ''}${entry.directory || ''} — ${counts} (${entry.enumeration || ''})`));
    });
    if (!data.directories.length) list.append(node('p', 'No directory context stored for this run yet.'));
  }

  async function loadResults() {
    const run = selectedRun();
    const params = new URLSearchParams({limit: String(pageSize), offset: String(offset)});
    if (run) params.set('run', run);
    if ($('label').value) params.set('label', $('label').value);
    if ($('missed').checked) params.set('missed', '1');
    const data = await api(`/api/assessment/files?${params}`);
    const body = $('assessment-files');
    body.replaceChildren();
    data.items.forEach(item => {
      const row = node('tr');
      const priority = item.priority_name ? `${item.priority} ${item.priority_name}` : item.choice;
      row.append(node('td', priority, 'ranking-priority'));
      row.append(node('td', item.file_name));
      row.append(node('td', item.unc_path, 'ranking-path'));
      const distribution = item.distribution ? Object.entries(item.distribution).map(([key, value]) => `${key} ${Number(value).toFixed(2)}`).join(', ') : '—';
      row.append(node('td', distribution));
      body.append(row);
    });
    if (!data.items.length) {
      const row = node('tr');
      const cell = node('td', 'No assessed candidates match this filter.', 'ranking-empty');
      cell.colSpan = 4; row.append(cell); body.append(row);
    }
    $('results-summary').textContent = `Model priority is metadata-based review value, not confirmed content. Showing ${data.items.length} result(s).`;
    $('results-page').textContent = `Page ${Math.floor(offset / pageSize) + 1}`;
    $('results-prev').disabled = offset === 0;
    $('results-next').disabled = data.items.length < pageSize;
  }

  $('check-gateway').addEventListener('click', checkGateway);
  $('start-assessment').addEventListener('click', startAssessment);
  $('cancel-assessment').addEventListener('click', async () => {
    try { await api('/api/assessment/cancel', {}); $('job-status').textContent = 'Cancellation requested…'; }
    catch (exception) { error(exception.message); }
  });
  $('refresh-runs').addEventListener('click', async () => {
    try { await loadCatalog(); await loadCoverage(); await loadResults(); } catch (exception) { error(exception.message); }
  });
  $('refresh-by-directory').addEventListener('click', async () => {
    try { await loadDirectoryCoverage(); } catch (exception) { error(exception.message); }
  });
  $('refresh-results').addEventListener('click', async () => {
    offset = 0; try { await loadResults(); } catch (exception) { error(exception.message); }
  });
  $('assessment-run').addEventListener('change', async () => {
    offset = 0; try { await loadCoverage(); await loadResults(); } catch (exception) { error(exception.message); }
  });
  $('label').addEventListener('change', () => { offset = 0; loadResults().catch(exception => error(exception.message)); });
  $('missed').addEventListener('change', () => { offset = 0; loadResults().catch(exception => error(exception.message)); });
  $('results-prev').addEventListener('click', () => { offset = Math.max(0, offset - pageSize); loadResults().catch(exception => error(exception.message)); });
  $('results-next').addEventListener('click', () => { offset += pageSize; loadResults().catch(exception => error(exception.message)); });

  (async () => {
    try {
      await loadCatalog();
      await loadCoverage();
      await loadResults();
      await checkGateway();
      setInterval(pollJob, 2000);
    } catch (exception) { error(exception.message); }
  })();
})();
