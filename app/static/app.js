(() => {
  const $ = id => document.getElementById(id);
  let apiKey = sessionStorage.getItem('zyrax_api_key') || '';
  let activeRunId = null;
  let pollHandle = null;
  let targets = [];
  if (apiKey) $('apiKey').value = apiKey;

  async function api(path, options = {}) {
    const response = await fetch(path, { ...options, headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${apiKey}`, ...(options.headers || {}) } });
    const body = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(body.detail || `Request failed (${response.status})`);
    return body;
  }
  function notify(message, error = false) {
    const row = document.createElement('div');
    row.className = 'feedrow';
    const meta = document.createElement('span');
    meta.textContent = `${new Date().toLocaleTimeString()} · ${error ? 'ERROR' : 'EVENT'}`;
    const detail = document.createElement('strong');
    detail.textContent = String(message);
    row.append(meta, detail);
    const feed = $('eventFeed');
    feed.prepend(row);
    while (feed.children.length > 100) feed.lastElementChild?.remove();
  }
  function setStatus(status) { $('runStatus').textContent = status.toUpperCase(); $('runStatus').className = `pill ${status === 'running' ? 'running' : ''}`; }
  async function refreshTargets() {
    targets = await api('/api/v1/targets');
    const select = $('targetSelect');
    select.replaceChildren();
    if (!targets.length) {
      const placeholder = document.createElement('option');
      placeholder.value = '';
      placeholder.textContent = 'Register a target first';
      select.append(placeholder);
      return;
    }
    for (const target of targets) {
      const option = document.createElement('option');
      option.value = target.id;
      option.textContent = `${target.name} · ${target.ip}:${target.port}`;
      select.append(option);
    }
  }
  async function refreshHistory() {
    const runs = await api('/api/v1/runs');
    const history = $('runHistory');
    history.replaceChildren();
    if (!runs.length) {
      history.textContent = 'No recorded runs yet.';
      history.className = 'empty';
      return;
    }
    history.className = '';
    for (const run of runs.slice(0, 8)) {
      const row = document.createElement('div');
      row.className = 'feedrow';
      const summary = document.createElement('div');
      const status = document.createElement('strong');
      status.textContent = String(run.status).toUpperCase();
      const timestamp = document.createElement('span');
      timestamp.textContent = new Date(run.started_at || Date.now()).toLocaleString();
      summary.append(status, document.createElement('br'), timestamp);
      const details = document.createElement('span');
      details.textContent = `${run.result?.requests_started ?? 0} requests · ${run.duration_seconds}s`;
      row.append(summary, details);
      history.append(row);
    }
  }
  function displayMetrics(result = {}) {
    $('mStarted').textContent = result.requests_started ?? 0;
    $('mSuccess').textContent = result.successful_responses ?? 0;
    $('mRate').textContent = Number(result.actual_requests_per_second ?? 0).toFixed(1);
    $('mLatency').textContent = result.latency_ms?.median == null ? '—' : result.latency_ms.median;
    $('mP95').textContent = result.latency_ms?.p95 == null ? '—' : result.latency_ms.p95;
    $('mErrors').textContent = (result.http_errors ?? 0) + (result.timeouts ?? 0) + (result.connection_errors ?? 0);
  }
  async function pollRun(id) {
    const record = await api(`/api/v1/runs/${id}`);
    const live = record.live || record.result || {};
    displayMetrics(live);
    setStatus(record.status);
    if (record.status !== 'running' && record.status !== 'queued') {
      clearInterval(pollHandle); pollHandle = null; activeRunId = null;
      $('startButton').disabled = false; $('stopButton').disabled = true;
      notify(`Run ${record.status}. ${record.result?.requests_started ?? 0} requests started.`);
      await refreshHistory();
    }
  }
  $('saveKey').addEventListener('click', async () => {
    apiKey = $('apiKey').value.trim();
    if (apiKey.length < 32) return notify('API key must be at least 32 characters.', true);
    sessionStorage.setItem('zyrax_api_key', apiKey);
    try { await refreshTargets(); await refreshHistory(); $('systemStatus').textContent = '● AUTHENTICATED'; notify('Control plane unlocked.'); }
    catch (error) { sessionStorage.removeItem('zyrax_api_key'); apiKey = ''; notify(error.message, true); }
  });
  $('targetForm').addEventListener('submit', async event => {
    event.preventDefault();
    try {
      const record = await api('/api/v1/targets', { method:'POST', body:JSON.stringify({name:$('targetName').value,ip:$('targetIp').value,port:Number($('targetPort').value),scheme:$('targetScheme').value}) });
      await refreshTargets(); notify(`Target registered: ${record.name} (${record.ip}:${record.port}).`);
    } catch (error) { notify(error.message, true); }
  });
  $('runForm').addEventListener('submit', async event => {
    event.preventDefault();
    if (!apiKey) return notify('Unlock the control plane first.', true);
    try {
      const record = await api('/api/v1/runs', { method:'POST', body:JSON.stringify({target_id:$('targetSelect').value,requests_per_second:Number($('rps').value),duration_seconds:Number($('duration').value),concurrency:Number($('concurrency').value)}) });
      activeRunId = record.id; $('startButton').disabled = true; $('stopButton').disabled = false; setStatus('running'); displayMetrics({});
      notify(`Measurement started for ${record.target.name}.`);
      pollHandle = setInterval(() => pollRun(activeRunId).catch(error => notify(error.message, true)), 1000);
      await pollRun(activeRunId);
    } catch (error) { notify(error.message, true); }
  });
  $('stopButton').addEventListener('click', async () => {
    if (!activeRunId) return;
    try { await api(`/api/v1/runs/${activeRunId}/stop`, {method:'POST'}); $('stopButton').disabled = true; notify('Stop requested.'); }
    catch (error) { notify(error.message, true); }
  });
  $('verifyAudit').addEventListener('click', async () => {
    try { const result = await api('/api/v1/audit/verify'); $('auditStatus').textContent = result.valid ? `VALID · ${result.checked_events} events · SHA-256 chain verified.` : `INVALID · failed at sequence ${result.failed_sequence}.`; }
    catch (error) { $('auditStatus').textContent = error.message; }
  });
  for (const id of ['rps','duration']) $(id).addEventListener('input', () => {
    const count = Number($('rps').value) * Number($('duration').value);
    $('budgetHint').textContent = `Request budget: ${count} total · maximum 300 · fixed GET / · response read capped at 16 KiB per request.`;
  });
  if (apiKey) $('saveKey').click();
})();
