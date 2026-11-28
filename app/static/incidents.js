(() => {
  'use strict';
  const $ = id => document.getElementById(id);
  const state = { alerts: [], selectedId: null, detail: null, busy: false };
  const statusLabels = { new: 'New', acknowledged: 'Acknowledged', investigating: 'Investigating', resolved: 'Resolved' };
  const severityLabels = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low' };
  const classificationLabels = { undetermined: 'Undetermined', true_positive: 'True positive', false_positive: 'False positive', benign: 'Benign' };

  function key() { return sessionStorage.getItem('zyrax_api_key') || ''; }
  async function api(path, options = {}) {
    const token = key();
    if (!token) throw new Error('Unlock the control plane with your API key first.');
    const headers = { Authorization: `Bearer ${token}`, ...(options.headers || {}) };
    if (options.body) headers['Content-Type'] = 'application/json';
    const response = await fetch(path, { ...options, headers });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(payload.detail || `Request failed (${response.status})`);
    return payload;
  }
  function node(tag, className, text) {
    const item = document.createElement(tag);
    if (className) item.className = className;
    if (text !== undefined && text !== null) item.textContent = String(text);
    return item;
  }
  function formatDate(value) {
    if (!value) return '—';
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString();
  }
  function setMessage(message, isError = false) {
    const detail = $('incidentDetail');
    detail.replaceChildren(node('div', isError ? 'incident-error' : 'incident-empty', message));
  }
  function filters() {
    return {
      status: $('incidentStatus').value,
      severity: $('incidentSeverity').value,
      classification: $('incidentClassification').value
    };
  }
  function visibleAlerts() {
    const query = $('incidentSearch').value.trim().toLowerCase();
    return state.alerts.filter(alert => {
      if (query && ![alert.title, alert.rule_id, alert.subject, alert.source].some(value => String(value || '').toLowerCase().includes(query))) return false;
      return true;
    });
  }
  function renderList() {
    const list = $('incidentList');
    list.replaceChildren();
    const alerts = visibleAlerts();
    $('incidentCount').textContent = `${alerts.length} alert${alerts.length === 1 ? '' : 's'}`;
    if (!alerts.length) {
      list.append(node('div', 'empty', state.alerts.length ? 'No alerts match this search.' : 'No alerts match the selected filters.'));
      return;
    }
    for (const alert of alerts) {
      const button = node('button', `incident-alert-card${alert.id === state.selectedId ? ' selected' : ''}`);
      button.type = 'button';
      button.setAttribute('aria-pressed', String(alert.id === state.selectedId));
      const top = node('div', 'incident-card-top');
      top.append(node('span', `severity severity-${alert.severity}`, severityLabels[alert.severity] || alert.severity));
      top.append(node('span', `status-tag status-${alert.status}`, statusLabels[alert.status] || alert.status));
      const title = node('strong', 'incident-card-title', alert.title || alert.rule_id);
      const meta = node('span', 'incident-card-meta', `${alert.rule_id} · ${alert.subject || 'Unknown subject'}`);
      const time = node('span', 'incident-card-time', formatDate(alert.updated_at || alert.last_seen));
      button.append(top, title, meta, time);
      button.addEventListener('click', () => loadDetail(alert.id));
      list.append(button);
    }
  }
  function renderActivity(activity) {
    const section = node('section', 'incident-section');
    section.append(node('h3', '', 'Investigation timeline'));
    const timeline = node('ol', 'incident-timeline');
    for (const entry of activity || []) {
      const item = node('li', 'timeline-item');
      const title = entry.activity_type === 'note_added' ? 'Analyst note' : 'Investigation updated';
      item.append(node('strong', '', title), node('time', '', formatDate(entry.created_at)));
      if (entry.note) item.append(node('p', 'timeline-note', entry.note));
      if (entry.old_status !== entry.new_status && entry.new_status) {
        item.append(node('p', 'timeline-change', `Status: ${statusLabels[entry.old_status] || entry.old_status} → ${statusLabels[entry.new_status] || entry.new_status}`));
      }
      if (entry.old_classification !== entry.new_classification && entry.new_classification) {
        item.append(node('p', 'timeline-change', `Classification: ${classificationLabels[entry.old_classification] || entry.old_classification} → ${classificationLabels[entry.new_classification] || entry.new_classification}`));
      }
      timeline.append(item);
    }
    if (!timeline.children.length) timeline.append(node('li', 'empty', 'No investigation activity has been recorded.'));
    section.append(timeline);
    return section;
  }
  function renderDetail(alert) {
    const root = $('incidentDetail');
    root.replaceChildren();
    const heading = node('div', 'incident-detail-heading');
    const titleBlock = node('div', '');
    titleBlock.append(node('div', 'eyebrow', `${alert.rule_id} · RULE ${alert.rule_version || ''}`), node('h2', '', alert.title || 'Detection alert'));
    const badges = node('div', 'incident-badges');
    badges.append(node('span', `severity severity-${alert.severity}`, severityLabels[alert.severity] || alert.severity));
    badges.append(node('span', `status-tag status-${alert.status}`, statusLabels[alert.status] || alert.status));
    heading.append(titleBlock, badges);
    root.append(heading);

    const summary = node('p', 'incident-description', alert.description || 'No description supplied.');
    root.append(summary);
    const rationale = node('div', 'incident-rationale');
    rationale.append(node('strong', '', 'Why this was detected'), node('p', '', alert.rationale || 'No detection rationale supplied.'));
    root.append(rationale);

    const facts = node('div', 'incident-facts');
    const entries = [
      ['Subject', alert.subject], ['Source', alert.source], ['Rule set', alert.ruleset_version],
      ['Events', alert.event_count], ['First seen', formatDate(alert.first_seen)], ['Last seen', formatDate(alert.last_seen)]
    ];
    for (const [label, value] of entries) {
      const fact = node('div', 'incident-fact');
      fact.append(node('span', '', label), node('strong', '', value ?? '—'));
      facts.append(fact);
    }
    root.append(facts);

    const controls = node('section', 'incident-section');
    controls.append(node('h3', '', 'Analyst decision'));
    const form = node('div', 'incident-controls');
    const statusLabel = node('label', '', 'Lifecycle status');
    const statusSelect = node('select');
    statusSelect.id = 'incidentDetailStatus';
    for (const [value, label] of Object.entries(statusLabels)) {
      const option = node('option', '', label); option.value = value; statusSelect.append(option);
    }
    statusSelect.value = alert.status;
    statusLabel.append(statusSelect);
    const classLabel = node('label', '', 'Classification');
    const classSelect = node('select');
    classSelect.id = 'incidentDetailClassification';
    for (const [value, label] of Object.entries(classificationLabels)) {
      const option = node('option', '', label); option.value = value; classSelect.append(option);
    }
    classSelect.value = alert.classification || 'undetermined';
    classLabel.append(classSelect);
    const save = node('button', 'btn', 'Save investigation');
    save.type = 'button';
    save.addEventListener('click', async () => {
      save.disabled = true;
      try {
        const updated = await api(`/api/v1/detection/alerts/${encodeURIComponent(alert.id)}`, {
          method: 'PATCH',
          body: JSON.stringify({ status: statusSelect.value, classification: classSelect.value })
        });
        state.detail = updated;
        await refreshAlerts(false);
        await loadDetail(alert.id);
      } catch (error) { showError(error.message); }
      finally { save.disabled = false; }
    });
    form.append(statusLabel, classLabel, save);
    controls.append(form);
    root.append(controls);

    const notes = node('section', 'incident-section');
    notes.append(node('h3', '', 'Investigation notes'));
    const noteForm = node('form', 'incident-note-form');
    const textarea = node('textarea');
    textarea.id = 'incidentNote';
    textarea.maxLength = 2000;
    textarea.rows = 3;
    textarea.placeholder = 'Record observations, validation steps, or investigation conclusions…';
    textarea.required = true;
    const noteMeta = node('div', 'incident-note-meta', 'Up to 2,000 characters. Notes are included in the investigation timeline.');
    const add = node('button', 'btn secondary', 'Add note');
    add.type = 'submit';
    noteForm.append(textarea, noteMeta, add);
    noteForm.addEventListener('submit', async event => {
      event.preventDefault();
      const note = textarea.value.trim();
      if (!note) return;
      add.disabled = true;
      try {
        await api(`/api/v1/detection/alerts/${encodeURIComponent(alert.id)}/notes`, {
          method: 'POST', body: JSON.stringify({ note })
        });
        await refreshAlerts(false);
        await loadDetail(alert.id);
      } catch (error) { showError(error.message); }
      finally { add.disabled = false; }
    });
    notes.append(noteForm);
    root.append(notes);

    const evidence = node('section', 'incident-section');
    const evidenceHead = node('div', 'incident-section-head');
    evidenceHead.append(node('h3', '', 'Evidence'));
    evidenceHead.append(node('span', 'incident-note-meta', 'Structured sensor evidence'));
    const pre = node('pre', 'incident-evidence', JSON.stringify(alert.evidence || {}, null, 2));
    evidence.append(evidenceHead, pre);
    root.append(evidence);

    root.append(renderActivity(alert.activity));
    const provenance = node('div', 'incident-provenance', `Fingerprint · ${alert.fingerprint || 'not available'}`);
    root.append(provenance);
  }
  function showError(message) {
    const status = $('incidentCount');
    status.textContent = message;
    status.classList.add('error-text');
  }
  async function loadDetail(id) {
    state.selectedId = id;
    renderList();
    try {
      const detail = await api(`/api/v1/detection/alerts/${encodeURIComponent(id)}`);
      state.detail = detail;
      renderDetail(detail);
    } catch (error) { setMessage(error.message, true); }
  }
  async function refreshAlerts(keepSelection = true) {
    if (state.busy) return;
    state.busy = true;
    $('incidentRefresh').disabled = true;
    try {
      const query = new URLSearchParams({ limit: '200' });
      for (const [name, value] of Object.entries(filters())) if (value) query.set(name, value);
      state.alerts = await api(`/api/v1/detection/alerts?${query.toString()}`);
      renderList();
      if (keepSelection && state.selectedId && state.alerts.some(item => item.id === state.selectedId)) {
        await loadDetail(state.selectedId);
      } else if (!keepSelection || !state.alerts.some(item => item.id === state.selectedId)) {
        state.selectedId = null;
        state.detail = null;
        setMessage(state.alerts.length ? 'Select an alert to inspect its evidence and investigation history.' : 'No alerts found. Import telemetry and run detection evaluation to populate this queue.');
        renderList();
      }
    } catch (error) { setMessage(error.message, true); }
    finally { state.busy = false; $('incidentRefresh').disabled = false; }
  }
  $('incidentRefresh').addEventListener('click', () => refreshAlerts());
  $('saveKey').addEventListener('click', () => refreshAlerts(false));
  for (const id of ['incidentStatus', 'incidentSeverity', 'incidentClassification']) {
    $(id).addEventListener('change', () => refreshAlerts(false));
  }
  $('incidentSearch').addEventListener('input', renderList);
  window.addEventListener('storage', event => {
    if (event.key === 'zyrax_api_key' && event.newValue) refreshAlerts(false);
  });
  if (key()) refreshAlerts(false);
})();