document.addEventListener('DOMContentLoaded', () => {
  if (typeof io === 'undefined') return;
  const socket = io();
  window.socDashboardSocket = socket;
  const connection = document.getElementById('connection-status');

  function setConnection(state, label) {
    if (!connection) return;
    connection.classList.remove('is-connected', 'is-disconnected', 'is-connecting');
    connection.classList.add(`is-${state}`);
    const text = connection.querySelector('.connection-label');
    if (text) text.textContent = label;
  }
  socket.on('connect', () => setConnection('connected', 'Live stream connected'));
  socket.on('disconnect', () => setConnection('disconnected', 'Live stream reconnecting'));
  socket.on('connect_error', () => setConnection('disconnected', 'Live stream unavailable'));

  const toastContainer = document.getElementById('liveToastContainer');
  function showToast(title, body, variant) {
    if (!toastContainer || typeof bootstrap === 'undefined') return;
    const toastEl = document.createElement('div');
    toastEl.className = `toast align-items-center text-bg-${variant || 'danger'} border-0`;
    toastEl.setAttribute('role', 'status');
    const row = document.createElement('div');
    row.className = 'd-flex';
    const content = document.createElement('div');
    content.className = 'toast-body';
    const heading = document.createElement('strong');
    heading.textContent = title;
    content.append(heading, document.createElement('br'), document.createTextNode(body));
    const close = document.createElement('button');
    close.type = 'button'; close.className = 'btn-close btn-close-white me-2 m-auto';
    close.setAttribute('data-bs-dismiss', 'toast'); close.setAttribute('aria-label', 'Close');
    row.append(content, close); toastEl.append(row); toastContainer.append(toastEl);
    const toast = new bootstrap.Toast(toastEl, { delay: 6000 });
    toast.show();
    toastEl.addEventListener('hidden.bs.toast', () => toastEl.remove());
  }
  const severityVariant = { CRITICAL: 'danger', HIGH: 'warning', MEDIUM: 'secondary', LOW: 'primary' };
  const severityColor = { CRITICAL: '#ef6c70', HIGH: '#e89154', MEDIUM: '#e4bb5e', LOW: '#59a9ef', INFO: '#72889b' };
  const badgeClass = { CRITICAL: 'badge-critical', HIGH: 'badge-high', MEDIUM: 'badge-medium', LOW: 'badge-low' };
  const safeText = (value) => (value === null || value === undefined || value === '' ? '—' : String(value));
  const localTime = (value) => {
    const date = value ? new Date(value) : new Date();
    return Number.isNaN(date.getTime()) ? 'now' : date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  };

  function updateSeverityChart(alert) {
    const chart = window.socSeverityChart;
    if (!chart) return;
    let index = chart.data.labels.indexOf(alert.severity);
    if (chart.data.labels.length === 1 && chart.data.labels[0] === 'No alerts') {
      chart.data.labels = []; chart.data.datasets[0].data = [];
    }
    index = chart.data.labels.indexOf(alert.severity);
    if (index < 0) {
      chart.data.labels.push(alert.severity);
      chart.data.datasets[0].data.push(1);
      chart.data.datasets[0].backgroundColor.push(severityColor[alert.severity] || '#72889b');
      chart.data.datasets[0].borderColor.push('#0d1926');
    } else chart.data.datasets[0].data[index] = Number(chart.data.datasets[0].data[index]) + 1;
    chart.update('none');
    const legend = document.querySelector(`[data-severity-count="${alert.severity}"]`);
    if (legend) legend.textContent = String(Number(legend.textContent || 0) + 1);
  }

  function updateTimeline() {
    const chart = window.socTimelineChart;
    if (!chart || !chart.data.datasets[0]) return;
    const values = chart.data.datasets[0].data;
    if (values.length) values[values.length - 1] = Number(values[values.length - 1] || 0) + 1;
    chart.update('none');
  }

  function bumpBarChart(chart, label) {
    if (!chart || !label) return;
    let index = chart.data.labels.indexOf(label);
    if (index < 0 && chart.data.labels.length < 5) {
      chart.data.labels.push(label); chart.data.datasets[0].data.push(1); index = chart.data.labels.length - 1;
    } else if (index < 0) index = chart.data.datasets[0].data.indexOf(Math.min(...chart.data.datasets[0].data));
    if (index >= 0) { chart.data.datasets[0].data[index] = Number(chart.data.datasets[0].data[index] || 0) + 1; chart.update('none'); }
  }

  function updateSourceChart(source) {
    const chart = window.socSourcesChart;
    if (!chart || !source) return;
    let index = chart.data.labels.indexOf(source);
    if (index < 0) {
      if (chart.data.labels.length === 0) { chart.data.labels.push(source); chart.data.datasets[0].data.push(1); chart.data.datasets[0].backgroundColor.push('#39d6ad'); chart.data.datasets[0].borderColor.push('#0d1926'); }
      else return;
    } else chart.data.datasets[0].data[index] = Number(chart.data.datasets[0].data[index] || 0) + 1;
    chart.update('none');
  }

  function insertLiveEvent(log) {
    const body = document.getElementById('liveEventsBody');
    if (!body) return;
    const filters = { search: (body.dataset.search || '').toLowerCase(), severity: body.dataset.severity || '', source: body.dataset.source || '' };
    const searchable = [log.event_type, log.source_ip, log.hostname, log.message, log.source].join(' ').toLowerCase();
    if ((filters.search && !searchable.includes(filters.search)) || (filters.severity && filters.severity !== log.severity) || (filters.source && filters.source !== log.source)) return;
    const empty = body.querySelector('.live-events-empty'); if (empty) empty.remove();
    const row = document.createElement('tr');
    [localTime(log.timestamp), safeText(log.event_type), safeText(log.severity), safeText(log.source_ip), safeText(log.hostname), safeText(log.message)].forEach((value, i) => {
      const cell = document.createElement('td'); cell.textContent = value;
      if ([1, 3, 4].includes(i)) cell.className = 'small-mono';
      if (i === 5) cell.className = 'small event-message';
      if (i === 2) { const badge = document.createElement('span'); badge.className = `badge ${badgeClass[log.severity] || 'badge-info'}`; badge.textContent = value; cell.textContent = ''; cell.append(badge); }
      row.append(cell);
    });
    body.prepend(row); while (body.rows.length > 100) body.deleteRow(body.rows.length - 1);
    const count = document.getElementById('live-event-count'); if (count) count.textContent = String(Number(count.textContent || 0) + 1);
  }

  function prependAlertRow(body, alert, isDashboard) {
    if (!body) return;
    const emptyRow = body.querySelector('.recent-alert-empty, td[colspan]');
    if (emptyRow) emptyRow.closest('tr').remove();
    const row = document.createElement('tr');
    row.setAttribute('data-href', `/alerts/${encodeURIComponent(alert.id)}`);
    if (!isDashboard) {
      row.tabIndex = 0;
      row.setAttribute('role', 'link');
      row.setAttribute('aria-label', `Open alert ${safeText(alert.title)}`);
    }
    const addCell = (value, className) => {
      const cell = document.createElement('td');
      if (className) cell.className = className;
      cell.textContent = safeText(value);
      row.append(cell);
      return cell;
    };
    if (isDashboard) {
      const titleCell = document.createElement('td');
      const title = document.createElement('a');
      title.className = 'feed-title alert-row-link'; title.href = `/alerts/${encodeURIComponent(alert.id)}`;
      title.textContent = safeText(alert.title);
      const rule = document.createElement('span'); rule.className = 'feed-detail'; rule.textContent = safeText(alert.rule_name);
      titleCell.append(title, rule); row.append(titleCell);
      const sev = document.createElement('td'); const badge = document.createElement('span');
      badge.className = `badge ${badgeClass[alert.severity] || 'badge-info'}`; badge.textContent = safeText(alert.severity); sev.append(badge); row.append(sev);
      addCell(alert.risk_score, 'risk-value'); addCell(alert.source_ip, 'small-mono'); addCell(alert.mitre_id, 'small-mono'); addCell(localTime(alert.created_at), 'feed-time');
    } else {
      addCell(`#${alert.id}`, 'small text-secondary'); addCell(alert.title, 'small');
      const sev = document.createElement('td'); const badge = document.createElement('span');
      badge.className = `badge ${badgeClass[alert.severity] || 'badge-info'}`; badge.textContent = safeText(alert.severity); sev.append(badge); row.append(sev);
      addCell(alert.risk_score, 'small fw-bold'); addCell(alert.source_ip, 'small'); addCell(alert.hostname, 'small'); addCell(alert.rule_name, 'small'); addCell(alert.mitre_id, 'small');
      const status = document.createElement('td'); const statusBadge = document.createElement('span'); statusBadge.className = 'badge badge-status'; statusBadge.textContent = safeText(alert.status); status.append(statusBadge); row.append(status);
      addCell(localTime(alert.created_at), 'small');
    }
    body.prepend(row);
    const limit = isDashboard ? 6 : 201;
    while (body.rows.length > limit) body.deleteRow(body.rows.length - 1);
  }

  socket.on('new_alert', (alert) => {
    showToast(`New alert: ${safeText(alert.title)}`, `${safeText(alert.severity)} · Risk ${safeText(alert.risk_score)} · ${safeText(alert.source_ip)}`, severityVariant[alert.severity] || 'danger');
    const criticalEl = document.getElementById('stat-critical-alerts');
    const highEl = document.getElementById('stat-high-alerts');
    const totalAlertsEl = document.getElementById('stat-total-alerts');
    if (totalAlertsEl) totalAlertsEl.textContent = String(Number(totalAlertsEl.textContent || 0) + 1);
    if (alert.severity === 'CRITICAL' && criticalEl) criticalEl.textContent = String(Number(criticalEl.textContent) + 1);
    if (alert.severity === 'HIGH' && highEl) highEl.textContent = String(Number(highEl.textContent) + 1);
    const countEl = document.getElementById(`stat-${String(alert.severity || '').toLowerCase()}-alerts`);
    if (countEl && !['CRITICAL', 'HIGH'].includes(alert.severity)) countEl.textContent = String(Number(countEl.textContent || 0) + 1);
    updateSeverityChart(alert);
    bumpBarChart(window.socIpsChart, alert.source_ip);
    bumpBarChart(window.socRulesChart, alert.rule_name);
    prependAlertRow(document.getElementById('recentAlertsBody'), alert, true);
    prependAlertRow(document.getElementById('alertsTableBody'), alert, false);
  });

  socket.on('new_log', (log) => {
    const total = document.getElementById('stat-total-events');
    if (total) total.textContent = String(Number(total.textContent) + 1);
    updateTimeline();
    updateSourceChart(log.source);
    insertLiveEvent(log);
    const feed = document.getElementById('recentEventsFeed');
    if (!feed) return;
    const empty = feed.querySelector('.empty-state'); if (empty) empty.remove();
    const item = document.createElement('div'); item.className = 'feed-item';
    const marker = document.createElement('span'); marker.className = 'feed-marker'; marker.style.setProperty('--feed-color', severityColor[log.severity] || severityColor.INFO);
    const content = document.createElement('div'); content.className = 'feed-content';
    const title = document.createElement('span'); title.className = 'feed-title'; title.textContent = `${safeText(log.event_type)} · ${safeText(log.source_ip || log.source)}`;
    const detail = document.createElement('span'); detail.className = 'feed-detail'; detail.textContent = safeText(log.message);
    content.append(title, detail);
    const time = document.createElement('time'); time.className = 'feed-time'; time.textContent = localTime(log.timestamp);
    item.append(marker, content, time); feed.prepend(item);
    while (feed.children.length > 6) feed.lastElementChild.remove();
  });

  socket.on('new_incident', (incident) => {
    const feed = document.getElementById('recentIncidentsFeed'); if (!feed) return;
    const empty = feed.querySelector('.empty-state'); if (empty) empty.remove();
    const item = document.createElement('a'); item.className = 'feed-item incident-feed-link'; item.href = `/incidents/${encodeURIComponent(incident.id)}`;
    const marker = document.createElement('span'); marker.className = 'feed-marker'; marker.style.setProperty('--feed-color', severityColor[incident.severity] || severityColor.INFO);
    const content = document.createElement('span'); content.className = 'feed-content';
    const title = document.createElement('span'); title.className = 'feed-title'; title.textContent = safeText(incident.title);
    const detail = document.createElement('span'); detail.className = 'feed-detail'; detail.textContent = `${safeText(incident.status)} · ${safeText(incident.assigned_to || 'Unassigned')}`;
    const time = document.createElement('time'); time.className = 'feed-time'; time.textContent = localTime(incident.updated_at);
    content.append(title, detail); item.append(marker, content, time); feed.prepend(item); while (feed.children.length > 5) feed.lastElementChild.remove();
    const total = document.getElementById('stat-open-incidents'); if (total) total.textContent = String(Number(total.textContent || 0) + 1);
  });

  socket.on('data_cleared', () => {
    const alertBody = document.getElementById('recentAlertsBody');
    const eventFeed = document.getElementById('recentEventsFeed');
    if (alertBody || eventFeed) window.location.reload();
  });
});
