document.addEventListener('DOMContentLoaded', () => {
  const el = document.getElementById('chartData');
  if (!el || typeof Chart === 'undefined') return;

  const parse = (attr) => { try { return JSON.parse(el.getAttribute(attr)) || []; } catch (e) { return []; } };
  const colors = { CRITICAL: '#ef6c70', HIGH: '#e89154', MEDIUM: '#e4bb5e', LOW: '#59a9ef', INFO: '#72889b' };
  const grid = '#1b2c3b';
  Chart.defaults.color = '#8599aa';
  Chart.defaults.borderColor = grid;
  Chart.defaults.font.family = 'Arial, Helvetica, sans-serif';
  Chart.defaults.font.size = 9;

  const timeline = document.getElementById('timelineChart');
  if (timeline) {
    window.socTimelineChart = new Chart(timeline, {
      type: 'line',
      data: { labels: parse('data-timeline-labels'), datasets: [{
        label: 'Events', data: parse('data-timeline-values'), borderColor: '#39d6ad',
        backgroundColor: 'rgba(57,214,173,.10)', fill: true, tension: .32,
        borderWidth: 2, pointRadius: 0, pointHoverRadius: 3, pointHoverBackgroundColor: '#39d6ad',
      }] },
      options: {
        responsive: true, maintainAspectRatio: false, animation: { duration: 220 },
        interaction: { intersect: false, mode: 'index' },
        plugins: { legend: { display: false }, tooltip: { backgroundColor: '#102130', borderColor: '#2c4458', borderWidth: 1, titleColor: '#dbe5eb', bodyColor: '#a8bac8', displayColors: false, padding: 9 } },
        scales: {
          x: { grid: { display: false }, ticks: { color: '#71879a', maxTicksLimit: 8, maxRotation: 0, autoSkip: true } },
          y: { beginAtZero: true, ticks: { color: '#71879a', precision: 0, maxTicksLimit: 5 }, grid: { color: grid, drawBorder: false } },
        },
      },
    });
  }

  const makeDoughnut = (id, rows, labelKey, colorFn) => {
    const canvas = document.getElementById(id);
    if (!canvas) return null;
    return new Chart(canvas, {
      type: 'doughnut',
      data: { labels: rows.map((row) => row[labelKey]), datasets: [{
        data: rows.map((row) => Number(row.count)), backgroundColor: rows.map(colorFn),
        borderColor: rows.map(() => '#0d1926'), borderWidth: 3, hoverOffset: 3,
      }] },
      options: { responsive: true, maintainAspectRatio: false, cutout: '74%', plugins: { legend: { display: false }, tooltip: { backgroundColor: '#102130', borderColor: '#2c4458', borderWidth: 1, titleColor: '#dbe5eb', bodyColor: '#a8bac8', padding: 8 } } },
    });
  };
  const severityRows = parse('data-severity');
  if (!severityRows.length) severityRows.push({ severity: 'No alerts', count: 1 });
  window.socSeverityChart = makeDoughnut('severityChart', severityRows, 'severity', (row) => colors[row.severity] || '#223647');
  window.socSourcesChart = makeDoughnut('sourcesChart', parse('data-sources'), 'source', (row, i) => ['#39d6ad','#59a9ef','#b18ce1','#e4bb5e','#e89154'][i % 5]);

  const makeBars = (id, rows, labelKey, color, globalName) => {
    const canvas = document.getElementById(id);
    if (!canvas) return;
    const chart = new Chart(canvas, {
      type: 'bar', data: { labels: rows.map((row) => row[labelKey]), datasets: [{ data: rows.map((row) => Number(row.count)), backgroundColor: color, borderRadius: 3, barThickness: 8 }] },
      options: { indexAxis: 'y', responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false }, tooltip: { backgroundColor: '#102130', borderColor: '#2c4458', borderWidth: 1, titleColor: '#dbe5eb', bodyColor: '#a8bac8', padding: 8 } }, scales: { x: { beginAtZero: true, ticks: { color: '#71879a', precision: 0, maxTicksLimit: 5 }, grid: { color: grid, drawBorder: false } }, y: { ticks: { color: '#91a4b3', autoSkip: false }, grid: { display: false } } } },
    });
    if (globalName) window[globalName] = chart;
    return chart;
  };
  window.socIpsChart = makeBars('ipsChart', parse('data-topips'), 'source_ip', '#59a9ef', 'socIpsChart');
  window.socRulesChart = makeBars('rulesChart', parse('data-toprules'), 'rule_name', '#39bfa0', 'socRulesChart');
});
