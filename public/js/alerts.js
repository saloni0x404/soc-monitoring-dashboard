document.addEventListener('DOMContentLoaded', () => {
  const root = document.getElementById('alertDetailRoot');
  if (!root) return;

  const alertId = root.getAttribute('data-alert-id');
  const statusLabel = document.getElementById('statusLabel');

  document.querySelectorAll('.status-btn').forEach((btn) => {
    btn.addEventListener('click', async () => {
      const status = btn.getAttribute('data-status');
      btn.disabled = true;
      try {
        const res = await fetch(`/alerts/${alertId}/status`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ status }),
        });
        const data = await res.json();
        if (res.ok) {
          statusLabel.textContent = data.status;
        } else {
          window.alert(data.error || 'Failed to update status');
        }
      } catch (e) {
        window.alert('Network error contacting the server.');
      } finally {
        btn.disabled = false;
      }
    });
  });

  const incidentBtn = document.getElementById('createIncidentBtn');
  if (incidentBtn) {
    incidentBtn.addEventListener('click', async () => {
      if (!confirm('Escalate this alert into a new incident?')) return;
      incidentBtn.disabled = true;
      try {
        const res = await fetch(`/incidents/from-alert/${alertId}`, { method: 'POST' });
        const data = await res.json();
        if (res.ok) {
          window.location = `/incidents/${data.incidentId}`;
        } else {
          window.alert(data.error || 'Failed to create incident');
          incidentBtn.disabled = false;
        }
      } catch (e) {
        window.alert('Network error contacting the server.');
        incidentBtn.disabled = false;
      }
    });
  }
});
