document.addEventListener('DOMContentLoaded', () => {
  const statusBox = document.getElementById('statusBox');
  const clearBtn = document.getElementById('clearBtn');

  function showStatus(message, isError) {
    if (!statusBox) return;
    statusBox.textContent = message;
    statusBox.classList.remove('d-none', 'alert-secondary', 'alert-success', 'alert-danger');
    statusBox.classList.add(isError ? 'alert-danger' : 'alert-success');
  }

  const refresh = document.getElementById('monitorRefresh');
  if (refresh) refresh.addEventListener('click', () => window.location.reload());

  document.querySelectorAll('.sim-btn').forEach((btn) => {
    btn.addEventListener('click', async () => {
      const type = btn.getAttribute('data-type');
      btn.disabled = true;
      try {
        const res = await fetch(`/simulator/generate/${type}`, { method: 'POST' });
        const data = await res.json();
        if (res.ok) {
          showStatus(data.message, false);
        } else {
          showStatus(data.error || 'Something went wrong.', true);
        }
      } catch (err) {
        showStatus('Network error - is the server running?', true);
      } finally {
        btn.disabled = false;
      }
    });
  });

  const demoBtn = document.getElementById('demoBtn');
  if (demoBtn) {
    demoBtn.addEventListener('click', async () => {
      demoBtn.disabled = true;
      try {
        const res = await fetch('/simulator/demo-seed', { method: 'POST' });
        const data = await res.json();
        showStatus(data.message || data.error || 'Done.', !res.ok);
      } catch (err) {
        showStatus('Network error - is the server running?', true);
      } finally {
        demoBtn.disabled = false;
      }
    });
  }

  if (clearBtn) {
    clearBtn.addEventListener('click', async () => {
      if (!confirm('Clear all logs? This cannot be undone.')) return;
      clearBtn.disabled = true;
      try {
        const res = await fetch('/simulator/clear', { method: 'POST' });
        const data = await res.json();
        showStatus(data.message || 'Cleared.', !res.ok);
      } catch (err) {
        showStatus('Network error - is the server running?', true);
      } finally {
        clearBtn.disabled = false;
      }
    });
  }
});
