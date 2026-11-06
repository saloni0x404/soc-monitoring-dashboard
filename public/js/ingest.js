document.addEventListener('DOMContentLoaded', function () {
  var form = document.getElementById('ingestForm');
  if (!form) return;
  var fileInput = document.getElementById('logFile');
  var textArea = document.getElementById('logText');
  var formatSel = document.getElementById('logFormat');
  var statusBox = document.getElementById('ingestStatus');
  var btn = document.getElementById('ingestBtn');
  var filename = '';

  function show(msg, ok) {
    statusBox.textContent = msg;
    statusBox.className = 'alert mt-3 ' + (ok ? 'alert-success' : 'alert-danger');
  }

  fileInput.addEventListener('change', function () {
    var f = fileInput.files[0];
    if (!f) return;
    if (f.size > 1500000) { show('File is larger than about 1.5 MB. Split it first.', false); fileInput.value = ''; return; }
    filename = f.name;
    var reader = new FileReader();
    reader.onload = function () { textArea.value = reader.result; };
    reader.readAsText(f);
  });

  form.addEventListener('submit', async function (e) {
    e.preventDefault();
    if (!textArea.value.trim()) { show('Choose a file or paste some log lines first.', false); return; }
    btn.disabled = true;
    try {
      var res = await fetch('/ingest', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ format: formatSel.value, content: textArea.value, filename: filename })
      });
      var data = await res.json();
      show(res.ok ? data.message + ' (' + data.skipped + ' line(s) ignored as not security-relevant)' : (data.error || 'Import failed.'), res.ok);
    } catch (err) {
      show('Network error - is the server running?', false);
    } finally {
      btn.disabled = false;
    }
  });
});
