document.addEventListener('DOMContentLoaded', () => {
  const analyzeBtn = document.getElementById('analyzeBtn');
  const alertSelect = document.getElementById('alertSelect');
  const output = document.getElementById('analysisOutput');
  const chatBtn = document.getElementById('chatBtn');
  const chatInput = document.getElementById('chatInput');
  const chatLog = document.getElementById('chatLog');

  if (analyzeBtn) {
    analyzeBtn.addEventListener('click', async () => {
      const id = alertSelect.value;
      if (!id) { output.textContent = 'Please select an alert first.'; return; }
      output.textContent = 'Analyzing... (local models may take a while)';
      analyzeBtn.disabled = true;
      try {
        const res = await fetch(`/ai/analyze/${id}`, { method: 'POST' });
        const data = await res.json();
        output.textContent = res.ok ? data.analysis : (data.error || 'Analysis failed.');
      } catch (e) {
        output.textContent = 'Network error contacting the server.';
      } finally {
        analyzeBtn.disabled = false;
      }
    });
  }

  function appendChat(who, text) {
    const div = document.createElement('div');
    div.className = 'mb-2';
    div.innerHTML = `<strong>${who}:</strong> <span class="text-secondary"></span>`;
    div.querySelector('span').textContent = text;
    chatLog.appendChild(div);
    chatLog.scrollTop = chatLog.scrollHeight;
  }

  async function sendChat() {
    const q = chatInput.value.trim();
    if (!q) return;
    appendChat('You', q);
    chatInput.value = '';
    chatBtn.disabled = true;
    try {
      const res = await fetch('/ai/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ question: q }),
      });
      const data = await res.json();
      appendChat('AI', res.ok ? data.answer : (data.error || 'Request failed.'));
    } catch (e) {
      appendChat('AI', 'Network error contacting the server.');
    } finally {
      chatBtn.disabled = false;
    }
  }

  if (chatBtn) {
    chatBtn.addEventListener('click', sendChat);
    chatInput.addEventListener('keydown', (e) => { if (e.key === 'Enter') sendChat(); });
  }
});
