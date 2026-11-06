document.addEventListener('click', function (e) {
  var row = e.target.closest('[data-href]');
  if (row && !e.target.closest('a, button, form, input')) window.location = row.getAttribute('data-href');
});
document.addEventListener('keydown', function (e) {
  var row = e.target.closest('[data-href]');
  if (row && (e.key === 'Enter' || e.key === ' ') && !e.target.closest('a, button, input')) {
    e.preventDefault(); window.location = row.getAttribute('data-href');
  }
});
document.addEventListener('submit', function (e) {
  var msg = e.target.getAttribute('data-confirm');
  if (msg && !window.confirm(msg)) e.preventDefault();
});
document.addEventListener('DOMContentLoaded', function () {
  var path = window.location.pathname.replace(/\/$/, '') || '/';
  document.querySelectorAll('[data-sidebar-link]').forEach(function (link) {
    var linkPath = new URL(link.href, window.location.origin).pathname.replace(/\/$/, '') || '/';
    var active = path === linkPath || (linkPath !== '/' && path.startsWith(linkPath + '/'));
    link.classList.toggle('active', active);
    if (active) link.setAttribute('aria-current', 'page');
    else link.removeAttribute('aria-current');
  });
  var clock = document.getElementById('local-clock');
  if (clock) {
    var tick = function () { clock.textContent = new Date().toLocaleTimeString([], {hour:'2-digit',minute:'2-digit',second:'2-digit'}); };
    tick(); window.setInterval(tick, 1000);
  }
  var search = document.getElementById('global-alert-search');
  document.addEventListener('keydown', function (e) {
    if (e.key === '/' && !e.ctrlKey && !e.metaKey && !['INPUT','TEXTAREA','SELECT'].includes(document.activeElement.tagName)) {
      e.preventDefault(); if (search) search.focus();
    }
  });
});
