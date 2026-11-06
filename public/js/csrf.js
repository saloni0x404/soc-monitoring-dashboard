// Adds the CSRF token to every POST form and every non-GET fetch() call.
(function () {
  var meta = document.querySelector('meta[name="csrf-token"]');
  var token = meta ? meta.getAttribute('content') : '';
  if (!token) return;

  var origFetch = window.fetch;
  window.fetch = function (input, init) {
    init = init || {};
    var method = (init.method || (input && input.method) || 'GET').toUpperCase();
    var url = typeof input === 'string' ? input : (input && input.url) || '';
    var sameOrigin = url.charAt(0) === '/' || url.indexOf(location.origin) === 0;
    if (method !== 'GET' && method !== 'HEAD' && sameOrigin) {
      var headers = new Headers(init.headers || {});
      headers.set('X-CSRF-Token', token);
      init.headers = headers;
    }
    return origFetch.call(this, input, init);
  };

  function addToken(form) {
    if ((form.method || '').toLowerCase() !== 'post') return;
    if (form.querySelector('input[name="_csrf"]')) return;
    var input = document.createElement('input');
    input.type = 'hidden';
    input.name = '_csrf';
    input.value = token;
    form.appendChild(input);
  }

  document.addEventListener('DOMContentLoaded', function () {
    document.querySelectorAll('form').forEach(addToken);
  });
  document.addEventListener('submit', function (e) { addToken(e.target); }, true);
})();
