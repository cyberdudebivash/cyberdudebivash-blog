(function () {
  'use strict';
  const container = document.getElementById('soc-gcii-feed');
  if (!container) return;
  function unavailable() {
    container.replaceChildren();
    const p = document.createElement('p');
    p.textContent = 'Global incident feed unavailable or invalid. Verified coverage cannot be asserted.';
    container.appendChild(p);
  }
  if (!window.CDBGlobalIncidents) { unavailable(); return; }
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 6000);
  fetch('/api/v1/global-incidents/feed.json', {
    method: 'GET', credentials: 'omit', cache: 'no-store',
    headers: {Accept: 'application/json'}, signal: controller.signal
  }).then(response => {
    if (!response.ok || !(response.headers.get('content-type') || '').includes('application/json')) throw Error('invalid response');
    const length = Number(response.headers.get('content-length') || 0);
    if (length > 1048576) throw Error('too large');
    return response.text();
  }).then(body => {
    if (body.length > 1048576) throw Error('too large');
    if (!window.CDBGlobalIncidents.render(container, JSON.parse(body))) throw Error('invalid feed');
  }).catch(unavailable).finally(() => clearTimeout(timer));
})();