let bearer = '';
const el = id => document.getElementById(id);
const status = text => { el('status').textContent = text; };
async function api(path, method = 'GET', payload) {
  if (!bearer) throw Error('Connect first');
  const response = await fetch('/api/items' + path, {
    method, headers: { Authorization: 'Bearer ' + bearer, ...(payload ? {'Content-Type':'application/json'} : {}) },
    body: payload ? JSON.stringify(payload) : undefined, cache: 'no-store'
  });
  if (!response.ok) throw Error('Request failed (' + response.status + ')');
  return response.json();
}
async function run(fn) { try { await fn(); status('Done'); } catch (e) { status(e.message); } }
async function refresh() {
  const items = await api(''); el('items').replaceChildren(); el('value').textContent = '';
  for (const item of items) { const option = document.createElement('option'); option.value = item.id; option.textContent = item.id; el('items').append(option); }
}
el('connect').onclick = () => run(async () => { bearer = el('token').value; el('token').value = ''; await refresh(); });
el('read').onclick = () => run(async () => { el('value').textContent = ''; el('value').textContent = (await api('/' + encodeURIComponent(el('items').value))).value; });
el('create').onclick = () => run(async () => { const value = el('newValue').value; await api('', 'POST', {value}); el('newValue').value = ''; await refresh(); });
el('edit').onclick = () => run(async () => { await api('/' + encodeURIComponent(el('items').value), 'PUT', {value: el('newValue').value}); el('newValue').value = ''; el('value').textContent = ''; });
const recipient = () => ({ issuer: el('issuer').value, subject: el('subject').value, kind: el('kind').value });
el('share').onclick = () => run(async () => { await api('/' + encodeURIComponent(el('items').value) + '/share', 'POST', {
  recipient: recipient(), rights: ['READ','EDIT','SHARE'].filter(r => el('right' + r[0] + r.slice(1).toLowerCase()).checked)
}); await refresh(); });
el('revoke').onclick = () => run(async () => { await api('/' + encodeURIComponent(el('items').value) + '/revoke', 'POST', {recipient: recipient()}); await refresh(); });
