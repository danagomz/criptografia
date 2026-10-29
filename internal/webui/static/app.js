const $ = (id) => document.getElementById(id);
const runButton = $('run'), verifyButton = $('verify'), tamperButton = $('tamper');

function status(kind, title, message) {
  const box = document.querySelector('.status-panel');
  box.className = `panel status-panel ${kind}`;
  $('status-label').textContent = title;
  $('status-copy').textContent = message;
  $('status-icon').textContent = kind === 'success' ? '✓' : kind === 'failure' ? '!' : '⌁';
}
function toast(message) {
  const node = $('toast'); node.textContent = message; node.classList.add('show');
  setTimeout(() => node.classList.remove('show'), 1600);
}
function setBusy(value) {
  runButton.disabled = value;
  if (value) document.querySelector('.status-panel').classList.add('loading');
}
function safe(value) {
  return String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}
async function request(path, body) {
  const response = await fetch(path, {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(body ?? {})});
  const result = await response.json();
  if (!response.ok) throw new Error(result.error || `Error HTTP ${response.status}`);
  return result;
}
function showEvents(events) {
  $('events').innerHTML = events.map(event => {
    const modified = event.event_type === 'GRADE_MODIFIED';
    const label = modified ? 'Modificación' : 'Registro';
    const grade = modified ? `${Number(event.previous_value).toFixed(2)} <span class="grade-change">→ ${Number(event.new_value).toFixed(2)}</span>` : Number(event.new_value).toFixed(2);
    return `<tr><td><b>${safe(event.event_id)}</b><small class="${modified?'modified':''}">${label}</small></td><td>${safe(event.student_uid)}</td><td>${safe(event.course_uid)}</td><td class="grade">${grade}</td><td><code title="${safe(event.payload_hash)}">${safe(event.payload_hash.slice(0,15))}…</code></td></tr>`;
  }).join('');
  $('event-count').textContent = `${events.length} EVENTOS`;
}
runButton.addEventListener('click', async () => {
  const count = Number($('count').value);
  if (!Number.isInteger(count) || count < 1 || count > 100000) { status('failure','CANTIDAD INVÁLIDA','Ingresa un entero entre 1 y 100 000.'); return; }
  setBusy(true); status('loading','PROCESANDO FLUJO','Generando, hasheando, cifrando y verificando el log…');
  try {
    const result = await request('/api/run', {count});
    $('total').textContent = result.event_count.toLocaleString('es-CO');
    $('types').textContent = `Registros ${result.counts_by_type.GRADE_REGISTERED || 0} · Modificaciones ${result.counts_by_type.GRADE_MODIFIED || 0}`;
    $('plain-hash').textContent = result.plain_hash;
    $('cipher-hash').textContent = result.cipher_hash;
    $('decrypted-hash').textContent = result.decrypted_hash;
    const preserved = result.preserved && result.event_hashes_valid && result.cipher_hash_verified;
    $('preserve-badge').textContent = preserved ? 'INFORMACIÓN PRESERVADA' : 'VERIFICACIÓN FALLIDA';
    $('preserve-badge').className = `badge ${preserved?'ok':'bad'}`;
    $('comparison').className = `comparison ${preserved?'ok':'bad'}`;
    $('comparison-text').textContent = preserved ? 'Los hashes coinciden. El descifrado recuperó el log original y los hashes de eventos son válidos.' : 'Hay una diferencia o un evento cuyo hash no es válido.';
    showEvents(result.events);
    verifyButton.disabled = false; tamperButton.disabled = false;
    status(preserved?'success':'failure', preserved?'FLUJO COMPLETADO · INTEGRIDAD CONFIRMADA':'FLUJO COMPLETADO · REVISAR RESULTADO', `${result.event_count} eventos procesados. Artefactos guardados en ${result.output_dir}.`);
  } catch (error) { status('failure','NO SE PUDO EJECUTAR',error.message); }
  finally { setBusy(false); }
});
verifyButton.addEventListener('click', async () => {
  try { const result = await request('/api/verify'); status(result.valid?'success':'failure',result.valid?'VERIFICACIÓN CORRECTA':'VERIFICACIÓN FALLIDA',result.message); }
  catch (error) { status('failure','ERROR DE VERIFICACIÓN',error.message); }
});
tamperButton.addEventListener('click', async () => {
  try {
    const result = await request('/api/tamper');
    const {hash_mismatch_detected: hash, authentication_failed: auth} = result.report;
    status(result.detected?'success':'failure',result.detected?'ALTERACIÓN DETECTADA':'ALTERACIÓN NO DETECTADA',`SHA-256: ${hash?'detectó el cambio':'no detectó el cambio'} · GCM: ${auth?'rechazó el descifrado':'no rechazó el descifrado'}. El archivo guardado sigue intacto.`);
  } catch (error) { status('failure','NO SE PUDO SIMULAR',error.message); }
});
document.querySelectorAll('[data-copy]').forEach(button => button.addEventListener('click', async () => {
  const value = $(button.dataset.copy).textContent;
  if (!value || value === '—') return;
  try { await navigator.clipboard.writeText(value); toast('Hash copiado'); } catch { toast('No fue posible copiar el hash'); }
}));
