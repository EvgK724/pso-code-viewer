import {sealDemo, openDemo, tokenFromInput, linkForToken} from './crypto.mjs';
import {exportPublicCard, importPublicCard, deviceIdentity, sealSurname, openSurname} from './exchange.mjs';
import {readDevice, loadContacts, saveContact, deleteContact, getMyName, setMyName} from './storage.mjs';
import {cardLinkFor, cardFromInput, compactLinkContents, copyRenderedLink} from './sharing.mjs';

const appBase = new URL('./', import.meta.url).href;
const $ = id => document.getElementById(id);
let device, selfContact, contacts = [], candidate = null;
let ready = false, busy = false, generation = 0, timer, endsAt = 0, demoLink = '';
let queuedIncoming = '';
const incomingHash = location.hash;
if (incomingHash) history.replaceState(null, '', location.pathname);

function say(text, error = false) {
  const notice = $('notice');
  notice.setAttribute('role', error ? 'alert' : 'status');
  notice.setAttribute('aria-live', error ? 'assertive' : 'polite');
  notice.textContent = text; notice.classList.toggle('error', error);
  if (error && text && !document.hidden) {
    notice.scrollIntoView({block:'center', behavior:'auto'});
    notice.focus({preventScroll:true});
  }
}
function hideResult(message = '') {
  generation++; clearInterval(timer); endsAt = 0; $('result').hidden = true;
  for (const id of ['surname','department','case-code','countdown']) $(id).textContent = '';
  if (message) say(message);
}
function clearSensitive() { hideResult(); $('compose-surname').value = ''; }
function tick() {
  if (!endsAt) return;
  const seconds = Math.ceil((endsAt - performance.now()) / 1000);
  if (seconds <= 0) return hideResult('Фамилия скрыта. До истечения срока ссылку можно открыть снова.');
  $('countdown').textContent = 'Скроется через ' + seconds + ' с';
}
function setBusy(value) {
  busy = value;
  for (const id of ['token','compose-surname','recipient','compose-orit','message-caption','expiry','my-name','contact-input','confirm-fingerprint']) $(id).disabled = value || !ready;
  for (const id of ['demo','open','paste-open','export-card','inspect-contact']) $(id).disabled = value || !ready;
  $('copy-handoff').disabled = value || !$('handoff-link').value;
  $('encrypt').disabled = value || !ready || !$('recipient').value;
  $('copy-link').disabled = value || !demoLink;
  $('copy-demo-compact').disabled = value || !demoLink;
  $('copy-composed').disabled = value || !$('output-link').value;
  $('copy-composed-compact').disabled = value || !$('output-link').value;
  $('copy-composed-address').disabled = value || !$('output-link').value;
  $('copy-card').disabled = value || !$('my-card').value;
  $('copy-card-compact').disabled = value || !$('my-card-link').value;
  $('copy-card-link').disabled = value || !$('my-card-link').value;
  $('save-contact').disabled = value || !ready || !candidate || !$('confirm-fingerprint').checked;
  for (const button of $('contacts-list').querySelectorAll('button')) button.disabled = value;
  if (!value && ready && queuedIncoming) {
    const hash = queuedIncoming; queuedIncoming = '';
    Promise.resolve().then(() => handleIncoming(hash));
  }
}
function showMode(mode) {
  clearSensitive(); const read = mode === 'read';
  $('read-panel').hidden = !read; $('write-panel').hidden = read;
  $('show-read').setAttribute('aria-pressed', String(read)); $('show-write').setAttribute('aria-pressed', String(!read)); if (ready) say('');
}
function messageCaption() {
  return $('message-caption').value === 'test' ? 'Проверочная история' :
    $('compose-orit').checked ? 'Новый пациент ОРИТ' : 'Новый пациент';
}
function updateCaptionPreview() { $('output-preview').textContent = messageCaption(); }
function invalidateComposed() {
  $('compose-output').hidden = true; $('output-link').value = '';
  $('output-preview').href = '#'; setBusy(busy);
}
function parseInput(input) {
  const value = String(input).trim();
  if (value.length > 2500) throw new Error('Ссылка слишком длинная. Скопируйте только ссылку без комментария.');
  return value.startsWith('PSO1.') ? value : tokenFromInput(value, appBase);
}
function inputKind(input) {
  const value = String(input).trim();
  if (value.length > 5000) throw new Error('Ссылка слишком длинная. Скопируйте только ссылку без комментария.');
  if (/^[0-9a-f\s-]+$/i.test(value) && value.replace(/[\s-]/g, '').length === 64) throw new Error('Это контрольный код карточки врача. По нему фамилия не открывается. Попросите отправителя создать ссылку для вас через «Создать ссылку» и скопировать её целиком.');
  if (/^[0-9\s-]+$/.test(value)) throw new Error('Вставлен только набор цифр. Нужна полная ссылка из «Скопировать адрес для Пачки» или зашифрованный код, начинающийся с PSO1.');
  if (!value) throw new Error('Сначала вставьте ссылку в поле или нажмите «Вставить и открыть».');
  let card = value.startsWith('PSO-CARD1.');
  try { card ||= new URL(value).hash.startsWith('#card='); } catch {}
  if (card) { cardFromInput(value, appBase); return 'card'; }
  const token = parseInput(value);
  if (!/^(?:PSO1(?:\.[A-Za-z0-9_-]+){4}|PSO-DEMO1\.[A-Za-z0-9_-]+)$/.test(token)) throw new Error('Код неполный или имеет другой формат. Скопируйте ссылку целиком через «Скопировать адрес для Пачки».');
  return 'message';
}
function clearHandoff() { $('handoff-panel').hidden = true; $('handoff-link').value = ''; }
async function openInput(input, fromIncoming = false) {
  if (busy || !ready) return;
  hideResult();
  if (!fromIncoming) clearHandoff();
  try {
    if (inputKind(input) === 'card') { $('token').value = ''; await inspectCard(input); }
    else await reveal(input);
  } catch (error) { say(error.message || 'Скопируйте ссылку из сообщения.', true); }
}
async function pasteAndOpen() {
  if (busy || !ready) return;
  hideResult();
  const current = generation;
  let input;
  setBusy(true); say('Если iPhone спросит разрешение, выберите «Вставить» или «Разрешить вставку».');
  try {
    // Must run in the click gesture: no background reads or earlier await.
    input = await navigator.clipboard.readText();
    if (current !== generation || document.hidden) return;
  } catch {
    if (current === generation && !document.hidden) {
      say('Вставка не разрешена. Удерживайте поле ниже, выберите «Вставить», затем «Открыть на 30 секунд».', true);
    }
    return;
  } finally { setBusy(false); }
  return openInput(input);
}
async function copyText(text, fallbackId, success, detailsId = '') {
  if (!text) return;
  try { await navigator.clipboard.writeText(text); say(success); }
  catch { if (detailsId) $(detailsId).open = true; $(fallbackId).value = text; $(fallbackId).focus(); $(fallbackId).select(); say('Удерживайте выделенный текст и выберите «Скопировать».'); }
}
async function copyCompactLink(url, label, fallbackId, detailsId = '') {
  if (!url) return;
  let contents;
  try { contents = compactLinkContents(url, label, appBase); }
  catch (error) { say(error.message, true); return; }
  try {
    await navigator.clipboard.write([new ClipboardItem({
      'text/html':new Blob([contents.html], {type:'text/html'}),
      'text/plain':new Blob([contents.plain], {type:'text/plain'})
    })]);
    say('Скопирована ссылка с подписью «' + label + '». Вставьте в Пачку. Если появится длинный адрес, вставьте его через кнопку ссылки (🔗) в Пачке.');
  } catch {
    await copyText(contents.plain, fallbackId, 'Браузер скопировал полную ссылку. В Пачке напишите «' + label + '», выделите эти слова и добавьте скопированный адрес через кнопку ссылки (🔗).', detailsId);
  }
}
function setCandidate(value) {
  candidate = value; $('contact-confirm').hidden = !value;
  $('candidate-name').textContent = value?.name || ''; $('candidate-fingerprint').textContent = value?.fingerprint || '';
  $('confirm-fingerprint').checked = false; setBusy(busy);
}
function renderContacts() {
  const selected = $('recipient').value, selector = $('recipient');
  selector.replaceChildren();
  const placeholder = document.createElement('option'); placeholder.value = ''; placeholder.textContent = 'Выберите получателя'; selector.append(placeholder);
  if (selfContact) {
    const own = document.createElement('option'); own.value = selfContact.id; own.textContent = 'Себе — проверить на этом телефоне'; selector.append(own);
  }
  $('contacts-list').replaceChildren();
  for (const contact of contacts) {
    const option = document.createElement('option'); option.value = contact.id; option.textContent = contact.name; selector.append(option);
    const row = document.createElement('div'); row.className = 'contact-item';
    const details = document.createElement('div');
    const name = document.createElement('strong'); name.className = 'contact-name'; name.textContent = contact.name;
    const fingerprint = document.createElement('p'); fingerprint.className = 'fingerprint'; fingerprint.textContent = contact.fingerprint; details.append(name, fingerprint);
    const remove = document.createElement('button'); remove.type = 'button'; remove.className = 'button button-secondary remove-contact'; remove.textContent = 'Убрать';
    remove.setAttribute('aria-label', 'Убрать контакт ' + contact.name);
    remove.addEventListener('click', async () => {
      if (busy) return; setBusy(true);
      try {
        await deleteContact(contact.id); contacts = await loadContacts(); renderContacts();
        $('compose-output').hidden = true; $('output-link').value = '';
        say('Контакт убран с этого телефона. Уже отправленные ссылки это не отзывает.');
      } catch (error) { say(error.message, true); } finally { setBusy(false); }
    });
    row.append(details, remove); $('contacts-list').append(row);
  }
  if (!contacts.length) { const empty = document.createElement('p'); empty.textContent = 'Пока нет коллег. Обменяйтесь карточками и добавьте врача ниже.'; $('contacts-list').append(empty); }
  if ([...selector.options].some(option => option.value === selected)) selector.value = selected;
  setBusy(busy);
}
async function reveal(input) {
  if (busy || !ready) return;
  showMode('read'); const current = generation; setBusy(true); say('Проверяем ссылку…');
  try {
    const token = parseInput(input); $('token').value = token;
    const isDemo = token.startsWith('PSO-DEMO1.'); let data;
    if (isDemo) data = await openDemo(device, token);
    else { contacts = await loadContacts(); renderContacts(); data = await openSurname(device, token, contacts); }
    if (current !== generation || document.hidden) return;
    $('result-label').textContent = isDemo ? 'Вымышленный пример' : 'Фамилия из сообщения';
    $('surname').textContent = data.surname; $('department').textContent = data.department;
    $('case-code').textContent = isDemo ? data.code : 'Отправитель: ' + data.senderName;
    $('result').hidden = false; $('token').value = ''; endsAt = performance.now() + 30000;
    tick(); timer = setInterval(tick, 250);
    say(isDemo ? 'Расшифрован вымышленный пример.' : 'Подпись отправителя проверена по сохранённой карточке.');
    $('result').scrollIntoView({block:'center', behavior:'auto'}); $('surname').focus({preventScroll:true});
  } catch (error) { if (current === generation) say(error.message || 'Не удалось открыть ссылку.', true); }
  finally { setBusy(false); }
}

$('show-read').addEventListener('click', () => showMode('read'));
$('show-write').addEventListener('click', () => showMode('write'));
$('open-form').addEventListener('submit', event => { event.preventDefault(); return openInput($('token').value); });
$('token').addEventListener('input', clearHandoff);
$('paste-open').addEventListener('click', pasteAndOpen);
$('copy-handoff').addEventListener('click', () => copyText($('handoff-link').value, 'handoff-link', 'Ссылка скопирована. Откройте синий значок «ПСО Код» на экране «Домой» и нажмите «Вставить и открыть».', 'handoff-full-link'));
$('hide').addEventListener('click', () => hideResult('Фамилия скрыта.'));
$('recipient').addEventListener('change', invalidateComposed);
for (const id of ['compose-surname','expiry']) $(id).addEventListener('input', invalidateComposed);
$('compose-orit').addEventListener('input', () => {
  if ($('message-caption').value !== 'test') $('message-caption').value = $('compose-orit').checked ? 'orit' : 'patient';
  updateCaptionPreview(); invalidateComposed();
});
$('message-caption').addEventListener('change', () => {
  const selected = $('message-caption').value;
  if (selected !== 'test') {
    const orit = selected === 'orit';
    if ($('compose-orit').checked !== orit) {
      $('compose-orit').checked = orit;
      const hadLink = !!$('output-link').value;
      invalidateComposed();
      if (hadLink) say('Отделение изменено. Введите фамилию и создайте новую ссылку.');
    }
  }
  updateCaptionPreview();
});
$('compose-form').addEventListener('submit', async event => {
  event.preventDefault(); if (busy || !ready) return;
  hideResult(); const current = generation, selectedID = $('recipient').value;
  let name = $('compose-surname').value;
  const department = $('compose-orit').checked ? 'ОРИТ' : '', ttlMinutes = Number($('expiry').value);
  $('compose-output').hidden = true; $('output-link').value = ''; setBusy(true); say('Шифруем для выбранного врача…');
  try {
    contacts = await loadContacts();
    const recipient = selectedID === selfContact.id ? selfContact : contacts.find(contact => contact.id === selectedID);
    if (!recipient) throw new Error('Выберите врача из проверенных контактов или вариант проверки на своём телефоне.');
    const token = await sealSurname(device, recipient, name, {department, ttlMinutes});
    name = ''; $('compose-surname').value = '';
    if (current !== generation || document.hidden) return;
    $('output-link').value = linkForToken(token, appBase);
    $('output-preview').href = $('output-link').value;
    updateCaptionPreview();
    $('output-recipient').textContent = selectedID === selfContact.id ? 'Получатель: только этот просмотрщик — проверка' : 'Получатель: ' + recipient.name;
    $('compose-output').hidden = false; say('Подпись со ссылкой готова. Нажмите «Скопировать готовую надпись» и вставьте в Пачку.');
    $('compose-output').scrollIntoView({block:'nearest', behavior:'auto'});
  } catch (error) { if (current === generation) say(error.message || 'Не удалось создать ссылку.', true); }
  finally { name = ''; setBusy(false); }
});
$('copy-composed').addEventListener('click', () => {
  if (busy || !$('output-link').value) return;
  updateCaptionPreview();
  if (copyRenderedLink($('output-preview'), document, globalThis.getSelection?.())) {
    say('Скопирована готовая надпись «' + messageCaption() + '». Вставьте в Пачку. Если вставились слова без ссылки, используйте «Другой способ с оформлением».');
    return;
  }
  return copyCompactLink($('output-link').value, messageCaption(), 'output-link', 'compose-full-link');
});
$('copy-composed-compact').addEventListener('click', () => copyCompactLink($('output-link').value, messageCaption(), 'output-link', 'compose-full-link'));
$('copy-composed-address').addEventListener('click', () => copyText($('output-link').value, 'output-link', 'Полный адрес скопирован. Он откроется только у выбранного получателя.', 'compose-full-link'));
$('demo').addEventListener('click', async () => {
  if (busy || !ready) return;
  clearSensitive(); const current = generation; setBusy(true); say('Создаём вымышленный пример…');
  try {
    const token = await sealDemo(device); if (current !== generation || document.hidden) return;
    $('token').value = token; demoLink = linkForToken(token, appBase);
    $('open-link').href = demoLink; $('link-tools').hidden = false; say('Пример готов. Откройте код или тестовую ссылку.');
  } catch { say('Не удалось создать тестовый код.', true); } finally { setBusy(false); }
});
$('copy-link').addEventListener('click', () => copyText(demoLink, 'token', 'Тестовая ссылка скопирована. Откройте её в этом же просмотрщике.'));
$('copy-demo-compact').addEventListener('click', () => copyCompactLink(demoLink, 'Тестовая ссылка', 'token'));
$('export-card').addEventListener('click', async () => {
  if (busy || !ready) return; setBusy(true);
  try {
    const card = await exportPublicCard(device, $('my-name').value), own = await importPublicCard(card);
    await setMyName(own.name); $('my-name').value = own.name; $('my-card').value = card;
    $('my-card-link').value = cardLinkFor(card, appBase); $('my-card-preview').href = $('my-card-link').value;
    $('my-fingerprint').textContent = own.fingerprint; $('my-card-box').hidden = false;
    say('Передайте карточку коллеге и сверьте отпечаток по телефону или лично. В карточке только открытые ключи.');
  } catch (error) { say(error.message, true); } finally { setBusy(false); }
});
$('copy-card').addEventListener('click', () => copyText($('my-card').value, 'my-card', 'Открытая карточка скопирована. Фамилий пациентов в ней нет.'));
$('copy-card-link').addEventListener('click', () => copyText($('my-card-link').value, 'my-card-link', 'Адрес скопирован. В Пачке напишите «Карточка врача», выделите эти слова → «Аа» → 🔗 → вставьте адрес.', 'my-card-full'));
$('copy-card-compact').addEventListener('click', () => copyCompactLink($('my-card-link').value, 'Карточка врача', 'my-card-link', 'my-card-full'));
$('contact-input').addEventListener('input', () => setCandidate(null));
async function inspectCard(input) {
  if (busy || !ready) return;
  clearSensitive(); $('contacts-details').open = true; $('contact-input').value = input;
  const current = generation;
  setCandidate(null); setBusy(true);
  try {
    const contact = await importPublicCard(cardFromInput(input, appBase));
    if (current !== generation || document.hidden) return;
    if (contact.id === selfContact.id) throw new Error('Это карточка этого телефона. Для проверки выберите «Себе» в списке получателей.');
    setCandidate(contact); say('Сверьте весь отпечаток с коллегой лично или по известному номеру телефона.');
    $('contact-confirm').scrollIntoView({block:'center', behavior:'auto'});
  } catch (error) { if (current === generation && !document.hidden) say(error.message, true); } finally { setBusy(false); }
}
$('contact-form').addEventListener('submit', event => { event.preventDefault(); return inspectCard($('contact-input').value); });
$('confirm-fingerprint').addEventListener('change', () => setBusy(busy));
$('save-contact').addEventListener('click', async () => {
  if (busy || !ready || !candidate || !$('confirm-fingerprint').checked) return; setBusy(true);
  try {
    await saveContact({...candidate, verified:true}); contacts = await loadContacts(); renderContacts();
    $('contact-input').value = ''; setCandidate(null); say('Врач добавлен. Чтобы принимать ваши ссылки, ему также нужно добавить вашу карточку.');
  } catch (error) { say(error.message, true); } finally { setBusy(false); }
});
async function handleIncoming(hash) {
  if (!hash) return;
  clearSensitive(); setCandidate(null);
  if (busy) { queuedIncoming = hash; return; }
  clearHandoff();
  if (!hash.startsWith('#pso=') && !hash.startsWith('#card=')) { say('Неизвестный формат ссылки.', true); return; }
  const link = appBase + hash;
  try {
    inputKind(link);
    $('handoff-link').value = link;
    const standalone = navigator.standalone === true || globalThis.matchMedia?.('(display-mode: standalone)').matches === true;
    $('handoff-panel').hidden = standalone;
    setBusy(busy);
    await openInput(link, true);
  } catch (error) { say(error.message, true); }
}
addEventListener('hashchange', () => {
  const hash = location.hash; history.replaceState(null, '', location.pathname);
  return handleIncoming(hash);
});
document.addEventListener('visibilitychange', () => { if (document.hidden) clearSensitive(); else tick(); });
addEventListener('pagehide', clearSensitive);

async function init() {
  setBusy(true);
  try {
    if (!globalThis.crypto?.subtle) throw new Error('Нужны современный браузер и подключение по HTTPS.');
    device = await readDevice(); const identity = await deviceIdentity(device);
    selfContact = {...await importPublicCard(await exportPublicCard(device, 'Этот телефон')), verified:true};
    contacts = await loadContacts(); $('my-name').value = await getMyName();
    $('device-id').textContent = identity.fingerprint; $('status').textContent = 'Ключ этого просмотрщика готов';
    ready = true; renderContacts(); setBusy(false);
    await handleIncoming(incomingHash);
  } catch (error) { ready = false; $('status').textContent = 'Не удалось подготовить просмотрщик'; say(error.message, true); setBusy(false); }
  if ('serviceWorker' in navigator) navigator.serviceWorker.register('./sw.js').catch(() => {});
}
init();
