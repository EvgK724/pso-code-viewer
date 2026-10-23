import {sealDemo, openDemo, tokenFromInput, linkForToken} from './crypto.mjs';
import {exportPublicCard, importPublicCard, deviceIdentity, sealSurname, openSurname} from './exchange.mjs';
import {readDevice, loadContacts, saveContact, deleteContact, getMyName, setMyName} from './storage.mjs';
import {cardLinkFor, cardFromInput, compactLinkContents, copyRenderedLink} from './sharing.mjs';
import {ShortLinkClient, shortIDFromInput} from './shortlinks.mjs';
import {SHORTLINK_ENDPOINT, PUSH_ENDPOINT, TEAM_ENDPOINT} from './shortlink-config.mjs';
import {PushClient, pushKeyBytes} from './push.mjs';
import {TeamClient, joinIDFromInput} from './team.mjs';
import {installAppUpdates} from './updates.mjs';

const appBase = new URL('./', import.meta.url).href;
const shortLinks = SHORTLINK_ENDPOINT ? new ShortLinkClient(SHORTLINK_ENDPOINT) : null;
const pushClient = PUSH_ENDPOINT ? new PushClient(PUSH_ENDPOINT) : null;
const teamClient = TEAM_ENDPOINT ? new TeamClient(TEAM_ENDPOINT) : null;
const $ = id => document.getElementById(id);
let device, selfContact, contacts = [], candidate = null;
let ready = false, busy = false, generation = 0, timer, endsAt = 0, demoLink = '';
let queuedIncoming = location.hash, activeIncoming = null;
let workerReady = null, pushBusy = false, pushEnabled = false, pushSupported = false, pushRefreshPending = false;
let pushPublicKey = '', pushSubscription = null;
let teamState={state:'unregistered',role:null,name:null}, teamMembers=[], teamBusy=false, joinID='', inviteLink='';
let appUpdates=null, appUpdateAvailable=false;
const standalone = navigator.standalone === true || globalThis.matchMedia?.('(display-mode: standalone)').matches === true;

if (queuedIncoming) history.replaceState(null, '', location.pathname);

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
  updatePushButtons();
  updateTeamButtons();
  for (const id of ['token','compose-surname','recipient','compose-orit','message-caption','expiry','my-name','contact-input','confirm-fingerprint']) $(id).disabled = value || !ready;
  for (const id of ['demo','open','paste-open','export-card','inspect-contact']) $(id).disabled = value || !ready;
  $('copy-handoff').disabled = value || !$('handoff-link').value;
  $('encrypt').disabled = value || !ready || !$('recipient').value || (teamClient && (!canReview() || teamBusy));
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
  flushIncoming();
}
function flushIncoming() {
  if (busy || !ready || document.hidden || activeIncoming || !queuedIncoming) return;
  // Recheck after the current operation has finished updating the UI.
  Promise.resolve().then(() => {
    if (busy || !ready || document.hidden || activeIncoming || !queuedIncoming) return;
    const hash = queuedIncoming; queuedIncoming = '';
    void handleIncoming(hash);
  });
}
function suspendSensitive() {
  // A notification can navigate an existing hidden window before focusing it.
  // Retry only an incoming link that has not yet shown its result. Once a name
  // was displayed, returning to the app must never make it reappear.
  if (activeIncoming?.pending && activeIncoming.generation === generation && !queuedIncoming) queuedIncoming = activeIncoming.hash;
  clearSensitive();
}
function showMode(mode) {
  clearSensitive(); const read = mode === 'read' || !!(teamClient && !canReview());
  $('read-panel').hidden = !read; $('write-panel').hidden = read;
  $('show-read').setAttribute('aria-pressed', String(read)); $('show-write').setAttribute('aria-pressed', String(!read)); if (ready) say('');
}
function messageCaption() {
  if (teamClient) return 'Проверочная история';
  return $('message-caption').value === 'test' ? 'Проверочная история' :
    $('compose-orit').checked ? 'Новый пациент ОРИТ' : 'Новый пациент';
}
function updateCaptionPreview() {
  $('output-preview').textContent = messageCaption();
  $('output-message').value = $('output-link').value ? messageCaption() + '\n' + $('output-link').value : '';
}
function invalidateComposed() {
  $('compose-output').hidden = true; $('output-link').value = '';
  $('output-message').value = '';
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
  if (joinIDFromInput(value,appBase)) return 'join';
  let card = value.startsWith('PSO-CARD1.');
  try { card ||= new URL(value).hash.startsWith('#card='); } catch {}
  if (card) { cardFromInput(value, appBase); return 'card'; }
  if (shortIDFromInput(value, appBase)) return 'message';
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
    if (inputKind(input) === 'join') { prepareJoin(input); return; }
    if (inputKind(input) === 'card') { $('token').value = ''; await inspectCard(input, fromIncoming); }
    else await reveal(input, fromIncoming);
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
async function copyCompactLink(url, label, fallbackId, detailsId = '', composed = false) {
  if (!url) return;
  let contents;
  try { contents = compactLinkContents(url, label, appBase); }
  catch (error) { say(error.message, true); return; }
  try {
    await navigator.clipboard.write([new ClipboardItem({
      'text/html':new Blob([contents.html], {type:'text/html'}),
      'text/plain':new Blob([contents.plain], {type:'text/plain'})
    })]);
    say('Скопирована ссылка с подписью «' + label + '». Вставьте в Пачку. ' + (composed ? 'Если появится длинный адрес, попробуйте «Другие способы копирования» → «Другой способ для iPhone».' : 'Если появится длинный адрес, вставьте его через кнопку ссылки (🔗) в Пачке.'));
  } catch {
    await copyText(contents.plain, fallbackId, composed ? 'Браузер скопировал полный адрес без оформления. Попробуйте «Другие способы копирования» → «Другой способ для iPhone».' : 'Браузер скопировал полную ссылку. В Пачке напишите «' + label + '», выделите эти слова и добавьте скопированный адрес через кнопку ссылки (🔗).', detailsId);
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
  if (selfContact && !teamClient) {
    const own = document.createElement('option'); own.value = selfContact.id; own.textContent = 'Себе — проверить на этом телефоне'; selector.append(own);
  }
  $('contacts-list').replaceChildren();
  for (const contact of contacts) {
    if (!teamClient) { const option = document.createElement('option'); option.value = contact.id; option.textContent = contact.name; selector.append(option); }
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
        void refreshNotifications();
        $('compose-output').hidden = true; $('output-link').value = '';
        say('Контакт убран с этого телефона. Уже отправленные ссылки это не отзывает.');
      } catch (error) { say(error.message, true); } finally { setBusy(false); }
    });
    row.append(details, remove); $('contacts-list').append(row);
  }
  if (!contacts.length) { const empty = document.createElement('p'); empty.textContent = 'Пока нет коллег. Обменяйтесь карточками и добавьте врача ниже.'; $('contacts-list').append(empty); }
  if (teamClient) {
    for (const [value,label] of [['cardiology','ПСО · Кардиолог'],['orit','ПСО · ОРИТ']]) {const option=document.createElement('option');option.value=value;option.textContent=label;selector.append(option);}
  }
  if ([...selector.options].some(option => option.value === selected)) selector.value = selected;
  setBusy(busy);
}
async function reveal(input, fromIncoming = false) {
  if (busy || !ready) return;
  showMode('read'); const current = generation; setBusy(true); say('Проверяем ссылку…');
  if (fromIncoming && activeIncoming) activeIncoming.generation = current;
  try {
    const shortID = shortIDFromInput(input, appBase);
    if (shortID && !shortLinks) throw new Error('Для короткой ссылки нужна обновлённая версия просмотрщика. Откройте приложение с интернетом и затем перезапустите его.');
    let trustedSender=null, token;
    if (shortID && teamClient && teamState.state==='active') {
      try { const record=await teamClient.resolve(device,shortID);token=record.token;trustedSender=record.sender; }
      catch(error) {if(error.status!==404)throw error;token=await shortLinks.resolve(input,appBase);}
    } else token=shortID?await shortLinks.resolve(input,appBase):parseInput(input);
    if (current !== generation || document.hidden) return;
    $('token').value = shortID ? input : token;
    const isDemo = token.startsWith('PSO-DEMO1.'); let data;
    if (isDemo) data = await openDemo(device, token);
    else { contacts = await loadContacts(); renderContacts(); data = await openSurname(device, token, trustedSender?[trustedSender,...contacts.filter(c=>c.id!==trustedSender.id)]:contacts); }
    if (current !== generation || document.hidden) return;
    if (fromIncoming && activeIncoming) activeIncoming.pending = false;
    $('result-label').textContent = isDemo ? 'Вымышленный пример' : 'Фамилия из сообщения';
    $('surname').textContent = data.surname; $('department').textContent = data.department;
    $('case-code').textContent = isDemo ? data.code : 'Отправитель: ' + data.senderName;
    $('result').hidden = false; $('token').value = ''; endsAt = performance.now() + 30000;
    tick(); timer = setInterval(tick, 250);
    say(isDemo ? 'Расшифрован вымышленный пример.' : 'Отправитель проверен.');
    $('result').scrollIntoView({block:'center', behavior:'auto'}); $('surname').focus({preventScroll:true});
  } catch (error) { if (current === generation) say(error.message || 'Не удалось открыть ссылку.', true); }
  finally { setBusy(false); }
}

function pushStatus(message) { $('push-status').textContent = message; }
function updatePushButtons() {
  const blocked = busy || pushBusy || !ready || !pushSupported;
  $('push-enable').disabled = blocked;
  $('push-enable').hidden = pushEnabled;
  $('push-test').disabled = blocked || !pushEnabled;
  $('push-test').hidden = !pushEnabled;
  $('push-disable').disabled = busy || pushBusy || !ready || !pushSubscription;
  $('push-disable').hidden = !pushSubscription;
}
function notificationMessage(status) {
  return ({accepted:'Сервис принял уведомление для получателя; доставка зависит от его телефона.',already:'Уведомление уже обрабатывалось.',unavailable:'У получателя нет доступных уведомлений. Передайте ссылку через Пачку.',gone:'Подписка получателя недействительна. Передайте ссылку через Пачку.',failed:'Уведомление не отправлено. Передайте ссылку через Пачку.'})[status] || 'Уведомление не подтверждено. Передайте ссылку через Пачку.';
}
async function finishPushAction() {
  pushBusy = false; updatePushButtons();
  if (pushRefreshPending) { pushRefreshPending = false; await refreshNotifications(); }
}
async function refreshNotifications(checkStatus = false) {
  if (!pushClient || !pushSupported || !ready || !workerReady || globalThis.Notification.permission !== 'granted') return;
  if (pushBusy) { pushRefreshPending = true; return; }
  if (!checkStatus && !pushEnabled) return;
  pushBusy = true; updatePushButtons();
  try {
    const registration = await workerReady;
    pushSubscription = await registration.pushManager.getSubscription();
    if (!pushSubscription) { pushEnabled = false; pushStatus('Уведомления выключены. Нажмите «Включить уведомления».'); return; }
    if (checkStatus && await pushClient.status(device) !== 'enabled') { pushEnabled = false; pushStatus('Уведомления выключены. Нажмите «Включить уведомления».'); return; }
    const status = await pushClient.register(device,pushSubscription,await notificationContacts());
    pushEnabled = status === 'enabled';
    pushStatus(pushEnabled ? 'Уведомления включены на этом телефоне.' : 'Сервис не включил уведомления. Повторите подключение.');
  } catch { pushEnabled = false; pushStatus('Не удалось подтвердить уведомления. Проверьте интернет и нажмите «Включить уведомления».'); }
  finally { await finishPushAction(); }
}
async function initNotifications() {
  if (!pushClient) { $('push-panel').hidden = true; return; }
  if (!standalone) { pushStatus('Для уведомлений откройте просмотрщик через синий значок на экране «Домой».'); updatePushButtons(); return; }
  pushSupported = !!workerReady && typeof globalThis.Notification !== 'undefined' && typeof globalThis.PushManager !== 'undefined';
  if (!pushSupported) { pushStatus('Уведомления недоступны на этом устройстве. На iPhone нужны iOS 16.4 или новее и установка на экран «Домой».'); updatePushButtons(); return; }
  pushStatus(globalThis.Notification.permission === 'denied' ? 'Уведомления запрещены. Разрешите их для «ПСО» в настройках уведомлений iPhone.' : 'Нажмите «Включить уведомления» и разрешите их на телефоне.');
  updatePushButtons();
  // Preload only a public application-server key; never request permission here.
  try { pushPublicKey = await pushClient.config(); } catch {}
  await refreshNotifications(true);
}
$('push-enable').addEventListener('click', async () => {
  if (busy || pushBusy || !ready || !pushSupported) return;
  pushBusy = true; updatePushButtons();
  try {
    // Must be the first asynchronous browser operation in the user click.
    const permissionPromise = globalThis.Notification.requestPermission();
    const permission = await permissionPromise;
    if (permission !== 'granted') { pushEnabled = false; pushStatus('Уведомления не разрешены. Разрешить их можно в настройках уведомлений iPhone.'); return; }
    const registration = await workerReady;
    if (!pushPublicKey) pushPublicKey = await pushClient.config();
    pushSubscription = await registration.pushManager.getSubscription();
    if (!pushSubscription) pushSubscription = await registration.pushManager.subscribe({userVisibleOnly:true,applicationServerKey:pushKeyBytes(pushPublicKey)});
    const status = await pushClient.register(device,pushSubscription,await notificationContacts());
    pushEnabled = status === 'enabled';
    pushStatus(pushEnabled ? 'Уведомления включены. Нажмите «Проверить уведомление», затем коснитесь пришедшего уведомления.' : 'Не удалось включить уведомления. Повторите подключение.');
  } catch { pushEnabled = false; pushStatus('Не удалось включить уведомления. Проверьте интернет и разрешение на уведомления, затем повторите.'); }
  finally { await finishPushAction(); }
});
$('push-disable').addEventListener('click', async () => {
  if (busy || pushBusy || !ready || !pushSubscription) return;
  pushBusy = true; pushRefreshPending = false; updatePushButtons();
  try {
    const status = await pushClient.unregister(device);
    if (status !== 'disabled') throw new Error('Not disabled');
    // Server stops first, even if the browser cannot remove its old subscription.
    pushEnabled = false;
    const removed = await pushSubscription.unsubscribe();
    if (removed) pushSubscription = null;
    pushStatus('Уведомления отключены. Включить их снова можно этой кнопкой.');
  } catch { pushStatus('Не удалось полностью отключить уведомления. Повторите или запретите их в настройках iPhone.'); }
  finally { await finishPushAction(); }
});
$('push-test').addEventListener('click', async () => {
  if (busy || pushBusy || !ready || !pushEnabled) return;
  pushBusy = true; updatePushButtons();
  try { pushStatus(notificationMessage(await pushClient.test(device)) + ' Проверочное уведомление открывает главную страницу.'); }
  catch { pushStatus('Проверочное уведомление не подтверждено. Проверьте интернет и повторите.'); }
  finally { await finishPushAction(); }
});

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
  if (teamClient) return composeTeamReview();
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
    const output = shortLinks ? await shortLinks.create(device, token, ttlMinutes, appBase) : linkForToken(token, appBase);
    if (current !== generation || document.hidden) return;
    $('output-link').value = output;
    $('output-preview').href = $('output-link').value;
    updateCaptionPreview();
    $('output-recipient').textContent = selectedID === selfContact.id ? 'Получатель: только этот просмотрщик — проверка' : 'Получатель: ' + recipient.name;
    $('compose-output').hidden = false;
    let pushMessage = '';
    if (shortLinks && pushClient) {
      try { pushMessage = notificationMessage(await pushClient.notify(device,shortIDFromInput(output,appBase))); }
      catch { pushMessage = 'Уведомление не подтверждено. Передайте ссылку через Пачку.'; }
      if (current !== generation || document.hidden) return;
    }
    say(shortLinks ? 'Короткая ссылка готова. ' + pushMessage + ' Нажмите «Скопировать ссылку» и вставьте в Пачку.' : 'Подпись со ссылкой готова. Нажмите «Скопировать готовую надпись» и вставьте в Пачку.');
    $('compose-output').scrollIntoView({block:'nearest', behavior:'auto'});
  } catch (error) { if (current === generation) say(error.message || 'Не удалось создать ссылку.', true); }
  finally { name = ''; setBusy(false); }
});
$('copy-composed').addEventListener('click', () => {
  if (shortLinks || teamClient) {
    updateCaptionPreview();
    return copyText($('output-message').value, 'output-message', 'Скопированы подпись и короткая ссылка. Вставьте в Пачку.');
  }
  return copyCompactLink($('output-link').value, messageCaption(), 'output-link', 'compose-full-link', true);
});
$('copy-composed-compact').addEventListener('click', () => {
  if (busy || !$('output-link').value) return;
  updateCaptionPreview();
  if (copyRenderedLink($('output-preview'), document, globalThis.getSelection?.())) {
    say('Браузер выполнил копирование надписи «' + messageCaption() + '». Проверьте вставку в Пачку: если получились слова без ссылки, этот способ не подходит — используйте полный адрес.');
    return;
  }
  return copyCompactLink($('output-link').value, messageCaption(), 'output-link', 'compose-full-link', true);
});
$('copy-composed-address').addEventListener('click', () => copyText($('output-link').value, 'output-link', 'Ссылка скопирована. Вставьте её в выбранный чат.', 'compose-full-link'));
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
async function inspectCard(input, fromIncoming = false) {
  if (busy || !ready) return;
  clearSensitive(); $('contacts-details').open = true; $('contact-input').value = input;
  const current = generation;
  if (fromIncoming && activeIncoming) activeIncoming.generation = current;
  setCandidate(null); setBusy(true);
  try {
    const contact = await importPublicCard(cardFromInput(input, appBase));
    if (current !== generation || document.hidden) return;
    if (contact.id === selfContact.id) throw new Error('Это карточка этого телефона. Для проверки выберите «Себе» в списке получателей.');
    if (fromIncoming && activeIncoming) activeIncoming.pending = false;
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
    void refreshNotifications();
    $('contact-input').value = ''; setCandidate(null); say('Врач добавлен. Чтобы принимать ваши ссылки, ему также нужно добавить вашу карточку.');
  } catch (error) { say(error.message, true); } finally { setBusy(false); }
});
async function handleIncoming(hash) {
  if (!hash) return;
  if (busy || !ready || document.hidden || activeIncoming) { queuedIncoming = hash; return; }
  const request = {hash, pending:true, generation};
  activeIncoming = request;
  clearSensitive(); setCandidate(null);
  clearHandoff();
  const link = appBase + hash;
  try {
    if (hash.startsWith('#join=')) { prepareJoin(link);request.pending=false;return; }
    if (!hash.startsWith('#pso=') && !hash.startsWith('#card=') && !hash.startsWith('#r=')) throw new Error('Неизвестный формат ссылки.');
    inputKind(link);
    $('handoff-link').value = link;
    $('handoff-panel').hidden = standalone;
    setBusy(busy);
    await openInput(link, true);
  } catch (error) { say(error.message, true); }
  finally {
    if (activeIncoming === request) activeIncoming = null;
    flushIncoming();
  }
}
addEventListener('hashchange', () => {
  const hash = location.hash; history.replaceState(null, '', location.pathname);
  if (!hash) return;
  queuedIncoming = hash;
  clearSensitive(); setCandidate(null);
  flushIncoming();
});
document.addEventListener('visibilitychange', () => { if (document.hidden) suspendSensitive(); else { tick(); flushIncoming(); } });
addEventListener('pagehide', suspendSensitive);


const roleLabels={admin:'Администратор',neurologist:'Невролог',intensivist:'Реаниматолог',cardiologist:'Кардиолог',bot:'Бот поступлений'};
function canReview(){return teamState.state==='active'&&['admin','neurologist'].includes(teamState.role);}
function updateTeamButtons(){
  if(!teamClient)return;
  const blocked=busy||teamBusy||!ready;
  for(const id of ['team-refresh','team-claim','invite-create'])$(id).disabled=blocked;
  $('team-claim').disabled=blocked||!joinID||!standalone;
  $('copy-invite').disabled=blocked||!inviteLink;
  for(const button of $('team-pending').querySelectorAll('button'))button.disabled=blocked||(button.teamConfirmation&&!button.teamConfirmation.checked);
}
function renderTeam(){
  if(!teamClient){$('team-panel').hidden=true;$('team-admin').hidden=true;return;}
  $('team-panel').hidden=false;
  $('team-state').textContent=teamState.state==='active'?(teamState.name+' · '+roleLabels[teamState.role]):({pending:'Подключение ожидает подтверждения администратора.',revoked:'Доступ этого телефона отключён.',unregistered:'Откройте приглашение от администратора.',unavailable:'Нет связи с командой. Повторите подключение.'})[teamState.state];
  $('show-write').hidden=!canReview();
  if(!canReview())showMode('read');
  $('team-admin').hidden=teamState.state!=='active'||teamState.role!=='admin';
  $('team-my-code').textContent=selfContact?.fingerprint||'';
  $('team-code-box').hidden=!['pending','active'].includes(teamState.state);
  updateTeamButtons();
}
async function refreshTeam(){
  if(!teamClient||!device||teamBusy)return;
  teamBusy=true;updateTeamButtons();
  try{teamState=await teamClient.status(device);teamMembers=teamState.state==='active'?await teamClient.directory(device):[];}
  catch{teamState={state:'unavailable',role:null,name:null};teamMembers=[];}
  finally{teamBusy=false;renderTeam();}
  if(teamState.state==='active'&&teamState.role==='admin')await renderTeamAdmin();
  if(pushEnabled)void refreshNotifications();
}
async function notificationContacts(){
  const local=await loadContacts(),seen=new Set(local.map(c=>c.id));
  if(teamState.state==='active')for(const member of teamMembers){if(['admin','neurologist','bot'].includes(member.role)&&!seen.has(member.id)){local.push(member);seen.add(member.id);}}
  return local;
}
function prepareJoin(input){
  const id=joinIDFromInput(input,appBase);if(!id)throw new Error('Приглашение неполное.');
  joinID=id;$('join-panel').hidden=false;$('join-link').value=appBase+'#join='+id;
  $('join-hint').textContent=standalone?'Нажмите «Подключить этот телефон». Администратор подтвердит вашу роль.':'Скопируйте приглашение, откройте синий значок и нажмите «Вставить и открыть».';
  $('team-panel').hidden=false;$('token').value='';updateTeamButtons();
  $('team-panel').scrollIntoView({block:'start',behavior:'auto'});
}
async function renderTeamAdmin(){
  if(!teamClient||teamState.state!=='active'||teamState.role!=='admin')return;
  $('team-pending').replaceChildren();
  try{
    const pending=await teamClient.pending(device);
    for(const member of pending){
      const row=document.createElement('div');row.className='contact-item';
      const name=document.createElement('strong');name.textContent=member.name+' · '+roleLabels[member.role];
      const code=document.createElement('p');code.className='device-id fingerprint';code.textContent=member.fingerprint;
      const label=document.createElement('label');label.className='check-label';const check=document.createElement('input');check.type='checkbox';const wording=document.createElement('span');wording.textContent='Сверил этот код с врачом лично или по известному номеру';label.append(check,wording);
      const approve=document.createElement('button');approve.type='button';approve.className='button button-secondary';approve.textContent='Подтвердить';approve.disabled=true;approve.teamConfirmation=check;
      check.addEventListener('change',()=>{approve.disabled=!check.checked||busy||teamBusy;});
      approve.addEventListener('click',async()=>{if(!check.checked||busy||teamBusy)return;teamBusy=true;updateTeamButtons();try{await teamClient.change(device,'approve',member.id);say('Подключение подтверждено.');}catch(e){say(e.message,true);}finally{teamBusy=false;await refreshTeam();}});
      row.append(name,code,label,approve);$('team-pending').append(row);
    }
    if(!pending.length){const empty=document.createElement('p');empty.textContent='Новых заявок нет.';$('team-pending').append(empty);}
    $('team-members').replaceChildren();
    for(const member of teamMembers){
      const row=document.createElement('div');row.className='contact-item';const name=document.createElement('strong');name.textContent=member.name+' · '+roleLabels[member.role];row.append(name);
      if(member.id!==selfContact.id){const remove=document.createElement('button');remove.type='button';remove.className='button button-secondary';remove.textContent='Отключить';let confirm=false;remove.addEventListener('click',async()=>{if(busy||teamBusy)return;if(!confirm){confirm=true;remove.textContent='Подтвердить отключение';return;}teamBusy=true;updateTeamButtons();try{await teamClient.change(device,'revoke',member.id);say('Доступ отключён.');}catch(e){say(e.message,true);}finally{teamBusy=false;await refreshTeam();}});row.append(remove);}
      $('team-members').append(row);
    }
  }catch(e){const message=document.createElement('p');message.textContent=e.message;$('team-pending').append(message);}
}
async function composeTeamReview(){
  if(!canReview()||teamBusy){say('Проверочные истории отправляют подключённые неврологи.',true);return;}
  hideResult();const current=generation,group=$('recipient').value,ttlMinutes=Number($('expiry').value);let name=$('compose-surname').value;
  invalidateComposed();setBusy(true);say('Создаём проверочную ссылку…');
  try{
    const directory=await teamClient.directory(device);teamMembers=directory;
    const role=group==='cardiology'?'cardiologist':group==='orit'?'intensivist':null;
    if(!role)throw new Error('Выберите чат.');
    const recipients=directory.filter(m=>m.role===role);if(!recipients.length)throw new Error('В этом чате пока нет подключённых получателей.');
    if(current!==generation||document.hidden)return;
    const entries=await Promise.all(recipients.map(async recipient=>({recipientId:recipient.id,token:await sealSurname(device,recipient,name,{department:$('compose-orit').checked?'ОРИТ':'',ttlMinutes})})));
    name='';$('compose-surname').value='';
    if(current!==generation||document.hidden)return;
    const output=await teamClient.create(device,{group,ttlMinutes,entries},appBase);
    if(current!==generation||document.hidden)return;
    $('output-link').value=output.link;$('output-preview').href=output.link;updateCaptionPreview();
    $('output-recipient').textContent=group==='cardiology'?'ПСО · Кардиолог':'ПСО · ОРИТ';$('compose-output').hidden=false;
    say(output.push==='accepted'?'Ссылка готова, уведомления приняты. Скопируйте её в выбранный чат.':output.push==='partial'?'Ссылка готова. Не все уведомления подтверждены — передайте ссылку в чат.':'Ссылка готова. Передайте её в выбранный чат.');
    $('compose-output').scrollIntoView({block:'nearest',behavior:'auto'});
  }catch(e){if(current===generation)say(e.message||'Не удалось создать ссылку.',true);}finally{name='';$('compose-surname').value='';setBusy(false);}
}
$('team-refresh').addEventListener('click',()=>refreshTeam());
$('copy-join').addEventListener('click',()=>copyText($('join-link').value,'join-link','Приглашение скопировано. Откройте синий значок → «Вставить и открыть».'));
$('team-claim').addEventListener('click',async()=>{
  if(!teamClient||!joinID||!standalone||busy||teamBusy)return;teamBusy=true;updateTeamButtons();
  try{await teamClient.claim(device,joinID);joinID='';$('join-panel').hidden=true;$('join-link').value='';say('Заявка отправлена. Сообщите администратору контрольный код ниже.');}
  catch(e){say(e.message,true);}finally{teamBusy=false;await refreshTeam();}
});
$('invite-form').addEventListener('submit',async event=>{
  event.preventDefault();if(!teamClient||busy||teamBusy||teamState.role!=='admin'||teamState.state!=='active')return;
  teamBusy=true;updateTeamButtons();try{const result=await teamClient.invite(device,$('invite-name').value.trim(),$('invite-role').value);inviteLink=appBase+'#join='+result.id;$('invite-link').value=inviteLink;$('invite-output').hidden=false;say('Приглашение готово. Передайте его только этому врачу.');}catch(e){say(e.message,true);}finally{teamBusy=false;updateTeamButtons();}
});
$('copy-invite').addEventListener('click',()=>copyText(inviteLink,'invite-link','Приглашение скопировано.'));

async function init() {
  setBusy(true);
  if ('serviceWorker' in navigator) {
    appUpdates = installAppUpdates({navigator,document,
      onReady(){appUpdateAvailable=true;$('app-update').textContent='Открыть новую версию';},
      onStatus(state){$('app-update-status').textContent=appUpdateAvailable?
        'Обновление загружено. Скопируйте готовые ссылки и нажмите кнопку.':
        ({checking:'Проверяем обновление…',offline:'Не удалось проверить обновление. Проверьте интернет и повторите.',current:'Установлена актуальная версия.',ready:'Обновление загружено.',unavailable:'Проверка обновлений недоступна в этом браузере.'})[state]||'';}
    });
    workerReady = appUpdates.ready;
    // Keep registration failures separate from existing key/decryption operations.
    workerReady.catch(() => {});
  }
  if (shortLinks || teamClient) {
    $('copy-composed').textContent = 'Скопировать ссылку';
    if (pushClient) { $('encrypt').textContent = 'Создать ссылку и уведомить'; $('push-compose-help').hidden = false; }
    $('short-output').hidden = false;
    $('copy-output-help').textContent = 'В Пачку вставятся подпись и короткий адрес https://. Адрес можно нажать, даже если оформление текста не сохранится.';
    $('compose-full-link').hidden = true;
  }
  try {
    if (!globalThis.crypto?.subtle) throw new Error('Нужны современный браузер и подключение по HTTPS.');
    device = await readDevice(); const identity = await deviceIdentity(device);
    selfContact = {...await importPublicCard(await exportPublicCard(device, 'Этот телефон')), verified:true};
    contacts = await loadContacts(); $('my-name').value = await getMyName();
    $('device-id').textContent = identity.fingerprint; $('status').textContent = 'Ключ этого просмотрщика готов';
    ready = true;
    if(teamClient) await refreshTeam();
    renderContacts(); setBusy(false);
  } catch (error) { ready = false; $('status').textContent = 'Не удалось подготовить просмотрщик'; say(error.message, true); setBusy(false); }
  if(teamClient) { $('message-caption').value='test';$('encrypt').textContent='Создать проверочную ссылку';$('push-compose-help').hidden=false; }
  void initNotifications();
}
$('app-update').addEventListener('click',async()=>{
  if(busy||teamBusy||pushBusy){$('app-update-status').textContent='Дождитесь завершения текущей операции.';return;}
  if(appUpdateAvailable){clearSensitive();location.reload();return;}
  if(!appUpdates){$('app-update-status').textContent='Проверка обновлений недоступна в этом браузере.';return;}
  $('app-update').disabled=true;
  try{await appUpdates.check();}finally{$('app-update').disabled=false;}
});
init();
