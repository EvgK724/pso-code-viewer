import {sealDemo, openDemo, tokenFromInput, linkForToken} from './crypto.mjs';
import {exportPublicCard, importPublicCard, deviceIdentity, sealSurname, openSurname} from './exchange.mjs';
import {readDevice, loadContacts, saveContact, deleteContact, getMyName, setMyName} from './storage.mjs';
import {cardLinkFor, cardFromInput, compactLinkContents, copyRenderedLink} from './sharing.mjs';
import {ShortLinkClient, shortIDFromInput} from './shortlinks.mjs';
import {SHORTLINK_ENDPOINT, PUSH_ENDPOINT, TEAM_ENDPOINT, DIRECT_ENDPOINT, DEVICE_AUTH_ENDPOINT} from './shortlink-config.mjs';
import {PushClient, pushKeyBytes} from './push.mjs';
import {TeamClient, joinIDFromInput} from './team.mjs';
import {installAppUpdates} from './updates.mjs';
import {DirectClient, directIDFromInput, newMessageID, savePending, loadPending, removePending} from './direct.mjs';
import {sealMessage, openMessage} from './messages.mjs';
import {preparePhoto, photoObjectURL} from './photos.mjs';
import {DeviceUnlockClient} from './device-unlock.mjs';
import {makeRecipientGrant, verifyRecipientGrant, verifyRecipientDirectory, pinOrganizerCard, loadOrganizerCard, trustedInvitationURL, parseTrustedInvitation} from './recipient-trust.mjs';

const appBase = new URL('./', import.meta.url).href;
const shortLinks = SHORTLINK_ENDPOINT ? new ShortLinkClient(SHORTLINK_ENDPOINT) : null;
const pushClient = PUSH_ENDPOINT ? new PushClient(PUSH_ENDPOINT) : null;
const teamClient = TEAM_ENDPOINT ? new TeamClient(TEAM_ENDPOINT) : null;
const directClient = DIRECT_ENDPOINT ? new DirectClient(DIRECT_ENDPOINT) : null;
const deviceUnlock = DEVICE_AUTH_ENDPOINT ? new DeviceUnlockClient(DEVICE_AUTH_ENDPOINT) : null;
const $ = id => document.getElementById(id);
let device, selfContact, contacts = [], candidate = null;
let ready = false, busy = false, generation = 0, timer, endsAt = 0, demoLink = '';
let queuedIncoming = location.hash, activeIncoming = null;
let workerReady = null, pushBusy = false, pushEnabled = false, pushSupported = false, pushRefreshPending = false;
let pushPublicKey = '', pushSubscription = null;
let teamState={state:'unregistered',role:null,name:null}, teamMembers=[], teamBusy=false, joinID='', inviteLink='';
let lastConfirmedTeam=null, teamConnectionMessage='';
let appUpdates=null, appUpdateAvailable=false;
let organizerPin=null, invitationOrganizer=null;
let activeBox='inbox', inboxItems=[], inboxNext=null, inboxBusy=false, directPhoto=null, photoURL='', previewURL='', photoBusy=false, directPendingBusy=false, discardPendingConfirmed=false;
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
  for (const id of ['surname','department','case-code','countdown','result-comment']) $(id).textContent = '';
  $('result-photo').hidden=true;$('result-photo').removeAttribute('src');
  if(photoURL){URL.revokeObjectURL(photoURL);photoURL='';}
  if (message) say(message);
}
function clearPhoto(){directPhoto=null;$('compose-photo').value='';$('photo-preview').hidden=true;$('photo-preview').removeAttribute('src');$('photo-remove').hidden=true;$('photo-status').textContent='';if(previewURL){URL.revokeObjectURL(previewURL);previewURL='';}}
function clearSensitive() { hideResult(); $('compose-surname').value = ''; $('compose-comment').value=''; clearPhoto(); }
function tick() {
  if (!endsAt) return;
  const seconds = Math.ceil((endsAt - performance.now()) / 1000);
  if (seconds <= 0) return hideResult('Содержимое скрыто. До истечения срока сообщение можно открыть снова.');
  $('countdown').textContent = 'Скроется через ' + seconds + ' с';
}
function setBusy(value) {
  busy = value;
  updatePushButtons();
  updateTeamButtons();
  for (const id of ['token','compose-surname','compose-comment','compose-photo','recipient','compose-orit','message-caption','expiry','my-name','contact-input','confirm-fingerprint']) $(id).disabled = value || !ready;
  for (const id of ['demo','open','paste-open','export-card','inspect-contact']) $(id).disabled = value || !ready;
  $('copy-handoff').disabled = value || !$('handoff-link').value;
  $('encrypt').disabled = value || photoBusy || !ready || !$('recipient').value || (teamClient && (!canReview() || teamBusy));
  $('inbox-refresh').disabled=value||inboxBusy||!ready;$('inbox-more').disabled=value||inboxBusy||!inboxNext;
  $('retry-pending').disabled=value||directPendingBusy||!ready;
  $('discard-pending').disabled=value||directPendingBusy||!ready;
  $('device-unlock-enable').disabled=value||teamBusy||!ready||teamState.state!=='active';
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
  if (busy || incomingTeamBlocked(queuedIncoming) || !ready || document.hidden || activeIncoming || !queuedIncoming) return;
  // Recheck after the current operation has finished updating the UI.
  Promise.resolve().then(() => {
    if (busy || incomingTeamBlocked(queuedIncoming) || !ready || document.hidden || activeIncoming || !queuedIncoming) return;
    const hash = queuedIncoming; queuedIncoming = '';
    void handleIncoming(hash);
  });
}
function incomingTeamBlocked(hash) {
  return teamBusy || !!(directClient && hash?.startsWith('#m=') && teamState.state!=='active');
}
function suspendSensitive() {
  // A notification can navigate an existing hidden window before focusing it.
  // Retry only an incoming link that has not yet shown its result. Once a name
  // was displayed, returning to the app must never make it reappear.
  if (activeIncoming?.pending && activeIncoming.generation === generation && !queuedIncoming) queuedIncoming = activeIncoming.hash;
  clearSensitive();deviceUnlock?.clear();
}
function showMode(mode, {preserveNotice=false} = {}) {
  clearSensitive(); const read = mode === 'read' || !!(teamClient && !canReview());
  $('read-panel').hidden = !read; $('write-panel').hidden = read;
  $('direct-panel').hidden=!directClient||!read;
  $('legacy-open').hidden=!!directClient&&!read;
  $('show-read').setAttribute('aria-pressed', String(read)); $('show-write').setAttribute('aria-pressed', String(!read)); if (ready&&!preserveNotice) say('');
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
  if (value.length > 12000) throw new Error('Ссылка слишком длинная. Скопируйте только ссылку без комментария.');
  if (/^[0-9a-f\s-]+$/i.test(value) && value.replace(/[\s-]/g, '').length === 64) throw new Error('Это контрольный код карточки врача. По нему фамилия не открывается. Попросите отправителя создать ссылку для вас через «Создать ссылку» и скопировать её целиком.');
  if (/^[0-9\s-]+$/.test(value)) throw new Error('Вставлен только набор цифр. Нужна полная ссылка из «Скопировать адрес для Пачки» или зашифрованный код, начинающийся с PSO1.');
  if (!value) throw new Error('Сначала вставьте ссылку в поле или нажмите «Вставить и открыть».');
  if (joinIDFromInput(value,appBase)||value.includes('#join=')) return 'join';
  if (directIDFromInput(value,appBase)) return 'direct';
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
    if (inputKind(input) === 'join') { await prepareJoin(input); return; }
    if (inputKind(input) === 'direct') { await revealDirect(directIDFromInput(input,appBase),fromIncoming);return; }
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
    $('result').hidden = false; $('token').value = ''; endsAt = performance.now() + Math.min(30000, Math.max(0,data.expires-Date.now()));
    tick(); timer = setInterval(tick, 250);
    say(isDemo ? 'Расшифрован вымышленный пример.' : 'Отправитель проверен.');
    $('result').scrollIntoView({block:'center', behavior:'auto'}); $('surname').focus({preventScroll:true});
  } catch (error) { if (current === generation) say(error.message || 'Не удалось открыть ссылку.', true); }
  finally { setBusy(false); }
}

function pushStatus(message) { $('push-status').textContent = message; }
function updatePushButtons() {
  const teamBlocked=!!teamClient&&(teamBusy||['unavailable','revoked'].includes(teamState.state));
  const blocked = busy || pushBusy || teamBlocked || !ready || !pushSupported;
  $('push-enable').disabled = blocked;
  $('push-enable').hidden = pushEnabled;
  $('push-test').disabled = blocked || !pushEnabled;
  $('push-test').hidden = !pushEnabled;
  $('push-disable').disabled = busy || pushBusy || teamBlocked || !ready || !pushSubscription;
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
  if(teamBusy||(teamClient&&['unavailable','revoked'].includes(teamState.state)))return;
  if (!pushClient || !pushSupported || !ready || !workerReady || globalThis.Notification.permission !== 'granted') return;
  if (pushBusy) { pushRefreshPending = true; return; }
  if (!checkStatus && !pushEnabled) return;
  pushBusy = true; updatePushButtons();
  try {
    const registration = await workerReady;
    pushSubscription = await registration.pushManager.getSubscription();
    if(teamBusy)return;
    if (!pushSubscription) { pushEnabled = false; pushStatus('Уведомления выключены. Нажмите «Включить уведомления».'); return; }
    if (checkStatus && await pushClient.status(device) !== 'enabled') { pushEnabled = false; pushStatus('Уведомления выключены. Нажмите «Включить уведомления».'); return; }
    if(teamBusy)return;
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
  if (busy || pushBusy || teamBusy || (teamClient&&['unavailable','revoked'].includes(teamState.state)) || !ready || !pushSupported) return;
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
  if (busy || pushBusy || teamBusy || (teamClient&&['unavailable','revoked'].includes(teamState.state)) || !ready || !pushSubscription) return;
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
  if (busy || pushBusy || teamBusy || (teamClient&&['unavailable','revoked'].includes(teamState.state)) || !ready || !pushEnabled) return;
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
for (const id of ['compose-surname','compose-comment','expiry']) $(id).addEventListener('input', invalidateComposed);
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
  if (directClient) return composeDirectReview();
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
    $('legacy-open').open=true;
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
  if (busy || incomingTeamBlocked(hash) || !ready || document.hidden || activeIncoming) { queuedIncoming = hash; return; }
  const request = {hash, pending:true, generation};
  activeIncoming = request;
  clearSensitive(); setCandidate(null);
  clearHandoff();
  const link = appBase + hash;
  try {
    if (hash.startsWith('#join=')) { await prepareJoin(link);request.pending=false;return; }
    if (!hash.startsWith('#pso=') && !hash.startsWith('#card=') && !hash.startsWith('#r=') && !hash.startsWith('#m=')) throw new Error('Неизвестный формат ссылки.');
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
document.addEventListener('visibilitychange', () => { if (document.hidden) suspendSensitive(); else { tick(); flushIncoming(); if(directClient)void refreshInbox(); } });
addEventListener('pagehide', suspendSensitive);


const roleLabels={admin:'Администратор',neurologist:'Невролог',intensivist:'Реаниматолог',cardiologist:'Кардиолог',bot:'Бот поступлений'};
function canReview(){return teamState.state==='active'&&['admin','neurologist'].includes(teamState.role);}
function canAdmin(){return teamState.state==='active'&&teamState.role==='admin';}
function actionError(error,stage){
  const status=Number.isInteger(error?.status)&&error.status>=100&&error.status<=599?' (HTTP '+error.status+')':'';
  return stage+': '+(error?.message||'Не удалось завершить действие.')+status;
}
function teamRefreshFailed(error,stage){
  teamMembers=[];
  if(error?.status===403||error?.status===401){
    lastConfirmedTeam=null;teamState={state:'revoked',role:null,name:null};teamConnectionMessage='';
  }else{
    teamState={state:'unavailable',role:null,name:null};
    teamConnectionMessage=actionError(error,stage)+' Действия недоступны. Нажмите «Обновить».';
  }
  clearSensitive();deviceUnlock?.clear();
  inboxItems=[];inboxNext=null;$('inbox-list').replaceChildren();
}
function updateTeamButtons(){
  if(!teamClient)return;
  const blocked=busy||teamBusy||!ready;
  $('team-refresh').disabled=blocked;
  $('invite-create').disabled=blocked||!canAdmin();
  $('team-claim').disabled=blocked||!joinID||!standalone||['unavailable','revoked'].includes(teamState.state);
  $('copy-invite').disabled=blocked||!inviteLink;
  for(const id of ['team-pending','team-members'])for(const button of $(id).querySelectorAll('button'))button.disabled=blocked||!canAdmin()||(button.teamConfirmation&&!button.teamConfirmation.checked);
  $('device-unlock-enable').disabled=blocked||teamState.state!=='active';
  updatePushButtons();
}
function renderTeam(){
  if(!teamClient){$('team-panel').hidden=true;$('team-admin').hidden=true;return;}
  $('team-panel').hidden=false;
  const displayTeam=teamState.state==='unavailable'?lastConfirmedTeam:teamState;
  const identity=displayTeam?.state==='active'?displayTeam.name+' · '+roleLabels[displayTeam.role]:'';
  $('team-state').textContent=teamState.state==='active'?identity:teamState.state==='unavailable'?(identity?identity+'. ':'')+(teamConnectionMessage||'Нет связи с командой. Действия недоступны. Нажмите «Обновить».'):({pending:'Подключение ожидает подтверждения администратора.',revoked:'Доступ этого телефона отключён.',unregistered:'Откройте приглашение от администратора.'})[teamState.state];
  $('show-write').hidden=!canReview();
  if(!canReview())showMode('read',{preserveNotice:true});
  if(directClient){$('show-read').textContent='Входящие';$('show-write').textContent='Написать';$('direct-panel').hidden=teamState.state!=='active';$('inbox-status').textContent=teamState.state==='active'?'':$('team-state').textContent;}
  // The last confirmed role is display-only; all actions use teamState.
  $('team-admin').hidden=displayTeam?.state!=='active'||displayTeam?.role!=='admin';
  $('team-my-code').textContent=selfContact?.fingerprint||'';
  $('team-code-box').hidden=!['pending','active'].includes(teamState.state);
  updateTeamButtons();
}
async function refreshTeam(){
  if(!teamClient||!device||teamBusy)return;
  teamBusy=true;updateTeamButtons();
  let stage='Проверка подключения';
  try{
    teamState=await teamClient.status(device);teamConnectionMessage='';
    lastConfirmedTeam=teamState.state==='active'?{...teamState}:null;
    stage='Не удалось обновить список команды';
    teamMembers=teamState.state==='active'?await teamClient.directory(device):[];
    if(teamState.state!=='active'){clearSensitive();deviceUnlock?.clear();inboxItems=[];inboxNext=null;$('inbox-list').replaceChildren();}
    if(directClient&&teamState.state==='active'){
      try{organizerPin=await loadOrganizerCard();if(teamState.role==='admin'&&!organizerPin)organizerPin=await pinOrganizerCard(await exportPublicCard(device,teamState.name),{confirmed:true});}
      catch(e){say(e.message,true);}
      $('organizer-missing').hidden=!!organizerPin;
    }
    if(canAdmin())await renderTeamAdmin();
  }
  catch(error){teamRefreshFailed(error,stage);}
  finally{teamBusy=false;renderTeam();flushIncoming();}
  if(teamState.state!=='active')return;
  // Do not burst inbox, device-auth and push requests after a team operation.
  if(directClient){await refreshInbox();await refreshPending();}
  if(deviceUnlock)await refreshUnlock();
  if(pushEnabled)await refreshNotifications();
}
async function notificationContacts(){
  const local=await loadContacts(),seen=new Set(local.map(c=>c.id));
  if(teamState.state==='active')for(const member of teamMembers){if(['admin','neurologist','bot'].includes(member.role)&&!seen.has(member.id)){local.push(member);seen.add(member.id);}}
  return local;
}
async function prepareJoin(input){
  const trusted=directClient?await parseTrustedInvitation(input,appBase):null;
  const id=trusted?.id||joinIDFromInput(input,appBase);if(!id)throw new Error('Приглашение неполное.');
  joinID=id;$('join-panel').hidden=false;$('join-link').value=trusted?String(input):appBase+'#join='+id;
  if(trusted){invitationOrganizer=trusted.organizerCard;$('organizer-code').textContent=trusted.fingerprint;$('organizer-confirm').checked=false;$('organizer-trust').hidden=false;}
  else if(directClient&&!organizerPin)say('Попросите организатора прислать новое приглашение с ключом команды.',true);
  $('join-hint').textContent=standalone?'Нажмите «Подключить этот телефон». Администратор подтвердит вашу роль.':'Скопируйте приглашение, откройте синий значок и нажмите «Вставить и открыть».';
  $('team-panel').hidden=false;$('token').value='';updateTeamButtons();
  $('team-panel').scrollIntoView({block:'start',behavior:'auto'});
}
async function renderTeamAdmin(){
  if(directClient)return renderDirectAdmin();
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
      check.addEventListener('change',()=>{approve.disabled=!check.checked||busy||teamBusy||!canAdmin();});
      approve.addEventListener('click',async()=>{if(!check.checked||busy||teamBusy||!canAdmin())return;teamBusy=true;updateTeamButtons();approve.textContent='Подтверждаем…';say('Подтверждаем подключение телефона…');try{await teamClient.change(device,'approve',member.id);row.hidden=true;say('Подключение подтверждено.');}catch(e){say(actionError(e,'Подтверждение телефона'),true);}finally{approve.textContent='Подтвердить';teamBusy=false;await refreshTeam();}});
      row.append(name,code,label,approve);$('team-pending').append(row);
    }
    if(!pending.length){const empty=document.createElement('p');empty.textContent='Новых заявок нет.';$('team-pending').append(empty);}
    $('team-members').replaceChildren();
    for(const member of teamMembers){
      const row=document.createElement('div');row.className='contact-item';const name=document.createElement('strong');name.textContent=member.name+' · '+roleLabels[member.role];row.append(name);
      if(member.id!==selfContact.id){const remove=document.createElement('button');remove.type='button';remove.className='button button-secondary';remove.textContent='Отключить';let confirm=false;remove.addEventListener('click',async()=>{if(busy||teamBusy||!canAdmin())return;if(!confirm){confirm=true;remove.textContent='Подтвердить отключение';return;}teamBusy=true;updateTeamButtons();try{await teamClient.change(device,'revoke',member.id);say('Доступ отключён.');}catch(e){say(e.message,true);}finally{teamBusy=false;await refreshTeam();}});row.append(remove);}
      $('team-members').append(row);
    }
  }catch(e){if(e.status===403||e.status===401)teamRefreshFailed(e,'Проверка доступа');const message=document.createElement('p');message.textContent=e.message;$('team-pending').append(message);}
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
  if(!teamClient||!joinID||!standalone||busy||teamBusy||['unavailable','revoked'].includes(teamState.state))return;teamBusy=true;updateTeamButtons();
  try{if(directClient&&!organizerPin)throw new Error('Сначала подтвердите ключ организатора по коду ниже.');await teamClient.claim(device,joinID);joinID='';$('join-panel').hidden=true;$('join-link').value='';say('Заявка отправлена. Сообщите администратору контрольный код ниже.');}
  catch(e){say(e.message,true);}finally{teamBusy=false;await refreshTeam();}
});
$('invite-form').addEventListener('submit',async event=>{
  event.preventDefault();if(!teamClient||busy||teamBusy||teamState.role!=='admin'||teamState.state!=='active')return;
  teamBusy=true;updateTeamButtons();try{const result=await teamClient.invite(device,$('invite-name').value.trim(),$('invite-role').value);inviteLink=directClient?await trustedInvitationURL(appBase,result.id,await exportPublicCard(device,teamState.name)):appBase+'#join='+result.id;$('invite-link').value=inviteLink;$('invite-output').hidden=false;say('Приглашение готово. Передайте его только этому врачу.');}catch(e){say(e.message,true);}finally{teamBusy=false;updateTeamButtons();flushIncoming();}
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
  if(teamClient) { $('message-caption').value='test';$('encrypt').textContent=directClient?'Отправить врачу':'Создать проверочную ссылку';$('push-compose-help').hidden=false; }
  $('direct-fields').hidden=!directClient;$('direct-panel').hidden=!directClient;
  $('legacy-open').open=!directClient;
  if(directClient){$('show-read').textContent='Входящие';$('show-write').textContent='Написать';$('compose-surname').required=false;$('legacy-output').hidden=true;setInterval(async()=>{if(!document.hidden){await refreshInbox();await retryPending(false);}},60000);}
  $('device-unlock-settings').hidden=!deviceUnlock;
  void initNotifications();
}
$('app-update').addEventListener('click',async()=>{
  if(busy||teamBusy||pushBusy){$('app-update-status').textContent='Дождитесь завершения текущей операции.';return;}
  if(appUpdateAvailable){clearSensitive();location.reload();return;}
  if(!appUpdates){$('app-update-status').textContent='Проверка обновлений недоступна в этом браузере.';return;}
  $('app-update').disabled=true;
  try{await appUpdates.check();}finally{$('app-update').disabled=false;}
});

function messageTitle(item){return item.kind==='review'?'Проверочная история':'Новый пациент';}
function dateLabel(time){return new Date(time).toLocaleString('ru-RU',{day:'2-digit',month:'2-digit',hour:'2-digit',minute:'2-digit'});}
function renderInbox(){
  $('inbox-list').replaceChildren();
  const unread=inboxItems.filter(item=>!item.openedAt).length;
  $('inbox-count').textContent=activeBox==='inbox'&&unread?String(unread):'';
  $('box-inbox').setAttribute('aria-pressed',String(activeBox==='inbox'));$('box-outbox').setAttribute('aria-pressed',String(activeBox==='outbox'));
  for(const item of inboxItems){
    const row=document.createElement('article');row.className='message-row';
    const title=document.createElement('strong');title.textContent=messageTitle(item);row.append(title);
    const info=document.createElement('p');info.className='message-meta';info.textContent=(item.group==='orit'?'Реаниматологи':'Кардиолог')+' · '+dateLabel(item.issued);row.append(info);
    const sender=document.createElement('p');sender.className='message-meta';sender.textContent='От '+item.senderName;row.append(sender);
    if(activeBox==='inbox'){
      const button=document.createElement('button');button.type='button';button.className='button '+(item.openedAt?'button-secondary':'button-primary');button.textContent=item.openedAt?'Открыть снова':'Открыть';button.addEventListener('click',()=>revealDirect(item.id));row.append(button);
      if(!item.openedAt){const badge=document.createElement('span');badge.className='unread-mark';badge.textContent='Не открыто';row.append(badge);}
    }else{const status=document.createElement('p');status.className='delivery-state';status.textContent=item.openedCount?'Открыли: '+item.openedCount+' из '+item.recipientCount:'Сохранено · ожидает открытия';row.append(status);}
    $('inbox-list').append(row);
  }
  $('inbox-more').hidden=!inboxNext;
  if(!inboxItems.length)$('inbox-status').textContent=activeBox==='inbox'?'Новых сообщений пока нет.':'Отправленных сообщений пока нет.';
}
async function refreshInbox(more=false){
  if(!directClient||!ready||teamBusy||teamState.state!=='active'||inboxBusy||document.hidden)return;
  const box=activeBox;inboxBusy=true;setBusy(busy);$('inbox-status').textContent='Обновляем…';
  try{const r=await directClient.list(device,box,more?inboxNext:null);if(box!==activeBox)return;
    inboxItems=more?[...inboxItems,...r.items.filter(m=>!inboxItems.some(old=>old.id===m.id))]:r.items;inboxNext=r.next;renderInbox();if(inboxItems.length)$('inbox-status').textContent=activeBox==='outbox'?'«Открыто» означает просмотр сообщения, а не выполненную консультацию.':'Сообщения доступны до 24 часов.';
    if(activeBox==='inbox'&&navigator.setAppBadge){const unread=inboxItems.filter(m=>!m.openedAt).length;try{if(unread)await navigator.setAppBadge(unread);else await navigator.clearAppBadge?.();}catch{}}
  }catch(e){$('inbox-status').textContent=e.status===403?'Доступ этого телефона отключён.':e.message;if(e.status===403){teamRefreshFailed(e,'Проверка доступа');renderTeam();}}
  finally{inboxBusy=false;setBusy(busy);}
}
async function revealDirect(id,fromIncoming=false){
  if(!directClient||busy||!ready)return;
  if(teamBusy||teamState.state!=='active'){say('Сначала обновите подключение к команде.',true);return;}
  showMode('read');const current=generation;setBusy(true);say('Открываем сообщение…');
  if(fromIncoming&&activeIncoming)activeIncoming.generation=current;
  try{
    let unlockToken=deviceUnlock?await deviceUnlock.ensure(device):'';
    if(current!==generation||document.hidden)return;
    let record;try{record=await directClient.open(device,id,{unlockToken});}catch(e){
      if(e.status!==428||!deviceUnlock)throw e;deviceUnlock.clear();unlockToken=await deviceUnlock.ensure(device);
      if(current!==generation||document.hidden)return;record=await directClient.open(device,id,{unlockToken});
    }
    if(current!==generation||document.hidden)return;
    if(!organizerPin)throw new Error('Сначала подключите ключ организатора через его личное приглашение.');
    let sender;
    if(record.sender.id===organizerPin.id&&record.senderRole==='admin')sender={...organizerPin,name:record.senderName,verified:true};
    else sender=await verifyRecipientGrant({id:record.sender.id,name:record.senderName,role:record.senderRole,card:record.senderCard,approvalProof:record.senderApprovalProof},organizerPin);
    if(record.meta.kind==='admission'&&record.senderRole!=='bot'||record.meta.kind==='review'&&!['admin','neurologist'].includes(record.senderRole))throw new Error('Роль отправителя не разрешает это сообщение.');
    const ownRecord=(await directClient.directory(device)).find(member=>member.id===selfContact.id);
    const ownRole=(await verifyRecipientGrant(ownRecord,organizerPin)).role;
    if(record.meta.group!==(ownRole==='cardiologist'?'cardiology':ownRole==='intensivist'?'orit':null))throw new Error('Сообщение адресовано другой группе врачей.');
    if(current!==generation||document.hidden)return;
    const data=record.payload?await openMessage(device,record.token,record.payload,[sender]):await openSurname(device,record.token,[sender]);
    if(current!==generation||document.hidden)return;
    if(record.payload&&(data.messageId!==id||data.group!==record.meta.group||data.kind!==record.meta.kind))throw new Error('Содержимое не соответствует сообщению.');
    if(data.expires!==record.meta.expires||data.issued!==record.meta.issued)throw new Error('Время сообщения не совпадает с подписанным содержимым.');
    $('surname').textContent=data.surname||'Проверочная история';$('department').textContent=data.department;
    $('result-label').textContent=record.meta.kind==='admission'?'Новый пациент':'Проверочная история';
    $('result-comment').textContent=data.comment||'';$('case-code').textContent='Отправитель: '+data.senderName;
    if(data.photo){photoURL=photoObjectURL(data.photo);$('result-photo').src=photoURL;$('result-photo').hidden=false;}
    $('result').hidden=false;$('token').value='';endsAt=performance.now()+Math.min(30000,Math.max(0,data.expires-Date.now()));tick();timer=setInterval(tick,250);
    if(fromIncoming&&activeIncoming)activeIncoming.pending=false;
    say('Сообщение расшифровано на этом телефоне.');$('result').scrollIntoView({block:'center',behavior:'auto'});$('surname').focus({preventScroll:true});
    // Receipt is written only after successful verification/decryption and display.
    void directClient.ack(device,id).then(()=>{for(const item of inboxItems)if(item.id===id)item.openedAt=Date.now();renderInbox();}).catch(()=>{if(current===generation&&!document.hidden)say('Сообщение открыто. Отметка о просмотре пока не отправлена.');});
  }catch(e){if(current===generation&&!document.hidden)say(e.message||'Не удалось открыть сообщение.',true);}
  finally{setBusy(false);}
}
async function refreshPending(){
  if(!directClient||!ready)return;
  try{const items=await loadPending();$('pending-count').textContent=items.length?'Ожидают подтверждения: '+items.length+'. Сохранён только шифр; повтор не создаёт второе сообщение.':'';$('retry-pending').hidden=!items.length;$('discard-pending').hidden=!items.length;discardPendingConfirmed=false;$('discard-pending').textContent='Удалить очередь с телефона';}
  catch{$('pending-count').textContent='Очередь этого телефона недоступна.';}
}
async function retryPending(announce=true){
  if(!directClient||!ready||busy||teamBusy||directPendingBusy||document.hidden||!canReview())return;
  directPendingBusy=true;setBusy(busy);let sent=0;
  try{for(const data of await loadPending()){
    if(teamBusy||!canReview())break;
    try{await directClient.create(device,data);await removePending(data.id);sent++;}
    catch(e){if(announce)say(e.status===409?'Состав получателей изменился. Старая зашифрованная запись не отправлена. Создайте её заново после удаления из очереди.':e.message,true);break;}
  }if(sent&&announce)say('Сохранено для получателей: '+sent+'.');await refreshPending();void refreshInbox();}
  finally{directPendingBusy=false;setBusy(busy);}
}
async function composeDirectReview(){
  if(!canReview()||teamBusy||photoBusy){say('Проверочные истории отправляют подключённые неврологи.',true);return;}
  hideResult();const current=generation,group=$('recipient').value,issued=Date.now(),expires=issued+Number($('expiry').value)*60000;
  let content={surname:$('compose-surname').value,department:$('compose-orit').checked?'ОРИТ':'ПСО',comment:$('compose-comment').value,photo:directPhoto};
  let queued=false;
  setBusy(true);say('Шифруем для получателей…');
  try{
    const role=group==='cardiology'?'cardiologist':group==='orit'?'intensivist':'',directory=await trustedDirectory(role);
    const recipients=directory.filter(member=>member.role===role);if(!recipients.length)throw new Error('В выбранной группе пока нет подключённых врачей.');
    const id=newMessageID(),sealed=await sealMessage(device,recipients,content,{id,group,kind:'review',issued,expires});
    content=null;$('compose-surname').value='';$('compose-comment').value='';clearPhoto();
    if(current!==generation||document.hidden)return;
    const request={id,group,kind:'review',issued,expires,...sealed};await savePending(request);queued=true;
    const result=await directClient.create(device,request);await removePending(id);queued=false;
    if(current!==generation||document.hidden)return;
    say(result.push==='accepted'?'Сообщение сохранено. Уведомление передано в службу доставки.':'Сообщение сохранено во «Входящих» получателей. Уведомление ожидает доставки.');
    await refreshPending();void refreshInbox();
  }catch(e){if(current===generation&&!document.hidden)say(queued?'Отправка не подтверждена. Шифр сохранён на этом телефоне. Во «Входящих» можно повторить отправку или удалить попытку. '+e.message:(e.message||'Отправка не подтверждена. Проверьте очередь.'),true);void refreshPending();}
  finally{content=null;setBusy(false);}
}
async function refreshUnlock(){
  if(!deviceUnlock||!ready||teamBusy||teamState.state!=='active')return;
  try{const s=await deviceUnlock.status(device);$('device-unlock-state').textContent=s.enabled?'Подтверждение при открытии включено.':'Можно подтверждать открытие Face ID или кодом телефона.';$('device-unlock-enable').hidden=s.enabled;}
  catch{$('device-unlock-state').textContent='Не удалось проверить защиту устройства.';}
}
$('device-unlock-enable').addEventListener('click',async()=>{
  if(!deviceUnlock||busy||teamBusy||!ready||teamState.state!=='active')return;setBusy(true);
  try{await deviceUnlock.enroll(device);say('Подтверждение на этом телефоне включено.');await refreshUnlock();}catch(e){say(e.message||'Не удалось включить подтверждение.',true);}finally{setBusy(false);}
});
$('box-inbox').addEventListener('click',()=>{activeBox='inbox';inboxItems=[];inboxNext=null;void refreshInbox();});
$('box-outbox').addEventListener('click',()=>{activeBox='outbox';inboxItems=[];inboxNext=null;void refreshInbox();});
$('inbox-refresh').addEventListener('click',()=>refreshInbox());
$('inbox-more').addEventListener('click',()=>refreshInbox(true));
$('retry-pending').addEventListener('click',()=>retryPending());
$('discard-pending').addEventListener('click',async()=>{
  if(busy||directPendingBusy||!ready)return;
  if(!discardPendingConfirmed){discardPendingConfirmed=true;$('discard-pending').textContent='Подтвердить удаление очереди';say('Будут удалены только попытки повтора на этом телефоне. Уже доставленные сообщения останутся у получателей.');return;}
  directPendingBusy=true;setBusy(busy);try{for(const entry of await loadPending())await removePending(entry.id);say('Очередь этого телефона удалена. Нужное сообщение можно подготовить заново.');await refreshPending();}catch(e){say(e.message,true);}finally{directPendingBusy=false;setBusy(busy);}
});
$('photo-remove').addEventListener('click',clearPhoto);
$('compose-photo').addEventListener('change',async()=>{
  const file=$('compose-photo').files?.[0];clearPhoto();if(!file)return;
  const current=generation;photoBusy=true;setBusy(busy);$('photo-status').textContent='Готовим фото на телефоне…';
  try{const photo=await preparePhoto(file);if(current!==generation||document.hidden)return;directPhoto=photo;previewURL=photoObjectURL(photo);$('photo-preview').src=previewURL;$('photo-preview').hidden=false;$('photo-remove').hidden=false;$('photo-status').textContent='Фото подготовлено. Оно будет зашифровано перед отправкой.';}
  catch(e){if(current===generation&&!document.hidden)$('photo-status').textContent=e.message;}
  finally{photoBusy=false;setBusy(busy);}
});
addEventListener('online',async()=>{await refreshInbox();await retryPending(false);});
async function renderDirectAdmin(){
  if(teamState.state!=='active'||teamState.role!=='admin')return;
  $('team-pending').replaceChildren();$('team-members').replaceChildren();
  try{
    const members=await directClient.members(device),pending=members.filter(m=>m.state==='pending');
    for(const member of pending){
      const row=document.createElement('div');row.className='contact-item';const title=document.createElement('strong');title.textContent=member.name+' · '+roleLabels[member.role];
      const code=document.createElement('p');code.className='fingerprint device-id';code.textContent=member.fingerprint;
      const label=document.createElement('label');label.className='check-label';const check=document.createElement('input');check.type='checkbox';const text=document.createElement('span');text.textContent='Сверил код с врачом лично или по известному номеру';label.append(check,text);
      const old=document.createElement('select');old.setAttribute('aria-label','Вместо прежнего телефона');const first=document.createElement('option');first.value='';first.textContent='Новый участник';old.append(first);
      for(const previous of members.filter(m=>m.id!==member.id&&m.role!=='admin'&&m.state!=='pending')){const option=document.createElement('option');option.value=previous.id;option.textContent='Заменить телефон: '+previous.name+(previous.state==='revoked'?' · отключён':'');old.append(option);}
      const approve=document.createElement('button');approve.type='button';approve.className='button button-primary';approve.textContent='Подтвердить подключение';approve.disabled=true;approve.teamConfirmation=check;
      check.addEventListener('change',()=>{approve.disabled=!check.checked||busy||teamBusy||!canAdmin();});
      approve.addEventListener('click',async()=>{
        if(!check.checked||busy||teamBusy||!canAdmin())return;
        teamBusy=true;updateTeamButtons();approve.textContent='Подтверждаем…';
        let stage=old.value?'Замена телефона':'Подтверждение телефона';say(stage+'…');
        try{
          if(old.value){const previous=members.find(m=>m.id===old.value);const proof=await makeRecipientGrant(device,{...member,name:previous.name,role:previous.role});await directClient.replace(device,old.value,member.id,proof);}
          else{await teamClient.change(device,'approve',member.id);stage='Подписание доступа';say(stage+'…');await directClient.certify(device,member.id,await makeRecipientGrant(device,member));}
          row.hidden=true;
          say(old.value?'Новый телефон подключён, прежний отключён. Старые сообщения на новый ключ не переносятся.':'Подключение подтверждено.');
        }catch(e){say(actionError(e,stage),true);}
        finally{approve.textContent='Подтвердить подключение';teamBusy=false;await refreshTeam();}
      });
      row.append(title,code,label,old,approve);$('team-pending').append(row);
    }
    if(!pending.length){const p=document.createElement('p');p.textContent='Новых заявок нет.';$('team-pending').append(p);}
    for(const member of members.filter(m=>m.state!=='pending')){
      const row=document.createElement('details');row.className='member-editor';const summary=document.createElement('summary');summary.textContent=member.name+' · '+roleLabels[member.role]+(member.state==='revoked'?' · отключён':'');row.append(summary);
      const inner=document.createElement('div');inner.className='details-body';const info=document.createElement('p');info.className='fingerprint';info.textContent=member.fingerprint;inner.append(info);
      if(member.role!=='admin'&&member.state==='active'){
        const name=document.createElement('input');name.type='text';name.maxLength=60;name.value=member.name;name.setAttribute('aria-label','Имя врача');
        const role=document.createElement('select');role.setAttribute('aria-label','Роль врача');for(const key of ['neurologist','intensivist','cardiologist','bot']){const o=document.createElement('option');o.value=key;o.textContent=roleLabels[key];role.append(o);}role.value=member.role;
        const save=document.createElement('button');save.type='button';save.className='button button-secondary';save.textContent='Сохранить изменения';save.addEventListener('click',async()=>{if(busy||teamBusy||!canAdmin())return;teamBusy=true;updateTeamButtons();try{await directClient.update(device,{id:member.id,name:name.value.trim(),role:role.value,state:'active',approvalProof:await makeRecipientGrant(device,{...member,name:name.value.trim(),role:role.value})});say('Данные участника обновлены.');}catch(e){say(e.message,true);}finally{teamBusy=false;await refreshTeam();}});
        const revoke=document.createElement('button');revoke.type='button';revoke.className='button button-secondary danger-button';revoke.textContent='Отключить доступ';let confirmed=false;
        revoke.addEventListener('click',async()=>{if(busy||teamBusy||!canAdmin())return;if(!confirmed){confirmed=true;revoke.textContent='Подтвердить отключение';return;}teamBusy=true;updateTeamButtons();try{await directClient.update(device,{id:member.id,name:member.name,role:member.role,state:'revoked'});say('Доступ отключён. Уже просмотренное удалить с чужого телефона нельзя.');}catch(e){say(e.message,true);}finally{teamBusy=false;await refreshTeam();}});
        const certify=document.createElement('button');certify.type='button';certify.className='button button-secondary';certify.textContent='Подтвердить ключ для новых сообщений';let checked=false;certify.addEventListener('click',async()=>{if(busy||teamBusy||!canAdmin())return;if(!checked){checked=true;certify.textContent='Код сверил — подписать доступ';return;}teamBusy=true;try{await directClient.certify(device,member.id,await makeRecipientGrant(device,member));say('Ключ подписан организатором.');}catch(e){say(e.message,true);}finally{teamBusy=false;await refreshTeam();}});
        inner.append(name,role,save,certify,revoke);
      }else{const p=document.createElement('p');p.textContent=member.state==='revoked'?'Для возврата создайте новое приглашение и подтвердите телефон.':'Устройство организатора.';inner.append(p);}
      row.append(inner);$('team-members').append(row);
    }
  }catch(e){if(e.status===403||e.status===401)teamRefreshFailed(e,'Проверка доступа');const p=document.createElement('p');p.textContent=e.message;$('team-members').append(p);}
}


async function trustedDirectory(role){
  if(!organizerPin)throw new Error('Сначала подключите ключ организатора через его личное приглашение.');
  const all=await directClient.directory(device);return verifyRecipientDirectory(role?all.filter(m=>m.role===role):all.filter(m=>m.id!==organizerPin.id),organizerPin);
}
$('organizer-confirm').addEventListener('change',()=>{$('organizer-save').disabled=!$('organizer-confirm').checked;});
$('organizer-save').addEventListener('click',async()=>{
  if(busy||!invitationOrganizer||!$('organizer-confirm').checked)return;setBusy(true);
  try{organizerPin=await pinOrganizerCard(invitationOrganizer,{confirmed:true});$('organizer-trust').hidden=true;$('organizer-missing').hidden=true;say('Ключ организатора подтверждён на этом телефоне.');}
  catch(e){say(e.message,true);}finally{setBusy(false);}
});
init();
