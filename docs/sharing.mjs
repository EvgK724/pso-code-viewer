// Presentation only: keys, fingerprints and encrypted payloads are never shortened.
const CARD = /^PSO-CARD1\.[A-Za-z0-9_-]+$/;
const MAX_INPUT = 5000;

function appURL(base) {
  const url = new URL('./', base);
  if (url.protocol !== 'https:' || url.username || url.password) throw new Error('Нужна HTTPS-ссылка просмотрщика.');
  return url;
}

function checkedLink(input, base) {
  const value = String(input).trim();
  if (value.length > MAX_INPUT) throw new Error('Ссылка слишком длинная. Скопируйте только ссылку без комментария.');
  const expected = appURL(base);
  let url;
  try { url = new URL(value); } catch { throw new Error('Вставьте карточку или полную ссылку просмотрщика.'); }
  if (url.origin !== expected.origin || url.username || url.password || url.search ||
      ![expected.pathname, expected.pathname + 'index.html'].includes(url.pathname)) {
    throw new Error('Эта ссылка не относится к данному просмотрщику.');
  }
  return url;
}

export function cardLinkFor(card, base) {
  const value = String(card).trim();
  if (!CARD.test(value) || value.length > MAX_INPUT) throw new Error('Неверный формат карточки врача.');
  const url = appURL(base);
  url.hash = 'card=' + value;
  if (url.href.length > MAX_INPUT) throw new Error('Карточка слишком длинная для ссылки.');
  return url.href;
}

export function cardFromInput(input, base) {
  const value = String(input).trim();
  if (value.length > MAX_INPUT) throw new Error('Карточка слишком длинная.');
  if (CARD.test(value)) return value;
  const url = checkedLink(value, base);
  if (!url.hash.startsWith('#card=') || !CARD.test(url.hash.slice(6))) throw new Error('В ссылке нет карточки врача.');
  return url.hash.slice(6);
}

function escapeHTML(value) {
  return String(value).replace(/[&<>"']/g, char => ({'&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;'}[char]));
}

export function compactLinkContents(input, label, base) {
  const url = checkedLink(input, base);
  if (url.hash.startsWith('#card=')) cardFromInput(url.href, base);
  else if (!/^#pso=(?:PSO1|PSO-DEMO1)\.[A-Za-z0-9_.-]+$/.test(url.hash) && !/^#r=[A-Za-z0-9_-]{21}[AQgw]$/.test(url.hash)) throw new Error('Неизвестный формат ссылки.');
  // Plain-text editors receive the full working link, never a label without its target.
  return {plain:url.href, html:'<a href="' + escapeHTML(url.href) + '">' + escapeHTML(label) + '</a>'};
}

// Copy the rendered anchor using the platform's own rich selection formats.
// Some native editors handle this differently from ClipboardItem HTML. A true
// result confirms copying, not that the receiving app preserves the hyperlink.
export function copyRenderedLink(anchor, doc = globalThis.document, selection = globalThis.getSelection?.()) {
  if (!anchor || !selection || !doc?.createRange || !doc?.execCommand) return false;
  const ranges = [], active = doc.activeElement;
  try {
    for (let i = 0; i < selection.rangeCount; i++) ranges.push(selection.getRangeAt(i).cloneRange());
    const range = doc.createRange();
    range.selectNode(anchor);
    selection.removeAllRanges(); selection.addRange(range);
    return doc.execCommand('copy') === true;
  } catch { return false; }
  finally {
    try {
      selection.removeAllRanges();
      for (const range of ranges) selection.addRange(range);
      active?.focus?.({preventScroll:true});
    } catch { /* Copying must not fail because a prior selection disappeared. */ }
  }
}
