const $ = id => document.getElementById(id);

const COPY = {
  safe: ['Looks safe', 'No common phishing signs found in this address.'],
  suspicious: ['Be careful', 'Some things about this page look off. Do not enter passwords or card details unless you are sure.'],
  dangerous: ['Likely phishing', 'This page matches several phishing patterns. Leave it and do not sign in.'],
  skip: ["Can't check this page", 'PhishGuard only checks http and https websites.']
};

// Runs inside the open page (injected), so it must not use outside variables.
function collectPageSignals() {
  const forms = Array.from(document.forms);
  const formHosts = [];
  forms.forEach(f => {
    try { formHosts.push(new URL(f.action || location.href, location.href).hostname); } catch (e) {}
  });
  const hiddenIframes = Array.from(document.querySelectorAll('iframe'))
    .filter(i => i.offsetWidth < 2 || i.offsetHeight < 2).length;
  return {
    passwordFields: document.querySelectorAll('input[type=password]').length,
    formHosts,
    hiddenIframes
  };
}

function render(result) {
  const [title, summary] = COPY[result.verdict];
  $('head').dataset.verdict = result.verdict;
  $('host').textContent = result.host || 'This page';
  $('title').textContent = title;
  $('summary').textContent = summary;

  const hasScore = result.verdict !== 'skip';
  $('meter').hidden = !hasScore;
  $('score').hidden = !hasScore;
  $('marker').style.left = Math.min(result.score, 100) + '%';
  $('score').textContent = 'Risk score ' + result.score + ' out of 100';

  // textContent only: URLs are attacker-controlled, never put them in innerHTML.
  const list = $('reasons');
  list.replaceChildren();
  if (!result.reasons.length) {
    const li = document.createElement('li');
    li.className = 'none';
    li.textContent = hasScore ? 'Nothing unusual in the address or page.' : 'Nothing to check here.';
    list.appendChild(li);
  }
  result.reasons.forEach(r => {
    const li = document.createElement('li');
    const text = document.createElement('span');
    const pts = document.createElement('span');
    text.textContent = r.text;
    pts.className = 'pts';
    pts.textContent = '+' + r.points;
    li.append(text, pts);
    list.appendChild(li);
  });
}

async function scanActiveTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab || !tab.url) return render(PhishCheck.analyze(''));
  let signals = null;
  try {
    const [res] = await chrome.scripting.executeScript({ target: { tabId: tab.id }, func: collectPageSignals });
    signals = res && res.result;
  } catch (e) { /* restricted page: fall back to URL-only checks */ }
  render(PhishCheck.analyze(tab.url, signals));
}

$('check').addEventListener('click', () => {
  let value = $('url').value.trim();
  if (!value) return;
  if (!/^[a-z]+:\/\//i.test(value)) value = 'http://' + value;
  render(PhishCheck.analyze(value));
});
$('url').addEventListener('keydown', e => { if (e.key === 'Enter') $('check').click(); });

scanActiveTab();
