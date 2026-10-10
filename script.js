/* CYBERGUARD - frontend only, Gemini API only. No backend needed. */
const $ = id => document.getElementById(id);
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const store = {
  get(k, d) { try { const v = localStorage.getItem(k); return v === null ? d : JSON.parse(v); } catch { return d; } },
  set(k, v) { try { localStorage.setItem(k, JSON.stringify(v)); } catch {} }
};
const NAMES = {url:'URL', image:'Image', video:'Video', email:'G.Mail', social:'Social ID', qr:'QR'};
const NETMSG = 'Network error: request Google tak nahi pahunchi. Check: 1) internet, 2) Brave Shields off karo is site ke liye, 3) adblock/VPN band karo, 4) site https:// par kholo.';
let gate = false, busy = false, framesP = null, vidMeta = '';

/* ---------- modal ---------- */
function show(html, wide) {
  $('modalBody').innerHTML = html;
  document.querySelector('.modal-box').classList.toggle('wide', !!wide);
  $('closeBtn').style.display = gate ? 'none' : '';
  $('modal').classList.add('on');
}
function closeModal() { if (gate) return; $('modal').classList.remove('on'); }
const closeTool = closeModal, closeGuidelines = closeModal, closeDashboard = closeModal;
$('modal').addEventListener('click', e => { if (e.target.id === 'modal') closeModal(); });
document.addEventListener('keydown', e => { if (e.key === 'Escape') closeModal(); });

/* ---------- API key (asked once) ---------- */
function openGate(change) {
  gate = !change;
  show(`<h2>Activate CYBERGUARD</h2>
    <p class="desc">Enter your Gemini API key once. It is checked and saved in this browser only, so you will not be asked again.</p>
    <input class="in" id="key" type="password" placeholder="AIza..." autocomplete="off">
    <div class="row"><button class="btn" id="kb" onclick="saveKey()">Activate</button>${change ? '<button class="btn g" onclick="closeModal()">Cancel</button>' : ''}</div>
    <div id="ke"></div>
    <p class="desc" style="margin-top:16px"><a href="https://aistudio.google.com/app/apikey" target="_blank" rel="noopener" style="color:#5aa0ff">Get a free Gemini API key</a></p>`);
}
async function saveKey() {
  const k = $('key').value.trim(), b = $('kb'), e = $('ke');
  if (!k) { e.innerHTML = '<div class="err">Paste your API key.</div>'; return; }
  b.disabled = true; b.textContent = 'Checking...'; e.innerHTML = '';
  try {
    const r = await fetch('https://generativelanguage.googleapis.com/v1beta/models?pageSize=1&key=' + encodeURIComponent(k));
    if (!r.ok) { const j = await r.json().catch(() => ({})); throw new Error(j.error?.message || 'Invalid API key.'); }
    store.set('cg_key', k); store.set('cg_models', null); gate = false; $('modal').classList.remove('on');
  } catch (x) {
    e.innerHTML = '<div class="err">' + esc(x instanceof TypeError ? NETMSG : x.message) + '</div>';
    b.disabled = false; b.textContent = 'Activate';
  }
}

/* ---------- Gemini ---------- */
const SCHEMA = {type:'OBJECT', properties:{
  verdict:{type:'STRING', enum:['Safe','Suspicious','Dangerous']},
  risk_score:{type:'INTEGER'},
  ai_generated_probability:{type:'INTEGER'},
  extracted:{type:'STRING'},
  summary:{type:'STRING'},
  findings:{type:'ARRAY', items:{type:'STRING'}},
  recommendations:{type:'ARRAY', items:{type:'STRING'}}
}, required:['verdict','risk_score','summary','findings','recommendations']};
const SYSTEM = 'You are CYBERGUARD, a cybersecurity threat analyst. Be precise and conservative; never invent facts you cannot verify from the input. verdict: Safe (risk 0-34), Suspicious (35-69), Dangerous (70-100). Set ai_generated_probability (0-100) only for image/video input, otherwise omit it. Set extracted only when asked to read text/QR from an image. Keep each finding under 25 words. Respond with JSON only.';

async function getModels(key) {
  const c = store.get('cg_models', null);
  if (c && c.t > Date.now() - 864e5 && c.l.length) return c.l;
  let l = [];
  try {
    const r = await fetch('https://generativelanguage.googleapis.com/v1beta/models?pageSize=200&key=' + encodeURIComponent(key));
    const j = await r.json();
    l = (j.models || []).filter(m => (m.supportedGenerationMethods || []).includes('generateContent'))
      .map(m => m.name.replace('models/', '')).map(n => ({n, m:n.match(/^gemini-(\d+(?:\.\d+)?)-flash$/)})).filter(x => x.m)
      .sort((a, b) => parseFloat(b.m[1]) - parseFloat(a.m[1])).map(x => x.n).slice(0, 3);
  } catch {}
  if (!l.length) l = ['gemini-flash-latest', 'gemini-2.5-flash'];
  store.set('cg_models', {t:Date.now(), l});
  return l;
}
async function gemini(parts) {
  const key = (store.get('cg_key', '') || '').trim();
  if (!key) { openGate(false); throw new Error('Add your Gemini API key first.'); }
  const body = JSON.stringify({
    systemInstruction:{parts:[{text:SYSTEM}]},
    contents:[{role:'user', parts}],
    generationConfig:{responseMimeType:'application/json', responseSchema:SCHEMA}
  });
  let r, j;
  for (const m of await getModels(key)) {
    try { r = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${m}:generateContent?key=${encodeURIComponent(key)}`, {method:'POST', headers:{'Content-Type':'application/json'}, body}); }
    catch { throw new Error(NETMSG); }
    j = await r.json().catch(() => ({}));
    if (r.ok) break;
    const msg = j.error?.message || '';
    if (!([404, 429, 503].includes(r.status) || /no longer available|not found/i.test(msg))) break;
    store.set('cg_models', null);
  }
  if (!r.ok) {
    const m = j.error?.message || 'Gemini request failed';
    if (r.status === 400 && /api key/i.test(m)) { store.set('cg_key', ''); }
    throw new Error(m);
  }
  if (j.promptFeedback?.blockReason) throw new Error('Gemini blocked this input (' + j.promptFeedback.blockReason + ').');
  const t = (j.candidates?.[0]?.content?.parts || []).map(p => p.text || '').join('');
  if (!t) throw new Error('Empty response from Gemini. Try again.');
  try { return JSON.parse(t.replace(/^```json|```$/g, '').trim()); } catch { throw new Error('Gemini returned an unreadable answer. Try again.'); }
}

/* ---------- tool definitions ---------- */
const TOOLS = {
  url:{t:'Enter any URL', d:'Detect suspicious URLs and phishing patterns.',
    html:`<div class="field"><input class="in" id="f_url" type="text" placeholder="https://example.com/login" autocomplete="off"></div>`},
  image:{t:'Enter any image', d:'Checks for AI generation, manipulation, deepfake traces and scam content.', file:'image/*',
    html:`<label class="drop"><input id="file" type="file" accept="image/*">📁 Tap to choose an image</label>`},
  video:{t:'Enter any video', d:'Video properties and 6 sampled frames are checked for AI generation, deepfake signs and scam content.', file:'video/*',
    html:`<label class="drop"><input id="file" type="file" accept="video/*">📁 Tap to choose a video</label>`},
  email:{t:'Enter any G.Mail', d:'Enter the sender, subject and body of the email.',
    html:`<div class="field"><label>Sender address</label><input class="in" id="f_from" placeholder="support@g00gle-mail.com" autocomplete="off"></div>
          <div class="field"><label>Subject</label><input class="in" id="f_sub" placeholder="Urgent: verify your account" autocomplete="off"></div>
          <div class="field"><label>Email body</label><textarea class="in" id="f_body" placeholder="Paste the email text here"></textarea></div>`},
  social:{t:'Enter any social media ID', d:'Check usernames for impersonation patterns.',
    html:`<div class="field"><label>Platform</label><select class="in" id="f_plat"><option>Instagram</option><option>X (Twitter)</option><option>Facebook</option><option>YouTube</option><option>Telegram</option><option>WhatsApp</option><option>LinkedIn</option><option>Other</option></select></div>
          <div class="field"><label>Username</label><input class="in" id="f_user" placeholder="@virat.kohIi" autocomplete="off"></div>
          <div class="field"><label>Brand or person it might be copying (optional)</label><input class="in" id="f_real" placeholder="virat.kohli" autocomplete="off"></div>`},
  qr:{t:'Enter any QR', d:'Upload a QR image. It is decoded and its contents inspected.', file:'image/*',
    html:`<label class="drop"><input id="file" type="file" accept="image/*">📁 Tap to choose a QR image</label>`}
};

function openTool(k) {
  const T = TOOLS[k]; framesP = null; vidMeta = '';
  if (!store.get('cg_key', '')) { openGate(false); return; }
  show(`<h2>${T.t}</h2><p class="desc">${T.d}</p>${T.html}<div id="pv"></div>
    <div class="row"><button class="btn" id="go" onclick="run('${k}')">Analyze</button><button class="btn g" onclick="closeModal()">Close</button></div><div id="out"></div>`);
  if (T.file) $('file').addEventListener('change', () => preview(k));
}

/* ---------- file helpers ---------- */
const toB64 = f => new Promise((res, rej) => { const r = new FileReader(); r.onload = () => res(r.result.split(',')[1]); r.onerror = rej; r.readAsDataURL(f); });
const loadImg = f => new Promise((res, rej) => { const i = new Image(); i.onload = () => res(i); i.onerror = rej; i.src = URL.createObjectURL(f); });

async function imagePart(f) {
  if (f.size <= 3e6 && /^image\/(jpeg|png|webp)$/.test(f.type)) return {inline_data:{mime_type:f.type, data:await toB64(f)}};
  const im = await loadImg(f), sc = Math.min(1, 2000 / Math.max(im.naturalWidth, im.naturalHeight));
  const c = document.createElement('canvas'); c.width = im.naturalWidth * sc; c.height = im.naturalHeight * sc;
  c.getContext('2d').drawImage(im, 0, 0, c.width, c.height);
  return {inline_data:{mime_type:'image/jpeg', data:c.toDataURL('image/jpeg', .9).split(',')[1]}};
}

function grabFrames(url) {
  return new Promise((res, rej) => {
    const v = document.createElement('video'); v.muted = true; v.playsInline = true; v.preload = 'auto'; v.src = url;
    v.onerror = () => rej(new Error('This video format cannot be read by the browser. Try an MP4 or WebM file.'));
    v.onloadedmetadata = async () => {
      if (!isFinite(v.duration) || !v.videoWidth) return rej(new Error('Could not read video details.'));
      vidMeta = `duration ${v.duration.toFixed(1)}s, resolution ${v.videoWidth}x${v.videoHeight}`;
      const N = 6, out = [], c = document.createElement('canvas'), sc = Math.min(1, 800 / v.videoWidth);
      c.width = v.videoWidth * sc; c.height = v.videoHeight * sc;
      const x = c.getContext('2d');
      try {
        for (let i = 0; i < N; i++) {
          const t = Math.max(0, Math.min(v.duration - .1, v.duration * (i + .5) / N));
          await new Promise(r => { const to = setTimeout(r, 8000); v.onseeked = () => { clearTimeout(to); r(); }; v.currentTime = t; });
          x.drawImage(v, 0, 0, c.width, c.height);
          out.push({t:t.toFixed(1), url:c.toDataURL('image/jpeg', .8)});
        }
        res(out);
      } catch (e) { rej(e); }
    };
  });
}

function preview(k) {
  const f = $('file').files[0]; if (!f) return;
  const u = URL.createObjectURL(f); $('out').innerHTML = '';
  if (k === 'video') {
    $('pv').innerHTML = `<video class="prev" src="${u}" controls muted playsinline></video><div class="frames" id="fr"></div>`;
    framesP = grabFrames(u);
    framesP.then(fs => { $('fr').innerHTML = fs.map(s => `<img src="${s.url}" title="${s.t}s">`).join(''); }).catch(e => { $('out').innerHTML = `<div class="err">${esc(e.message)}</div>`; });
  } else $('pv').innerHTML = `<img class="prev" src="${u}" alt="preview">`;
}

/* ---------- QR decode ---------- */
async function decodeQR(f) {
  if (!window.jsQR) return null;
  const im = await loadImg(f);
  for (const max of [1200, 800, 500, 1800]) {
    const sc = Math.min(1, max / Math.max(im.naturalWidth, im.naturalHeight));
    const c = document.createElement('canvas'); c.width = Math.round(im.naturalWidth * sc); c.height = Math.round(im.naturalHeight * sc);
    const x = c.getContext('2d', {willReadFrequently:true}); x.drawImage(im, 0, 0, c.width, c.height);
    const q = jsQR(x.getImageData(0, 0, c.width, c.height).data, c.width, c.height, {inversionAttempts:'attemptBoth'});
    if (q && q.data) return q.data;
  }
  return null;
}

/* ---------- prompts + run ---------- */
async function buildRequest(k) {
  if (k === 'url') {
    const v = $('f_url').value.trim(); if (!v) throw new Error('Enter a URL.');
    return {label:v, parts:[{text:`Analyze this URL for phishing, malware, typosquatting, URL shorteners, suspicious TLDs, deceptive subdomains, homograph tricks and brand impersonation. Do not assume you can visit it; judge from its structure and your knowledge.\nURL: ${v}`}]};
  }
  if (k === 'email') {
    const a = $('f_from').value.trim(), s = $('f_sub').value.trim(), b = $('f_body').value.trim();
    if (!a && !s && !b) throw new Error('Enter the email details.');
    return {label:(s || a || b).slice(0, 70), parts:[{text:`Analyze this email for phishing: spoofed or lookalike sender, urgency, credential or payment requests, suspicious links, attachments, grammar, mismatched branding.\nFrom: ${a}\nSubject: ${s}\n\n${b}`}]};
  }
  if (k === 'social') {
    const p = $('f_plat').value, u = $('f_user').value.trim(), r = $('f_real').value.trim();
    if (!u) throw new Error('Enter a username.');
    return {label:`${p} ${u}`, parts:[{text:`Check this social media username for impersonation or scam patterns: lookalike characters (I/l, 0/O, rn/m), added words like official/support/real/giveaway, brand or celebrity mimicry, underscores or digits padding, scam-style naming.\nPlatform: ${p}\nUsername: ${u}\n${r ? 'Possibly imitating: ' + r : ''}\nYou cannot see the live profile, so say clearly that this is a username-pattern analysis only.`}]};
  }
  const f = $('file')?.files[0]; if (!f) throw new Error('Choose a file first.');
  if (k === 'image') {
    if (f.size > 20e6) throw new Error('Image is too large. Use one under 20 MB.');
    return {label:f.name, parts:[{text:'Inspect this image. Judge whether it is AI-generated (diffusion/GAN artifacts, odd hands, garbled text, texture, lighting, symmetry), edited or manipulated, a deepfake, or contains scam, phishing, fake-document or fake-payment content. Give ai_generated_probability 0-100 and explain the visual evidence.'}, await imagePart(f)]};
  }
  if (k === 'video') {
    if (!framesP) throw new Error('Choose a video first.');
    const fs = await framesP;
    const parts = [{text:`These ${fs.length} frames were sampled in time order from one video. Properties: ${vidMeta}, size ${(f.size / 1e6).toFixed(1)} MB, type ${f.type}. Judge whether the video is AI-generated or a deepfake (temporal inconsistency, face warping, lip or eye artifacts, texture flicker, unnatural motion or lighting) and whether it shows scam content. Give ai_generated_probability 0-100. Note that only still frames were checked, not audio.`}];
    fs.forEach(s => { parts.push({text:`Frame at ${s.t}s:`}); parts.push({inline_data:{mime_type:'image/jpeg', data:s.url.split(',')[1]}}); });
    return {label:f.name, parts};
  }
  if (k === 'qr') {
    const data = await decodeQR(f);
    if (data) return {label:data.slice(0, 70), extracted:data, parts:[{text:`This content was decoded from a QR code. Analyze it for quishing, malicious or deceptive URLs, payment/UPI scams, fake login pages, Wi-Fi or contact-card tricks.\n\nContent: ${data}`}]};
    return {label:f.name, parts:[{text:'Read the QR code in this image and put its exact decoded content in "extracted". If it is not readable, say so in summary and set extracted to an empty string. Then analyze the content for quishing, malicious URLs, payment scams or tampering (for example a QR sticker pasted over another one).'}, await imagePart(f)]};
  }
}

async function run(k) {
  if (busy) return;
  const out = $('out'), go = $('go'); out.innerHTML = '';
  try {
    const req = await buildRequest(k);
    busy = true; go.disabled = true; go.innerHTML = '<span class="spin"></span>Analyzing';
    const r = await gemini(req.parts);
    if (req.extracted) r.extracted = req.extracted;
    out.innerHTML = render(r, k);
    const h = store.get('cg_hist', []);
    h.unshift({k, label:req.label, v:r.verdict, s:r.risk_score, t:Date.now()});
    store.set('cg_hist', h.slice(0, 200));
  } catch (e) { out.innerHTML = `<div class="err">${esc(e.message)}</div>`; }
  busy = false; go.disabled = false; go.textContent = 'Analyze';
}

const cls = v => v === 'Safe' ? 'safe' : v === 'Dangerous' ? 'danger' : 'warning';
function render(r, k) {
  const sc = Math.max(0, Math.min(100, +r.risk_score || 0)), li = a => (a || []).map(x => `<li>${esc(x)}</li>`).join('');
  const ai = (k === 'image' || k === 'video') && r.ai_generated_probability != null ? `<p><b>AI-generated probability:</b> ${r.ai_generated_probability}%</p>` : '';
  const ex = r.extracted ? `<p><b>Decoded content:</b> ${esc(r.extracted)}</p>` : '';
  return `<div class="result-box ${cls(r.verdict)}">
    <div class="risk-header"><div><span class="result-label">VERDICT</span><h3>${esc(r.verdict)}</h3></div><div class="risk-score">${sc}<small>/100</small></div></div>
    <div class="score-bar"><div class="score-fill" style="width:${sc}%"></div></div>
    <div class="analysis-details">${ex}${ai}<p>${esc(r.summary)}</p></div>
    <div class="warnings"><h4>Findings</h4><ul class="warning-list">${li(r.findings)}</ul></div>
    <div class="recommendation"><h4>What to do</h4><ul>${li(r.recommendations)}</ul></div></div>`;
}

/* ---------- guidelines + dashboard ---------- */
function openGuidelines() {
  show(`<h2>CyberGuard Guidelines</h2><p class="desc">CyberGuard helps identify suspicious digital content using Google Gemini.</p>
    <ul><li>Do not enter real passwords, OTPs or card details.</li><li>Use test data whenever possible.</li>
    <li>A risk score is an indicator, not a guaranteed verdict. AI-generated detection is an estimate.</li>
    <li>Images and video frames are sent to Google Gemini for analysis. Your API key stays in this browser.</li>
    <li>Always verify suspicious content through trusted sources.</li></ul>
    <div class="row"><button class="btn g" onclick="openGate(true)">Change API key</button><button class="btn g" onclick="closeModal()">Close</button></div>`);
}
function openDashboard() {
  const h = store.get('cg_hist', []), n = v => h.filter(x => x.v === v).length;
  const bars = Object.keys(NAMES).map(k => { const c = h.filter(x => x.k === k).length; return `<div><span>${NAMES[k]}</span><i style="width:${h.length ? Math.max(c / h.length * 100, c ? 4 : 0) : 0}%"></i> ${c}</div>`; }).join('');
  const list = h.length ? h.slice(0, 40).map(x => `<div class="hist"><div>${NAMES[x.k]}<small>${esc(x.label)}</small></div><div style="text-align:right"><span class="tag ${cls(x.v)}">${x.v}</span><small>${x.s}/100 · ${new Date(x.t).toLocaleString()}</small></div></div>`).join('')
    : '<p class="desc">No scans yet. Pick a tool to run your first scan.</p>';
  show(`<h2>📊 CyberGuard Command Dashboard</h2><p class="desc">Security analysis overview. History is stored on this device only.</p>
    <div class="stats"><div class="stat"><b>${h.length}</b><span>Total</span></div><div class="stat"><b style="color:#5ff0b0">${n('Safe')}</b><span>Safe</span></div><div class="stat"><b style="color:#ffd062">${n('Suspicious')}</b><span>Suspicious</span></div><div class="stat"><b style="color:#ff7b86">${n('Dangerous')}</b><span>Dangerous</span></div></div>
    <div class="bars">${bars}</div><div style="margin-top:14px">${list}</div>
    <div class="row"><button class="btn g" onclick="closeModal()">Close</button>${h.length ? `<button class="btn g" onclick="store.set('cg_hist',[]);openDashboard()">Clear history</button>` : ''}</div>`, true);
}

if (!store.get('cg_key', '')) openGate(false);
