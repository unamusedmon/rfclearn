
const progress = document.querySelector('.progress');
const body = document.querySelector('.doc-body');
const toc = document.querySelector('#toc-links');
const focusBtn = document.querySelector('[data-action="focus"]');
const comfyBtn = document.querySelector('[data-action="comfy"]');
const topBtn = document.querySelector('[data-action="top"]');
const headerPanel = document.querySelector('.header-reference-panel');

const rfcMatch = document.querySelector('.eyebrow')?.textContent.match(/RFC (\d+)/);
const rfcNumber = rfcMatch ? rfcMatch[1] : null;

// FSRS Study Mode
const studyOverlay = document.querySelector('#study-overlay');
const studyRfcBtn = document.querySelector('#study-rfc');
const studyBadge = document.querySelector('#study-badge');
const closeStudyBtn = document.querySelector('#close-study');
const cardContainer = document.querySelector('#card-container');
const studyActions = document.querySelector('#study-actions');
const studySummary = document.querySelector('#study-summary');
const progressBar = document.querySelector('#study-progress-bar');

let currentSession = [];
let sessionIdx = 0;
let sessionStats = { reviewed: 0, mastered: 0, dueTomorrow: 0 };

const w = [0.4, 0.6, 2.4, 5.8, 4.93, 0.94, 0.86, 0.01, 1.49, 0.14, 0.94, 2.18, 0.05, 0.34, 1.26, 0.29, 2.61];

function getSRSData() {
  return JSON.parse(localStorage.getItem('rfc_srs_state_fsrs') || '{}');
}

function saveSRSData(state) {
  localStorage.setItem('rfc_srs_state_fsrs', JSON.stringify(state));
  updateDueBadge();
}

function getRetrievability(state, now) {
  if (!state || !state.last_date) return 0;
  const t = Math.max(0, (now - state.last_date) / (24 * 60 * 60 * 1000));
  return Math.pow(1 + t / (9 * state.S), -1);
}

function fsrs_update(grade, state, now) {
  let { S, D, last_date, repetitions } = state || { S: 0, D: 0, last_date: 0, repetitions: 0 };
  if (repetitions === 0) {
    S = w[grade - 1]; D = w[4] - (grade - 3) * w[5];
  } else {
    D = Math.min(Math.max(D - w[6] * (grade - 3), 1), 10);
    const R = getRetrievability(state, now);
    if (grade === 1) { S = w[7] * Math.exp(-w[8] * D) * (Math.pow(S + 1, w[9]) - 1) * Math.exp(w[10] * (1 - R)); }
    else { S = S * (1 + Math.exp(w[11]) * (11 - D) * Math.pow(S, -w[12]) * (Math.exp(w[13] * (1 - R)) - 1)); }
  }
  repetitions++;
  return { S, D, last_date: now, repetitions };
}

function updateDueBadge() {
  if (!studyBadge || !rfcNumber) return;
  const srs = getSRSData(); const now = Date.now();
  const due = (window.FLASHCARDS || []).filter(c => {
    if (c.rfc !== rfcNumber) return false;
    const state = srs[c.id]; if (!state) return true;
    return getRetrievability(state, now) <= 0.9;
  });
  studyBadge.textContent = due.length || '';
  studyBadge.style.display = due.length ? 'inline-block' : 'none';
}

function initStudySession(all = false) {
  const srs = getSRSData(); const now = Date.now();
  currentSession = (window.FLASHCARDS || []).filter(c => {
    if (c.rfc !== rfcNumber) return false;
    if (all) return true;
    const state = srs[c.id]; if (!state) return true;
    return getRetrievability(state, now) <= 0.9;
  });
  if (currentSession.length === 0 && !all) {
    alert("No cards due for this RFC! Click again to study all cards for this RFC.");
    studyRfcBtn.onclick = () => initStudySession(true);
    return;
  }
  currentSession.sort(() => Math.random() - 0.5);
  sessionIdx = 0; sessionStats = { reviewed: 0, mastered: 0, dueTomorrow: 0 };
  studyOverlay.classList.add('active'); studySummary.classList.remove('active');
  cardContainer.style.display = 'block'; showCard();
}

function showCard() {
  if (sessionIdx >= currentSession.length) { showSummary(); return; }
  const card = currentSession[sessionIdx]; const state = getSRSData()[card.id];
  const R = state ? Math.round(getRetrievability(state, Date.now()) * 100) : 0;
  cardContainer.classList.remove('flipped'); studyActions.classList.remove('visible');
  document.querySelector('#card-category').textContent = card.category;
  document.querySelector('#card-category-back').textContent = card.category;
  document.querySelector('#card-prompt').textContent = card.prompt;
  document.querySelector('#card-answer').textContent = card.answer;
  document.querySelector('#card-meta').textContent = state ? `S: ${state.S.toFixed(1)} | D: ${state.D.toFixed(1)} | R: ${R}%` : 'New Card';
  document.querySelector('#study-count').textContent = `Card ${sessionIdx + 1} of ${currentSession.length}`;
  progressBar.style.width = `${(sessionIdx / currentSession.length) * 100}%`;
}

function showSummary() {
  cardContainer.style.display = 'none'; studyActions.classList.remove('visible'); studySummary.classList.add('active');
  progressBar.style.width = '100%';
  document.querySelector('#sum-reviewed').textContent = sessionStats.reviewed;
  document.querySelector('#sum-mastered').textContent = sessionStats.mastered;
  const srs = getSRSData(); const tomorrow = Date.now() + 24*60*60*1000;
  const dueTomorrow = Object.values(srs).filter(s => getRetrievability(s, tomorrow) <= 0.9).length;
  document.querySelector('#sum-due').textContent = dueTomorrow;
}

function handleAnswer(grade) {
  const card = currentSession[sessionIdx]; const srs = getSRSData();
  const newState = fsrs_update(grade, srs[card.id], Date.now());
  srs[card.id] = newState; saveSRSData(srs);
  sessionStats.reviewed++; if (newState.S > 30) sessionStats.mastered++;
  sessionIdx++; showCard();
}

if (cardContainer) {
    cardContainer.addEventListener('click', () => {
      if (!cardContainer.classList.contains('flipped')) { cardContainer.classList.add('flipped'); studyActions.classList.add('visible'); }
    });
}

document.querySelectorAll('.srs-btn').forEach(btn => {
  btn.addEventListener('click', (e) => {
    e.stopPropagation();
    handleAnswer(parseInt(btn.dataset.quality));
  });
});

if (closeStudyBtn) closeStudyBtn.addEventListener('click', () => studyOverlay.classList.remove('active'));
document.querySelector('#finish-study').addEventListener('click', () => studyOverlay.classList.remove('active'));
document.querySelector('#restart-study').addEventListener('click', () => initStudySession());
if (studyRfcBtn) studyRfcBtn.addEventListener('click', () => initStudySession(false));

const resetSrsBtn = document.querySelector("#reset-srs");
if (resetSrsBtn) resetSrsBtn.addEventListener("click", () => { if(confirm("Wipe all FSRS progress?")) { localStorage.removeItem("rfc_srs_state_fsrs"); location.reload(); } });

window.addEventListener('keydown', (e) => {
  if (!studyOverlay || !studyOverlay.classList.contains('active')) return;
  if (e.key === 'Escape') studyOverlay.classList.remove('active');
  if (e.key === ' ') { if (!cardContainer.classList.contains('flipped')) cardContainer.click(); }
  if (cardContainer.classList.contains('flipped')) {
    if (e.key === '1') handleAnswer(1); if (e.key === '2') handleAnswer(2); if (e.key === '3') handleAnswer(3); if (e.key === '4') handleAnswer(4);
  }
});

// Relationship Map Logic (minimal to avoid issues)
const mapOverlay = document.querySelector('#map-overlay');
const openMapBtn = document.querySelector('#open-map');
const closeMapBtn = document.querySelector('#close-map');
const mapContainer = document.querySelector('#map-container');

function updateProgress() {
  const max = document.documentElement.scrollHeight - innerHeight;
  progress.style.width = max > 0 ? `${(scrollY / max) * 100}%` : '0%';
}

function makeToc() {
  let headingNodes = [...document.querySelectorAll('h1, h2, h3, .doc-body span > a[href^="#section-"], .threat-item')].slice(0, 100);
  if (!headingNodes.length) {
    toc.innerHTML = '<p class="muted">This RFC source is mostly preformatted text, so use browser find for section jumps.</p>';
    return [];
  }
  headingNodes = headingNodes.filter(el => !el.closest('.doc-hero'));
  const headings = headingNodes.map(el => {
    if (el.tagName === 'A' && el.parentElement && el.parentElement.tagName === 'SPAN') return el.parentElement;
    return el;
  });
  toc.innerHTML = '';
  headings.forEach((heading, index) => {
    if (heading.classList.contains('threat-item')) return;
    if (!heading.id) { heading.id = `section-${index + 1}`; }
    const id = heading.id;
    const link = document.createElement('a');
    link.href = `#${id}`;
    link.textContent = heading.textContent.replace('Note', '').trim().slice(0, 96) || `Section ${index + 1}`;
    toc.appendChild(link);
  });
  return headings;
}

function initActiveToc(headings) {
  if (!headings || !headings.length || !('IntersectionObserver' in window)) return;
  const links = new Map([...toc.querySelectorAll('a[href^="#"]')].map(a => [decodeURIComponent(a.hash.slice(1)), a]));
  const setActive = (id) => {
    links.forEach(link => link.classList.toggle('active', link.getAttribute('href') === `#${id}`));
  };
  const observer = new IntersectionObserver((entries) => {
    const visible = entries.filter(entry => entry.isIntersecting).sort((a, b) => b.intersectionRatio - a.intersectionRatio)[0];
    if (visible?.target?.id) setActive(visible.target.id);
  }, { rootMargin: '-18% 0px -70% 0px', threshold: [0, .25, .5, 1] });
  headings.forEach(heading => heading.id && observer.observe(heading));
}

function initAnnotations(headings) {
  if (!rfcNumber || !headings || !headings.length) return;
  const allNotes = JSON.parse(localStorage.getItem('rfc_notes') || '{}');
  const rfcNotes = allNotes[rfcNumber] || {};
  headings.forEach((heading) => {
    const sectionId = heading.id;
    const isThreatItem = heading.classList.contains('threat-item');
    const existingNote = rfcNotes[sectionId]?.content || '';
    const toggle = document.createElement('button');
    toggle.className = 'anno-toggle';
    toggle.textContent = 'Note';
    toggle.title = 'Toggle annotation';
    if (isThreatItem) { heading.querySelector('.threat-header').appendChild(toggle); }
    else { heading.appendChild(toggle); }
    const indicator = document.createElement('span');
    indicator.className = 'anno-indicator';
    indicator.style.display = existingNote ? 'inline-block' : 'none';
    if (isThreatItem) { heading.querySelector('.threat-header').appendChild(indicator); }
    else { heading.appendChild(indicator); }
    const wrap = document.createElement('div');
    wrap.className = 'anno-editor-wrap';
    if (existingNote) { toggle.classList.add('active'); }
    const editor = document.createElement('textarea');
    editor.className = 'anno-editor';
    editor.placeholder = 'Add your notes for this ' + (isThreatItem ? 'indicator' : 'section') + '...';
    editor.value = existingNote;
    const status = document.createElement('div');
    status.className = 'anno-status';
    status.textContent = 'Saved';
    wrap.appendChild(editor);
    wrap.appendChild(status);
    if (isThreatItem) { heading.appendChild(wrap); }
    else { heading.insertAdjacentElement('afterend', wrap); }
    toggle.addEventListener('click', (e) => {
      e.preventDefault(); e.stopPropagation();
      const isVisible = wrap.classList.toggle('visible');
      toggle.classList.toggle('active', isVisible || editor.value.trim() !== '');
      if (isVisible) editor.focus();
    });
    editor.addEventListener('blur', () => {
      const content = editor.value.trim();
      const allNotes = JSON.parse(localStorage.getItem('rfc_notes') || '{}');
      if (!allNotes[rfcNumber]) allNotes[rfcNumber] = {};
      if (content) {
        let title = '';
        if (isThreatItem) { title = 'Threat: ' + heading.querySelector('.threat-name').textContent; }
        else { title = heading.textContent.replace('Note', '').trim(); }
        allNotes[rfcNumber][sectionId] = {
          content: content, title: title,
          rfcTitle: document.title.split(':')[1]?.trim() || `RFC ${rfcNumber}`,
          timestamp: Date.now(), type: isThreatItem ? 'threat' : 'section'
        };
        indicator.style.display = 'inline-block';
        toggle.classList.add('active');
      } else {
        delete allNotes[rfcNumber][sectionId];
        if (Object.keys(allNotes[rfcNumber]).length === 0) { delete allNotes[rfcNumber]; }
        indicator.style.display = 'none';
        toggle.classList.remove('active');
      }
      localStorage.setItem('rfc_notes', JSON.stringify(allNotes));
      status.classList.add('visible');
      setTimeout(() => status.classList.remove('visible'), 2000);
    });
  });
}

function setHeaderPanelDefault() {
  if (!headerPanel) return;
  headerPanel.open = !matchMedia('(max-width: 780px)').matches;
}

addEventListener('scroll', updateProgress, { passive: true });
if (focusBtn) focusBtn.addEventListener('click', () => body.classList.toggle('focus'));
if (comfyBtn) comfyBtn.addEventListener('click', () => body.classList.toggle('comfy'));
if (topBtn) topBtn.addEventListener('click', () => scrollTo({ top: 0, behavior: 'smooth' }));
setHeaderPanelDefault();
const headings = makeToc();
initActiveToc(headings);
initAnnotations(headings);
updateProgress();
updateDueBadge();
