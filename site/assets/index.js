
const q = document.querySelector('#q');
const cards = [...document.querySelectorAll('.card')];
const empty = document.querySelector('.empty');
const count = document.querySelector('#count');
const filters = [...document.querySelectorAll('.filter')];
const densityToggleBtn = document.querySelector('#density-toggle');
const viewNotesBtn = document.querySelector('#view-notes');
const backToGridBtn = document.querySelector('#back-to-grid');
const notesView = document.querySelector('#notes-view');
const mainGrid = document.querySelector('main');
const notesContainer = document.querySelector('#notes-container');
const exportBtn = document.querySelector('#export-notes');
const importBtn = document.querySelector('#import-notes-btn');
const importFile = document.querySelector('#import-notes-file');
const noteFilterBtns = [...document.querySelectorAll('.notes-filter-btn')];
const toolbar = document.querySelector('.toolbar');
const studyPathBtns = [...document.querySelectorAll('.study-path-btn')];
const clearStudyPathBtn = document.querySelector('#clear-study-path');
const activeStudyPathEl = document.querySelector('#active-study-path');
const ifThenCueInput = document.querySelector('#if-then-cue');
const ifThenActionInput = document.querySelector('#if-then-action');
const ifThenPreview = document.querySelector('#if-then-preview');
const ifThenStatus = document.querySelector('#if-then-status');
const saveIfThenBtn = document.querySelector('#save-if-then');
const clearIfThenBtn = document.querySelector('#clear-if-then');
const emptyDefaultText = empty?.textContent || '';

function readJSON(key, fallback = {}) {
  try { return JSON.parse(localStorage.getItem(key) || JSON.stringify(fallback)); }
  catch (err) { return fallback; }
}

function writeJSON(key, value) {
  try { localStorage.setItem(key, JSON.stringify(value)); }
  catch (err) { console.warn(`Could not save ${key}`, err); }
}

function setOverlayOpen(overlay, open) {
  if (!overlay) return;
  overlay.classList.toggle('active', open);
  overlay.setAttribute('aria-hidden', String(!open));
}

// FSRS Study Mode
const studyOverlay = document.querySelector('#study-overlay');
const startStudyBtn = document.querySelector('#start-study');
const studyAllBtn = document.querySelector('#study-all');
const closeStudyBtn = document.querySelector('#close-study');
const cardContainer = document.querySelector('#card-container');
const studyActions = document.querySelector('#study-actions');
const studySummary = document.querySelector('#study-summary');
const progressBar = document.querySelector('#study-progress-bar');
const srsDueBadge = document.querySelector('#srs-due-count');

let activeTag = 'all';
let activeNoteFilter = 'all';
let activeStudyPath = '';
let activeStudyRfcSet = null;

let savedDensity = 'comfortable';
try { savedDensity = localStorage.getItem('rfc_card_density') || 'comfortable'; }
catch (err) { savedDensity = 'comfortable'; }
document.body.classList.toggle('card-compact', savedDensity === 'compact');
if (densityToggleBtn) densityToggleBtn.textContent = savedDensity === 'compact' ? 'Comfort cards' : 'Compact cards';
let currentSession = [];
let sessionIdx = 0;
let sessionStats = { reviewed: 0, mastered: 0, dueTomorrow: 0 };

const w = [0.4, 0.6, 2.4, 5.8, 4.93, 0.94, 0.86, 0.01, 1.49, 0.14, 0.94, 2.18, 0.05, 0.34, 1.26, 0.29, 2.61];

function getSRSData() {
  return readJSON('rfc_srs_state_fsrs');
}

function saveSRSData(state) {
  writeJSON('rfc_srs_state_fsrs', state);
  updateDueCounts();
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

function updateDueCounts() {
  const srs = getSRSData(); const now = Date.now();
  const due = (window.FLASHCARDS || []).filter(c => {
    const state = srs[c.id]; if (!state) return true;
    return getRetrievability(state, now) <= 0.9;
  });
  if (srsDueBadge) srsDueBadge.textContent = due.length;
}

function initStudySession(all = false) {
  const srs = getSRSData(); const now = Date.now();
  currentSession = (window.FLASHCARDS || []).filter(c => {
    if (all) return true;
    const state = srs[c.id]; if (!state) return true;
    return getRetrievability(state, now) <= 0.9;
  });
  if (currentSession.length === 0 && !all) { alert("No cards due! Use 'Study All' to practice anyway."); return; }
  currentSession.sort(() => Math.random() - 0.5);
  sessionIdx = 0; sessionStats = { reviewed: 0, mastered: 0, dueTomorrow: 0 };
  setOverlayOpen(studyOverlay, true); studySummary.classList.remove('active');
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
  btn.addEventListener('click', (e) => { e.stopPropagation(); handleAnswer(parseInt(btn.dataset.quality)); });
});

if (closeStudyBtn) closeStudyBtn.addEventListener('click', () => setOverlayOpen(studyOverlay, false));
document.querySelector('#finish-study')?.addEventListener('click', () => setOverlayOpen(studyOverlay, false));
document.querySelector('#restart-study').addEventListener('click', () => initStudySession());
if (startStudyBtn) startStudyBtn.addEventListener('click', () => initStudySession(false));
if (studyAllBtn) studyAllBtn.addEventListener('click', () => initStudySession(true));

const resetSrsBtn = document.querySelector("#reset-srs");
if (resetSrsBtn) resetSrsBtn.addEventListener("click", () => { if(confirm("Wipe all FSRS progress?")) { try { localStorage.removeItem("rfc_srs_state_fsrs"); } catch (err) {} location.reload(); } });

window.addEventListener('keydown', (e) => {
  if (!studyOverlay || !studyOverlay.classList.contains('active')) return;
  if (e.key === 'Escape') setOverlayOpen(studyOverlay, false);
  if (e.key === ' ') { e.preventDefault(); if (!cardContainer.classList.contains('flipped')) cardContainer.click(); }
  if (cardContainer.classList.contains('flipped')) {
    if (e.key === '1') handleAnswer(1); if (e.key === '2') handleAnswer(2); if (e.key === '3') handleAnswer(3); if (e.key === '4') handleAnswer(4);
  }
});

// Relationship Map Logic
const mapOverlay = document.querySelector('#map-overlay');
const openMapBtn = document.querySelector('#open-map');
const closeMapBtn = document.querySelector('#close-map');
const mapContainer = document.querySelector('#map-container');

const GRAPH_DATA = {
  get nodes() {
    return (window.FLASHCARDS || []).filter(c => c.id.endsWith('-fundamental')).map(c => ({
        id: c.rfc, num: c.rfc,
        name: c.prompt.match(/RFC \d+ \((.*?)\)/)?.[1] || `RFC ${c.rfc}`,
        layer: c.answer.match(/Layer: (.*?)\n/)?.[1].split(',')[0].trim().toLowerCase() || 'application'
    }));
  },
  links: [
    { source: "793", target: "791", type: "dependency" }, { source: "768", target: "791", type: "dependency" },
    { source: "1035", target: "768", type: "dependency" }, { source: "1035", target: "793", type: "dependency" },
    { source: "4271", target: "793", type: "dependency" }, { source: "2131", target: "768", type: "dependency" },
    { source: "5321", target: "793", type: "dependency" }, { source: "3954", target: "768", type: "dependency" },
    { source: "7011", target: "768", type: "dependency" }, { source: "2616", target: "793", type: "dependency" },
    { source: "7230", target: "793", type: "dependency" }, { source: "7540", target: "793", type: "dependency" },
    { source: "2328", target: "791", type: "dependency" }, { source: "826", target: "791", type: "dependency" },
    { source: "2460", target: "791", type: "update-chain" }, { source: "7230", target: "2616", type: "update-chain" },
    { source: "1035", target: "5321", type: "threat" }, { source: "1035", target: "768", type: "threat" },
    { source: "4271", target: "2328", type: "threat" }, { source: "791", target: "2460", type: "threat" },
    { source: "793", target: "7540", type: "threat" },
  ]
};

function initMap() {
  if (!mapContainer) return;
  const nodes = GRAPH_DATA.nodes; if (!nodes.length) { console.warn("No nodes found"); return; }
  const nodeIds = new Set(nodes.map(n => n.id));
  const links = GRAPH_DATA.links.filter(l => nodeIds.has(l.source) && nodeIds.has(l.target)).map(l => ({...l}));

  const width = mapContainer.clientWidth || window.innerWidth;
  const height = mapContainer.clientHeight || window.innerHeight;

  mapContainer.querySelector('svg')?.remove();
  const ns = 'http://www.w3.org/2000/svg';
  const svg = document.createElementNS(ns, 'svg');
  svg.setAttribute('width', '100%');
  svg.setAttribute('height', '100%');
  svg.setAttribute('viewBox', `0 0 ${width} ${height}`);
  svg.setAttribute('role', 'img');
  svg.setAttribute('aria-label', 'RFC dependency graph');
  const g = document.createElementNS(ns, 'g');
  svg.appendChild(g);
  mapContainer.appendChild(svg);

  const centerX = width / 2;
  const centerY = height / 2;
  const radius = Math.max(180, Math.min(width, height) * 0.36);
  const priority = new Set(['768', '791', '792', '793', '826', '1035', '2131', '2328', '3954', '4271', '5321', '7011', '7230', '7540']);
  const visibleNodes = nodes.filter(n => priority.has(n.id));
  const visibleIds = new Set(visibleNodes.map(n => n.id));
  const visibleLinks = links.filter(l => visibleIds.has(l.source) && visibleIds.has(l.target));
  visibleNodes.forEach((node, index) => {
    const angle = (index / visibleNodes.length) * Math.PI * 2 - Math.PI / 2;
    node.x = centerX + Math.cos(angle) * radius;
    node.y = centerY + Math.sin(angle) * radius;
  });
  const byId = new Map(visibleNodes.map(node => [node.id, node]));
  const linkEls = [];
  const nodeEls = [];

  visibleLinks.forEach(link => {
    const source = byId.get(link.source);
    const target = byId.get(link.target);
    if (!source || !target) return;
    const path = document.createElementNS(ns, 'path');
    const midX = (source.x + target.x) / 2;
    const midY = (source.y + target.y) / 2;
    const curveX = midX + (centerX - midX) * 0.24;
    const curveY = midY + (centerY - midY) * 0.24;
    path.setAttribute('d', `M${source.x},${source.y} Q${curveX},${curveY} ${target.x},${target.y}`);
    path.setAttribute('class', `link ${link.type}`);
    path.dataset.source = source.id;
    path.dataset.target = target.id;
    g.appendChild(path);
    linkEls.push(path);
  });

  visibleNodes.forEach(node => {
    const group = document.createElementNS(ns, 'g');
    group.setAttribute('class', `node node-${node.layer}`);
    group.setAttribute('transform', `translate(${node.x},${node.y})`);
    group.setAttribute('tabindex', '0');
    group.setAttribute('role', 'link');
    group.setAttribute('aria-label', `Open RFC ${node.num}: ${node.name}`);
    group.dataset.id = node.id;
    const nodeWidth = Math.max(120, node.name.length * 8 + 30);
    const title = document.createElementNS(ns, 'title');
    title.textContent = `RFC ${node.num}: ${node.name}`;
    const rect = document.createElementNS(ns, 'rect');
    rect.setAttribute('width', String(nodeWidth));
    rect.setAttribute('height', '54');
    rect.setAttribute('x', String(-nodeWidth / 2));
    rect.setAttribute('y', '-27');
    const label = document.createElementNS(ns, 'text');
    label.setAttribute('dy', '-4');
    label.style.fontSize = '11px';
    label.textContent = node.name;
    const num = document.createElementNS(ns, 'text');
    num.setAttribute('class', 'node-rfc');
    num.setAttribute('dy', '14');
    num.textContent = `RFC ${node.num}`;
    group.append(title, rect, label, num);
    const open = () => { window.location.href = `rfc/rfc${node.num}.html`; };
    group.addEventListener('click', open);
    group.addEventListener('keydown', (event) => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); open(); } });
    group.addEventListener('pointerenter', () => highlightGraph(node.id, nodeEls, linkEls));
    group.addEventListener('pointerleave', () => clearGraphHighlight(nodeEls, linkEls));
    g.appendChild(group);
    nodeEls.push(group);
  });

  let transform = { x: 0, y: 0, scale: 1 };
  let dragStart = null;
  const applyTransform = () => g.setAttribute('transform', `translate(${transform.x} ${transform.y}) scale(${transform.scale})`);
  svg.addEventListener('wheel', (event) => {
    event.preventDefault();
    transform.scale = Math.min(3, Math.max(0.45, transform.scale + (event.deltaY > 0 ? -0.08 : 0.08)));
    applyTransform();
  }, { passive: false });
  svg.addEventListener('pointerdown', (event) => { dragStart = { x: event.clientX - transform.x, y: event.clientY - transform.y }; svg.setPointerCapture(event.pointerId); });
  svg.addEventListener('pointermove', (event) => {
    if (!dragStart) return;
    transform.x = event.clientX - dragStart.x;
    transform.y = event.clientY - dragStart.y;
    applyTransform();
  });
  svg.addEventListener('pointerup', () => { dragStart = null; });
}

function highlightGraph(id, nodeEls, linkEls) {
  const neighbors = new Set([id]);
  linkEls.forEach(link => {
    if (link.dataset.source === id) neighbors.add(link.dataset.target);
    if (link.dataset.target === id) neighbors.add(link.dataset.source);
  });
  nodeEls.forEach(node => node.classList.toggle('dimmed', !neighbors.has(node.dataset.id)));
  linkEls.forEach(link => {
    const active = link.dataset.source === id || link.dataset.target === id;
    link.classList.toggle('highlight', active);
    link.classList.toggle('dimmed', !active);
  });
}

function clearGraphHighlight(nodeEls, linkEls) {
  nodeEls.forEach(node => node.classList.remove('dimmed'));
  linkEls.forEach(link => link.classList.remove('dimmed', 'highlight'));
}

function setStudyPath(pathId, scrollIntoView = false) {
  const activeBtn = studyPathBtns.find((btn) => btn.dataset.path === pathId) || null;
  activeStudyPath = activeBtn?.dataset.label || '';
  activeStudyRfcSet = activeBtn ? new Set((activeBtn.dataset.rfcs || '').split(' ').filter(Boolean)) : null;
  studyPathBtns.forEach((btn) => btn.classList.toggle('active', btn === activeBtn));
  if (activeStudyPathEl) activeStudyPathEl.textContent = activeStudyPath || 'Full library mode';
  if (clearStudyPathBtn) clearStudyPathBtn.disabled = !activeBtn;
  try { localStorage.setItem('rfc_active_study_path', activeBtn?.dataset.path || ''); } catch (err) {}
  applyFilters();
  if (scrollIntoView) document.querySelector('#rfc-grid')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function updateIfThenPreview() {
  if (!ifThenPreview) return;
  const cue = ifThenCueInput?.value.trim() || '';
  const action = ifThenActionInput?.value.trim() || '';
  if (!cue && !action) {
    ifThenPreview.textContent = 'If your cue happens, then your study move lives here. Tiny counts. Tiny is how empires are built.';
    return;
  }
  ifThenPreview.textContent = `If ${cue || '...'}, then ${action || '...'}.`;
}

function loadIfThenPlan() {
  const saved = readJSON('rfc_if_then_plan', { cue: '', action: '' });
  if (ifThenCueInput) ifThenCueInput.value = saved.cue || '';
  if (ifThenActionInput) ifThenActionInput.value = saved.action || '';
  updateIfThenPreview();
}

if (openMapBtn) openMapBtn.addEventListener('click', () => { setOverlayOpen(mapOverlay, true); setTimeout(initMap, 100); });
if (closeMapBtn) closeMapBtn.addEventListener('click', () => setOverlayOpen(mapOverlay, false));

window.addEventListener('keydown', (e) => {
  if (e.key === 'Escape' && mapOverlay?.classList.contains('active')) setOverlayOpen(mapOverlay, false);
});

function applyFilters() {
  const term = q?.value.trim().toLowerCase() || '';
  let visible = 0;
  for (const card of cards) {
    const tagHit = activeTag === 'all' || card.dataset.tags.split(' ').includes(activeTag);
    const studyHit = !activeStudyRfcSet || activeStudyRfcSet.has(card.dataset.rfc);
    const hit = tagHit && studyHit && card.dataset.search.includes(term);
    card.style.display = hit ? '' : 'none';
    if (hit) visible++;
  }
  if (count) count.textContent = `${visible} of ${cards.length} shown${activeStudyPath ? ` · Path: ${activeStudyPath}` : ''}`;
  if (empty) {
    empty.style.display = visible ? 'none' : 'block';
    empty.textContent = activeStudyPath ? `No RFCs match the current search inside "${activeStudyPath}". Try clearing the search or switching tracks.` : emptyDefaultText;
  }
}

function renderNotes() {
  if (!notesContainer) return;
  const allNotes = readJSON('rfc_notes');
  notesContainer.innerHTML = '';
  const rfcNums = Object.keys(allNotes).sort((a, b) => parseInt(a) - parseInt(b));
  let hasVisibleNotes = false;
  rfcNums.forEach(num => {
    const sectionIds = Object.keys(allNotes[num]).sort();
    const filteredSids = sectionIds.filter(sid => activeNoteFilter === 'all' || allNotes[num][sid].type === activeNoteFilter);
    if (filteredSids.length === 0) return;
    hasVisibleNotes = true;
    const rfcGroup = document.createElement('div'); rfcGroup.className = 'notes-rfc-group';
    const firstNoteId = filteredSids[0];
    const rfcTitle = allNotes[num][firstNoteId].rfcTitle || `RFC ${num}`;
    const header = document.createElement('div'); header.className = 'notes-rfc-header';
    header.innerHTML = `<span>RFC ${num}: ${rfcTitle}</span> <a href="rfc/rfc${num}.html">View RFC</a>`;
    rfcGroup.appendChild(header);
    filteredSids.forEach(sid => {
      const note = allNotes[num][sid];
      const item = document.createElement('div'); item.className = 'note-item';
      const link = document.createElement('a'); link.className = 'note-item-link';
      link.href = `rfc/rfc${num}.html#${sid}`; link.textContent = note.title || `Section ${sid}`;
      const content = document.createElement('div'); content.className = 'note-item-content';
      content.textContent = note.content; item.appendChild(link); item.appendChild(content); rfcGroup.appendChild(item);
    });
    notesContainer.appendChild(rfcGroup);
  });
  if (!hasVisibleNotes) {
    notesContainer.innerHTML = rfcNums.length === 0 ? '<div class="notes-empty">You haven\'t added any notes yet.</div>' : `<div class="notes-empty">No notes match the "${activeNoteFilter}" filter.</div>`;
  }
}

function toggleNotesView(show) {
  if (show) {
    mainGrid.style.display = 'none'; document.querySelector('.hero').style.display = 'none';
    document.querySelector('.toolbar').style.display = 'none'; notesView.classList.add('active'); renderNotes();
  } else {
    mainGrid.style.display = 'block'; document.querySelector('.hero').style.display = 'block';
    document.querySelector('.toolbar').style.display = 'block'; notesView.classList.remove('active');
  }
}

q?.addEventListener('input', applyFilters);
studyPathBtns.forEach((btn) => btn.addEventListener('click', () => setStudyPath(btn.dataset.path, true)));
if (clearStudyPathBtn) clearStudyPathBtn.addEventListener('click', () => setStudyPath('', false));
if (densityToggleBtn) densityToggleBtn.addEventListener('click', () => {
  const compact = !document.body.classList.contains('card-compact');
  document.body.classList.toggle('card-compact', compact);
  try { localStorage.setItem('rfc_card_density', compact ? 'compact' : 'comfortable'); } catch (err) {}
  densityToggleBtn.textContent = compact ? 'Comfort cards' : 'Compact cards';
});
filters.forEach(btn => btn.addEventListener('click', () => { activeTag = btn.dataset.tag; filters.forEach(item => item.classList.toggle('active', item === btn)); applyFilters(); }));
noteFilterBtns.forEach(btn => btn.addEventListener('click', () => { activeNoteFilter = btn.dataset.filter; noteFilterBtns.forEach(b => b.classList.toggle('active', b === btn)); renderNotes(); }));
if (viewNotesBtn) viewNotesBtn.addEventListener('click', () => toggleNotesView(true));
if (backToGridBtn) backToGridBtn.addEventListener('click', () => toggleNotesView(false));
if (exportBtn) exportBtn.addEventListener('click', () => {
  const allNotes = localStorage.getItem('rfc_notes') || '{}';
  const blob = new Blob([allNotes], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a'); a.href = url; a.download = `rfc-annotations-${new Date().toISOString().split('T')[0]}.json`; a.click(); URL.revokeObjectURL(url);
});
if (importBtn && importFile) importBtn.addEventListener('click', () => importFile.click());
if (importFile) importFile.addEventListener('change', (e) => {
  const file = e.target.files[0]; if (!file) return;
  const reader = new FileReader();
  reader.onload = (event) => {
    try {
      const imported = JSON.parse(event.target.result);
      const current = readJSON('rfc_notes');
      for (const rfcNum in imported) {
        if (!current[rfcNum]) current[rfcNum] = imported[rfcNum];
        else current[rfcNum] = { ...current[rfcNum], ...imported[rfcNum] };
      }
      writeJSON('rfc_notes', current); renderNotes(); alert('Notes imported and merged successfully!');
    } catch (err) { alert('Error importing notes: Invalid JSON file'); }
  };
  reader.readAsText(file);
});
ifThenCueInput?.addEventListener('input', updateIfThenPreview);
ifThenActionInput?.addEventListener('input', updateIfThenPreview);
if (saveIfThenBtn) saveIfThenBtn.addEventListener('click', () => {
  const cue = ifThenCueInput?.value.trim() || '';
  const action = ifThenActionInput?.value.trim() || '';
  writeJSON('rfc_if_then_plan', { cue, action });
  if (ifThenStatus) ifThenStatus.textContent = cue && action ? 'Saved locally. Future you now has a cue, a move, and slightly fewer excuses.' : 'Saved, though a specific cue and action will work better.';
  updateIfThenPreview();
});
if (clearIfThenBtn) clearIfThenBtn.addEventListener('click', () => {
  if (ifThenCueInput) ifThenCueInput.value = '';
  if (ifThenActionInput) ifThenActionInput.value = '';
  writeJSON('rfc_if_then_plan', { cue: '', action: '' });
  if (ifThenStatus) ifThenStatus.textContent = 'Pact cleared. The gremlin has been temporarily released back into the wild.';
  updateIfThenPreview();
});

loadIfThenPlan();
try {
  const savedStudyPath = localStorage.getItem('rfc_active_study_path') || '';
  if (savedStudyPath) setStudyPath(savedStudyPath, false);
  else applyFilters();
} catch (err) {
  applyFilters();
}
updateDueCounts();
window.addEventListener('scroll', () => toolbar?.classList.toggle('scrolled', window.scrollY > 12), { passive: true });
