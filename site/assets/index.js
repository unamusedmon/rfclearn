
const q = document.querySelector('#q');
const cards = [...document.querySelectorAll('.card')];
const empty = document.querySelector('.empty');
const count = document.querySelector('#count');
const filters = [...document.querySelectorAll('.filter')];
const viewNotesBtn = document.querySelector('#view-notes');
const backToGridBtn = document.querySelector('#back-to-grid');
const notesView = document.querySelector('#notes-view');
const mainGrid = document.querySelector('main');
const notesContainer = document.querySelector('#notes-container');
const exportBtn = document.querySelector('#export-notes');
const importBtn = document.querySelector('#import-notes-btn');
const importFile = document.querySelector('#import-notes-file');
const noteFilterBtns = [...document.querySelectorAll('.notes-filter-btn')];

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
let currentSession = [];
let sessionIdx = 0;
let sessionStats = { reviewed: 0, mastered: 0, dueTomorrow: 0 };

// FSRS-4.5 Weights
const w = [0.4, 0.6, 2.4, 5.8, 4.93, 0.94, 0.86, 0.01, 1.49, 0.14, 0.94, 2.18, 0.05, 0.34, 1.26, 0.29, 2.61];

function getSRSData() {
  return JSON.parse(localStorage.getItem('rfc_srs_state_fsrs') || '{}');
}

function saveSRSData(state) {
  localStorage.setItem('rfc_srs_state_fsrs', JSON.stringify(state));
  updateDueCounts();
}

function getRetrievability(state, now) {
  if (!state || !state.last_date) return 0;
  const t = Math.max(0, (now - state.last_date) / (24 * 60 * 60 * 1000));
  return Math.pow(1 + t / (9 * state.S), -1);
}

function fsrs_update(grade, state, now) {
  let { S, D, last_date, repetitions } = state || { S: 0, D: 0, last_date: 0, repetitions: 0 };
  const t = last_date ? Math.max(0, (now - last_date) / (24 * 60 * 60 * 1000)) : 0;
  const R = last_date ? getRetrievability(state, now) : 0;

  if (repetitions === 0) {
    S = w[grade - 1];
    D = w[4] - (grade - 3) * w[5];
  } else {
    // Difficulty update
    D = D - w[6] * (grade - 3);
    D = Math.min(Math.max(D, 1), 10);
    
    // Stability update
    if (grade === 1) {
      S = w[7] * Math.exp(-w[8] * D) * (Math.pow(S + 1, w[9]) - 1) * Math.exp(w[10] * (1 - R));
    } else {
      S = S * (1 + Math.exp(w[11]) * (11 - D) * Math.pow(S, -w[12]) * (Math.exp(w[13] * (1 - R)) - 1));
    }
  }

  repetitions++;
  return { S, D, last_date: now, repetitions };
}

function updateDueCounts() {
  const srs = getSRSData();
  const now = Date.now();
  const due = (window.FLASHCARDS || []).filter(c => {
    const state = srs[c.id];
    if (!state) return true;
    return getRetrievability(state, now) <= 0.9;
  });
  if (srsDueBadge) srsDueBadge.textContent = due.length;
}

function initStudySession(all = false) {
  const srs = getSRSData();
  const now = Date.now();
  currentSession = (window.FLASHCARDS || []).filter(c => {
    if (all) return true;
    const state = srs[c.id];
    if (!state) return true;
    return getRetrievability(state, now) <= 0.9;
  });

  if (currentSession.length === 0 && !all) {
    alert("No cards due! Use 'Study All' to practice anyway.");
    return;
  }

  currentSession.sort(() => Math.random() - 0.5);
  sessionIdx = 0;
  sessionStats = { reviewed: 0, mastered: 0, dueTomorrow: 0 };
  studyOverlay.classList.add('active');
  studySummary.classList.remove('active');
  cardContainer.style.display = 'block';
  showCard();
}

function showCard() {
  if (sessionIdx >= currentSession.length) { showSummary(); return; }
  const card = currentSession[sessionIdx];
  const state = getSRSData()[card.id];
  const R = state ? Math.round(getRetrievability(state, Date.now()) * 100) : 0;
  
  cardContainer.classList.remove('flipped');
  studyActions.classList.remove('visible');
  document.querySelector('#card-category').textContent = card.category;
  document.querySelector('#card-category-back').textContent = card.category;
  document.querySelector('#card-prompt').textContent = card.prompt;
  document.querySelector('#card-answer').textContent = card.answer;
  document.querySelector('#card-meta').textContent = state ? `S: ${state.S.toFixed(1)} | D: ${state.D.toFixed(1)} | R: ${R}%` : 'New Card';
  document.querySelector('#study-count').textContent = `Card ${sessionIdx + 1} of ${currentSession.length}`;
  progressBar.style.width = `${(sessionIdx / currentSession.length) * 100}%`;
}

function showSummary() {
  cardContainer.style.display = 'none';
  studyActions.classList.remove('visible');
  studySummary.classList.add('active');
  progressBar.style.width = '100%';
  document.querySelector('#sum-reviewed').textContent = sessionStats.reviewed;
  document.querySelector('#sum-mastered').textContent = sessionStats.mastered;
  
  const srs = getSRSData();
  const tomorrow = Date.now() + 24 * 60 * 60 * 1000;
  const dueTomorrow = Object.values(srs).filter(s => getRetrievability(s, tomorrow) <= 0.9).length;
  document.querySelector('#sum-due').textContent = dueTomorrow;
}

function handleAnswer(grade) {
  const card = currentSession[sessionIdx];
  const srs = getSRSData();
  const newState = fsrs_update(grade, srs[card.id], Date.now());
  srs[card.id] = newState;
  saveSRSData(srs);
  sessionStats.reviewed++;
  if (newState.S > 30) sessionStats.mastered++;
  sessionIdx++;
  showCard();
}

if (cardContainer) {
    cardContainer.addEventListener('click', () => {
      if (!cardContainer.classList.contains('flipped')) {
        cardContainer.classList.add('flipped');
        studyActions.classList.add('visible');
      }
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

if (startStudyBtn) startStudyBtn.addEventListener('click', () => initStudySession(false));
if (studyAllBtn) studyAllBtn.addEventListener('click', () => initStudySession(true));

const resetSrsBtn = document.querySelector("#reset-srs");
if (resetSrsBtn) resetSrsBtn.addEventListener("click", () => { if(confirm("Wipe all FSRS progress?")) { localStorage.removeItem("rfc_srs_state_fsrs"); location.reload(); } });

window.addEventListener('keydown', (e) => {
  if (!studyOverlay || !studyOverlay.classList.contains('active')) return;
  if (e.key === 'Escape') studyOverlay.classList.remove('active');
  if (e.key === ' ') { if (!cardContainer.classList.contains('flipped')) cardContainer.click(); }
  if (cardContainer.classList.contains('flipped')) {
    if (e.key === '1') handleAnswer(1);
    if (e.key === '2') handleAnswer(2);
    if (e.key === '3') handleAnswer(3);
    if (e.key === '4') handleAnswer(4);
  }
});

function applyFilters() {
  const term = q.value.trim().toLowerCase();
  let visible = 0;
  for (const card of cards) {
    const tagHit = activeTag === 'all' || card.dataset.tags.split(' ').includes(activeTag);
    const hit = tagHit && card.dataset.search.includes(term);
    card.style.display = hit ? '' : 'none';
    if (hit) visible++;
  }
  count.textContent = `${visible} shown`;
  empty.style.display = visible ? 'none' : 'block';
}

function renderNotes() {
  const allNotes = JSON.parse(localStorage.getItem('rfc_notes') || '{}');
  notesContainer.innerHTML = '';
  const rfcNums = Object.keys(allNotes).sort((a, b) => parseInt(a) - parseInt(b));
  let hasVisibleNotes = false;
  rfcNums.forEach(num => {
    const sectionIds = Object.keys(allNotes[num]).sort();
    const filteredSids = sectionIds.filter(sid => {
        if (activeNoteFilter === 'all') return true;
        return allNotes[num][sid].type === activeNoteFilter;
    });
    if (filteredSids.length === 0) return;
    hasVisibleNotes = true;
    const rfcGroup = document.createElement('div');
    rfcGroup.className = 'notes-rfc-group';
    const firstNoteId = sectionIds[0];
    const rfcTitle = allNotes[num][firstNoteId].rfcTitle || `RFC ${num}`;
    const header = document.createElement('div');
    header.className = 'notes-rfc-header';
    header.innerHTML = `<span>RFC ${num}: ${rfcTitle}</span> <a href=\"rfc/rfc${num}.html\">View RFC</a>`;
    rfcGroup.appendChild(header);
    filteredSids.forEach(sid => {
      const note = allNotes[num][sid];
      const item = document.createElement('div');
      item.className = 'note-item';
      const link = document.createElement('a');
      link.className = 'note-item-link';
      link.href = `rfc/rfc${num}.html#${sid}`;
      link.textContent = note.title || `Section ${sid}`;
      const content = document.createElement('div');
      content.className = 'note-item-content';
      content.textContent = note.content;
      item.appendChild(link);
      item.appendChild(content);
      rfcGroup.appendChild(item);
    });
    notesContainer.appendChild(rfcGroup);
  });
  if (!hasVisibleNotes) {
    if (rfcNums.length === 0) {
        notesContainer.innerHTML = '<div class=\"notes-empty\">You haven\'t added any notes yet. Go to an RFC page and click the \"Note\" button on any section or threat indicator.</div>';
    } else {
        notesContainer.innerHTML = `<div class=\"notes-empty\">No notes match the \"${activeNoteFilter}\" filter.</div>`;
    }
  }
}

function toggleNotesView(show) {
  if (show) {
    mainGrid.style.display = 'none';
    document.querySelector('.hero').style.display = 'none';
    document.querySelector('.toolbar').style.display = 'none';
    notesView.classList.add('active');
    renderNotes();
  } else {
    mainGrid.style.display = 'block';
    document.querySelector('.hero').style.display = 'block';
    document.querySelector('.toolbar').style.display = 'block';
    notesView.classList.remove('active');
  }
}

q.addEventListener('input', applyFilters);
for (const button of filters) {
  button.addEventListener('click', () => {
    activeTag = button.dataset.tag;
    filters.forEach((item) => item.classList.toggle('active', item === button));
    applyFilters();
  });
}

for (const btn of noteFilterBtns) {
    btn.addEventListener('click', () => {
        activeNoteFilter = btn.dataset.filter;
        noteFilterBtns.forEach(b => b.classList.toggle('active', b === btn));
        renderNotes();
    });
}

viewNotesBtn.addEventListener('click', () => toggleNotesView(true));
backToGridBtn.addEventListener('click', () => toggleNotesView(false));

exportBtn.addEventListener('click', () => {
  const allNotes = localStorage.getItem('rfc_notes') || '{}';
  const blob = new Blob([allNotes], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `rfc-annotations-${new Date().toISOString().split('T')[0]}.json`;
  a.click();
  URL.revokeObjectURL(url);
});

importBtn.addEventListener('click', () => importFile.click());
importFile.addEventListener('change', (e) => {
  const file = e.target.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = (event) => {
    try {
      const imported = JSON.parse(event.target.result);
      const current = JSON.parse(localStorage.getItem('rfc_notes') || '{}');
      for (const rfcNum in imported) {
        if (!current[rfcNum]) { current[rfcNum] = imported[rfcNum]; }
        else { current[rfcNum] = { ...current[rfcNum], ...imported[rfcNum] }; }
      }
      localStorage.setItem('rfc_notes', JSON.stringify(current));
      renderNotes();
      alert('Notes imported and merged successfully!');
    } catch (err) { alert('Error importing notes: Invalid JSON file'); }
  };
  reader.readAsText(file);
});

updateDueCounts();
applyFilters();
