
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

// Relationship Map Logic
const mapOverlay = document.querySelector('#map-overlay');
const openMapBtn = document.querySelector('#open-map');
const closeMapBtn = document.querySelector('#close-map');
const mapContainer = document.querySelector('#map-container');

const GRAPH_DATA = {
  nodes: (window.FLASHCARDS || []).filter(c => c.id.endsWith('-fundamental')).map(c => ({
    id: c.rfc,
    num: c.rfc,
    name: c.prompt.match(/RFC \d+ \((.*?)\)/)?.[1] || `RFC ${c.rfc}`,
    layer: c.answer.match(/Layer: (.*?)\n/)?.[1].split(',')[0].trim().toLowerCase() || 'application'
  })),
  links: [
    // Dependencies (runs over)
    { source: "793", target: "791", type: "dependency" }, // TCP over IP
    { source: "768", target: "791", type: "dependency" }, // UDP over IP
    { source: "1035", target: "768", type: "dependency" }, // DNS over UDP
    { source: "1035", target: "793", type: "dependency" }, // DNS over TCP
    { source: "4271", target: "793", type: "dependency" }, // BGP over TCP
    { source: "2131", target: "768", type: "dependency" }, // DHCP over UDP
    { source: "5321", target: "793", type: "dependency" }, // SMTP over TCP
    { source: "3954", target: "768", type: "dependency" }, // NetFlow over UDP
    { source: "7011", target: "768", type: "dependency" }, // IPFIX over UDP
    { source: "2616", target: "793", type: "dependency" }, // HTTP over TCP
    { source: "7230", target: "793", type: "dependency" }, // HTTP over TCP
    { source: "7540", target: "793", type: "dependency" }, // HTTP/2 over TCP
    { source: "2328", target: "791", type: "dependency" }, // OSPF over IP
    { source: "826", target: "791", type: "dependency" }, // ARP relates to IP
    
    // Update Chains
    { source: "2460", target: "791", type: "update-chain" }, // IPv6 / IPv4
    { source: "7230", target: "2616", type: "update-chain" }, // HTTP updates
    
    // Threat Relationships (Shared vectors)
    { source: "1035", target: "5321", type: "threat" }, // DNS/SMTP Amplification
    { source: "1035", target: "768", type: "threat" }, // DNS/UDP Reflection
    { source: "4271", target: "2328", type: "threat" }, // BGP/OSPF Spoofing
    { source: "791", target: "2460", type: "threat" }, // IP/IPv6 Fragmentation
    { source: "793", target: "7540", type: "threat" }, // TCP/HTTP2 Flooding
  ]
};

function initMap() {
  if (!window.d3) return;
  
  const width = mapContainer.clientWidth;
  const height = mapContainer.clientHeight;
  
  mapContainer.innerHTML = mapContainer.querySelector('.map-legend').outerHTML; // Keep legend
  
  const svg = d3.select("#map-container").append("svg")
    .attr("width", "100%")
    .attr("height", "100%")
    .attr("viewBox", [0, 0, width, height]);

  const g = svg.append("g");

  // Zoom
  svg.call(d3.zoom()
    .extent([[0, 0], [width, height]])
    .scaleExtent([0.1, 8])
    .on("zoom", ({transform}) => g.attr("transform", transform)));

  const simulation = d3.forceSimulation(GRAPH_DATA.nodes)
    .force("link", d3.forceLink(GRAPH_DATA.links).id(d => d.id).distance(150))
    .force("charge", d3.forceManyBody().strength(-300))
    .force("center", d3.forceCenter(width / 2, height / 2))
    .force("collision", d3.forceCollide().radius(60));

  const link = g.append("g")
    .selectAll("path")
    .data(GRAPH_DATA.links)
    .join("path")
    .attr("class", d => `link ${d.type}`);

  const node = g.append("g")
    .selectAll(".node")
    .data(GRAPH_DATA.nodes)
    .join("g")
    .attr("class", d => `node node-${d.layer}`)
    .call(drag(simulation))
    .on("click", (e, d) => {
      if (e.defaultPrevented) return;
      window.location.href = `rfc/rfc${d.num}.html`;
    })
    .on("mouseover", (e, d) => {
      const neighbors = new Set();
      neighbors.add(d.id);
      GRAPH_DATA.links.forEach(l => {
        if (l.source.id === d.id) neighbors.add(l.target.id);
        if (l.target.id === d.id) neighbors.add(l.source.id);
      });
      
      node.classed("dimmed", n => !neighbors.has(n.id));
      link.classed("dimmed", l => l.source.id !== d.id && l.target.id !== d.id);
      link.classed("highlight", l => l.source.id === d.id || l.target.id === d.id);
    })
    .on("mouseout", () => {
      node.classed("dimmed", false);
      link.classed("dimmed", false);
      link.classed("highlight", false);
    });

  node.append("rect")
    .attr("width", 100)
    .attr("height", 45)
    .attr("x", -50)
    .attr("y", -22);

  node.append("text")
    .attr("dy", "-2")
    .text(d => d.name.length > 15 ? d.name.substring(0, 13) + '...' : d.name);

  node.append("text")
    .attr("class", "node-rfc")
    .attr("dy", "12")
    .text(d => `RFC ${d.num}`);

  simulation.on("tick", () => {
    link.attr("d", d => {
      const dx = d.target.x - d.source.x;
      const dy = d.target.y - d.source.y;
      const dr = Math.sqrt(dx * dx + dy * dy);
      return `M${d.source.x},${d.source.y}A${dr},${dr} 0 0,1 ${d.target.x},${d.target.y}`;
    });

    node.attr("transform", d => `translate(${d.x},${d.y})`);
  });

  function drag(sim) {
    return d3.drag()
      .on("start", (e) => {
        if (!e.active) sim.alphaTarget(0.3).restart();
        e.subject.fx = e.subject.x;
        e.subject.fy = e.subject.y;
      })
      .on("drag", (e) => {
        e.subject.fx = e.x;
        e.subject.fy = e.y;
      })
      .on("end", (e) => {
        if (!e.active) sim.alphaTarget(0);
        e.subject.fx = null;
        e.subject.fy = null;
      });
  }
}

if (openMapBtn) {
    openMapBtn.addEventListener('click', () => {
      mapOverlay.classList.add('active');
      initMap();
    });
}
if (closeMapBtn) closeMapBtn.addEventListener('click', () => mapOverlay.classList.remove('active'));

window.addEventListener('keydown', (e) => {
  if (e.key === 'Escape' && mapOverlay.classList.contains('active')) {
    mapOverlay.classList.remove('active');
  }
});
