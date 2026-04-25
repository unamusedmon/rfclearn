
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

let activeTag = 'all';
let activeNoteFilter = 'all';

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
        const note = allNotes[num][sid];
        return note.type === activeNoteFilter;
    });

    if (filteredSids.length === 0) return;
    hasVisibleNotes = true;

    const rfcGroup = document.createElement('div');
    rfcGroup.className = 'notes-rfc-group';
    
    const firstNoteId = sectionIds[0];
    const rfcTitle = allNotes[num][firstNoteId].rfcTitle || `RFC ${num}`;
    
    const header = document.createElement('div');
    header.className = 'notes-rfc-header';
    header.innerHTML = `<span>RFC ${num}: ${rfcTitle}</span> <a href="rfc/rfc${num}.html">View RFC</a>`;
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
        notesContainer.innerHTML = '<div class="notes-empty">You haven\'t added any notes yet. Go to an RFC page and click the "Note" button on any section or threat indicator.</div>';
    } else {
        notesContainer.innerHTML = `<div class="notes-empty">No notes match the "${activeNoteFilter}" filter.</div>`;
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
        if (!current[rfcNum]) {
          current[rfcNum] = imported[rfcNum];
        } else {
          current[rfcNum] = { ...current[rfcNum], ...imported[rfcNum] };
        }
      }
      localStorage.setItem('rfc_notes', JSON.stringify(current));
      renderNotes();
      alert('Notes imported and merged successfully!');
    } catch (err) {
      alert('Error importing notes: Invalid JSON file');
    }
  };
  reader.readAsText(file);
});

applyFilters();
