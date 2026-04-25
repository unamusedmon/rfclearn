
const progress = document.querySelector('.progress');
const body = document.querySelector('.doc-body');
const toc = document.querySelector('#toc-links');
const focusBtn = document.querySelector('[data-action="focus"]');
const comfyBtn = document.querySelector('[data-action="comfy"]');
const topBtn = document.querySelector('[data-action="top"]');
const headerPanel = document.querySelector('.header-reference-panel');

const rfcMatch = document.querySelector('.eyebrow')?.textContent.match(/RFC (\d+)/);
const rfcNumber = rfcMatch ? rfcMatch[1] : null;

function updateProgress() {
  const max = document.documentElement.scrollHeight - innerHeight;
  progress.style.width = max > 0 ? `${(scrollY / max) * 100}%` : '0%';
}

function makeToc() {
  // Find standard headings AND span-wrapped section links that act as headings in preformatted RFCs AND threat-items
  let headingNodes = [...document.querySelectorAll('h1, h2, h3, .doc-body span > a[href^="#section-"], .threat-item')].slice(0, 100);
  
  if (!headingNodes.length) {
    toc.innerHTML = '<p class="muted">This RFC source is mostly preformatted text, so use browser find for section jumps.</p>';
    return [];
  }

  // Filter out headings from doc-hero so we don't annotate the main title twice
  headingNodes = headingNodes.filter(el => !el.closest('.doc-hero'));

  // If we found 'a' tags, we want their parent span if it exists, otherwise the 'a' itself
  const headings = headingNodes.map(el => {
    if (el.tagName === 'A' && el.parentElement && el.parentElement.tagName === 'SPAN') return el.parentElement;
    return el;
  });

  toc.innerHTML = '';
  headings.forEach((heading, index) => {
    // For TOC, we only want actual document sections, not threat items
    if (heading.classList.contains('threat-item')) return;
    
    if (!heading.id) {
        heading.id = `section-${index + 1}`;
    }
    const id = heading.id;
    const link = document.createElement('a');
    link.href = `#${id}`;
    link.textContent = heading.textContent.replace('Note', '').trim().slice(0, 96) || `Section ${index + 1}`;
    toc.appendChild(link);
  });
  return headings;
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
    
    // For threat items, we append the toggle differently or style it
    if (isThreatItem) {
        heading.querySelector('.threat-header').appendChild(toggle);
    } else {
        heading.appendChild(toggle);
    }

    const indicator = document.createElement('span');
    indicator.className = 'anno-indicator';
    indicator.style.display = existingNote ? 'inline-block' : 'none';
    
    if (isThreatItem) {
        heading.querySelector('.threat-header').appendChild(indicator);
    } else {
        heading.appendChild(indicator);
    }

    const wrap = document.createElement('div');
    wrap.className = 'anno-editor-wrap';
    if (existingNote) {
      toggle.classList.add('active');
    }
    
    const editor = document.createElement('textarea');
    editor.className = 'anno-editor';
    editor.placeholder = 'Add your notes for this ' + (isThreatItem ? 'indicator' : 'section') + '...';
    editor.value = existingNote;
    
    const status = document.createElement('div');
    status.className = 'anno-status';
    status.textContent = 'Saved';

    wrap.appendChild(editor);
    wrap.appendChild(status);
    
    // Insert after the heading or at the end of threat item.
    if (isThreatItem) {
        heading.appendChild(wrap);
    } else {
        heading.insertAdjacentElement('afterend', wrap);
    }

    toggle.addEventListener('click', (e) => {
      e.preventDefault();
      e.stopPropagation();
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
        if (isThreatItem) {
            title = 'Threat: ' + heading.querySelector('.threat-name').textContent;
        } else {
            title = heading.textContent.replace('Note', '').trim();
        }
        
        allNotes[rfcNumber][sectionId] = {
          content: content,
          title: title,
          rfcTitle: document.title.split(':')[1]?.trim() || `RFC ${rfcNumber}`,
          timestamp: Date.now(),
          type: isThreatItem ? 'threat' : 'section'
        };
        indicator.style.display = 'inline-block';
        toggle.classList.add('active');
      } else {
        delete allNotes[rfcNumber][sectionId];
        if (Object.keys(allNotes[rfcNumber]).length === 0) {
          delete allNotes[rfcNumber];
        }
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
initAnnotations(headings);
updateProgress();
