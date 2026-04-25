
const progress = document.querySelector('.progress');
const body = document.querySelector('.doc-body');
const toc = document.querySelector('#toc-links');
const focusBtn = document.querySelector('[data-action="focus"]');
const comfyBtn = document.querySelector('[data-action="comfy"]');
const topBtn = document.querySelector('[data-action="top"]');
const headerPanel = document.querySelector('.header-reference-panel');

function updateProgress() {
  const max = document.documentElement.scrollHeight - innerHeight;
  progress.style.width = max > 0 ? `${(scrollY / max) * 100}%` : '0%';
}

function makeToc() {
  const headings = [...body.querySelectorAll('h1, h2, h3')].slice(0, 80);
  if (!headings.length) {
    toc.innerHTML = '<p class="muted">This RFC source is mostly preformatted text, so use browser find for section jumps.</p>';
    return;
  }
  toc.innerHTML = '';
  headings.forEach((heading, index) => {
    const id = `section-${index + 1}`;
    heading.id = id;
    const link = document.createElement('a');
    link.href = `#${id}`;
    link.textContent = heading.textContent.trim().slice(0, 96) || `Section ${index + 1}`;
    toc.appendChild(link);
  });
}

function setHeaderPanelDefault() {
  if (!headerPanel) return;
  headerPanel.open = !matchMedia('(max-width: 780px)').matches;
}

addEventListener('scroll', updateProgress, { passive: true });
focusBtn.addEventListener('click', () => body.classList.toggle('focus'));
comfyBtn.addEventListener('click', () => body.classList.toggle('comfy'));
topBtn.addEventListener('click', () => scrollTo({ top: 0, behavior: 'smooth' }));
setHeaderPanelDefault();
makeToc();
updateProgress();
