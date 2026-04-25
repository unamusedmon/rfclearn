
const q = document.querySelector('#q');
const cards = [...document.querySelectorAll('.card')];
const empty = document.querySelector('.empty');
const count = document.querySelector('#count');
const filters = [...document.querySelectorAll('.filter')];
let activeTag = 'all';

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

q.addEventListener('input', applyFilters);
for (const button of filters) {
  button.addEventListener('click', () => {
    activeTag = button.dataset.tag;
    filters.forEach((item) => item.classList.toggle('active', item === button));
    applyFilters();
  });
}
applyFilters();
