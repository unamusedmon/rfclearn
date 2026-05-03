(function () {
  const modes = ["comfortable", "dense", "wide", "focus"];
  const storageKey = "rfclearn.readerMode";

  function setMode(mode) {
    if (!modes.includes(mode)) mode = "comfortable";
    document.body.classList.remove(...modes.map((m) => `reader-mode-${m}`));
    document.body.classList.add(`reader-mode-${mode}`);
    localStorage.setItem(storageKey, mode);
    document.querySelectorAll("[data-reader-mode]").forEach((button) => {
      button.classList.toggle("active", button.dataset.readerMode === mode);
    });
  }

  function removeNearestCard(node) {
    const card = node.closest("section, article, aside, .card, .panel, .source-card, .source-panel, div");
    if (card) card.remove();
  }

  document.addEventListener("click", (event) => {
    const button = event.target.closest("[data-reader-mode]");
    if (!button) return;
    setMode(button.dataset.readerMode);
  });

  document.querySelectorAll("button").forEach((button) => {
    if (button.textContent.trim().toLowerCase() === "note") button.remove();
  });
  document.querySelectorAll("textarea").forEach((textarea) => textarea.remove());
  document.querySelectorAll("body *").forEach((node) => {
    const text = node.textContent.trim();
    if (node.childNodes.length === 1 && text === "Saved") node.remove();
    if (/reader mode/i.test(text) && /cold-war fax/i.test(text)) removeNearestCard(node);
    if (/cover page/i.test(text) && /RFC:\s*\d+/i.test(text)) removeNearestCard(node);
    if (/^\d+\s+page\s+cards?$/i.test(text) || /^RFC\s+Editor\s+HTML$/i.test(text) || /^Page\s+breaks\s+preserved$/i.test(text)) node.remove();
    if (/JUMP\s+LINKS\s+LIVE\s+HERE/i.test(text) && /CONTENTS/i.test(text)) removeNearestCard(node);
  });
  document.querySelectorAll(".rfc-diagram-panel").forEach((figure) => {
    const text = figure.textContent.replace(/Original ASCII/i, "").trim();
    if (text.length < 140 && !/[+|][-=]{3,}|-->|<--/.test(text)) figure.remove();
  });

  setMode(localStorage.getItem(storageKey) || "comfortable");
})();
