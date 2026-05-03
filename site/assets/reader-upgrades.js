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
  document.addEventListener("click", (event) => {
    const button = event.target.closest("[data-reader-mode]");
    if (!button) return;
    setMode(button.dataset.readerMode);
  });
  setMode(localStorage.getItem(storageKey) || "comfortable");
})();
