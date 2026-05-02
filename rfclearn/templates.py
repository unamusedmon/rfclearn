"""HTML/CSS/JS templates for RFC Learn."""

SITE_CSS = r"""

:root {
  color-scheme: dark;
  --bg: #070912;
  --panel: #0e1424;
  --panel2: #111a2d;
  --panel3: #152035;
  --text: #eef5ff;
  --text2: #d8e6fa;
  --muted: #9fb0c9;
  --muted2: #7a88a1;
  --line: rgba(255,255,255,.11);
  --line2: rgba(255,255,255,.08);
  --cyan: #65e4ff;
  --cyan2: #4dc8ff;
  --violet: #b89cff;
  --violet2: #a388ff;
  --pink: #ff70b8;
  --pink2: #ff5aa0;
  --green: #7dffa8;
  --green2: #5eff8c;
  --amber: #ffd36a;
  --amber2: #ffc748;
  --red: #ff6b8b;
  --glass: rgba(14,20,36,.65);
  --glass2: rgba(14,20,36,.85);
}

* { box-sizing: border-box; }
*::before, *::after { box-sizing: border-box; }

html {
  scroll-behavior: smooth;
  text-rendering: optimizeLegibility;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
}

body {
  margin: 0;
  min-height: 100vh;
  background: 
    radial-gradient(circle at 12% -10%, rgba(101,228,255,.22), transparent 32rem),
    radial-gradient(circle at 88% 8%, rgba(184,156,255,.2), transparent 31rem),
    radial-gradient(circle at 50% 90%, rgba(255,112,184,.12), transparent 38rem),
    linear-gradient(135deg, #050711 0%, #09111e 48%, #100b1f 100%);
  color: var(--text);
  font: 16px/1.6 Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
}

body:before {
  content: "";
  position: fixed;
  inset: 0;
  pointer-events: none;
  background-image: 
    linear-gradient(rgba(255,255,255,.025) 1px, transparent 1px),
    linear-gradient(90deg, rgba(255,255,255,.025) 1px, transparent 1px);
  background-size: 44px 44px;
  mask-image: radial-gradient(circle at top, black, transparent 75%);
}

/* Subtle animated background stars */
body:after {
  content: "";
  position: fixed;
  inset: 0;
  pointer-events: none;
  background: transparent;
}

/* Animation keyframes */
@keyframes float {
  0%, 100% { transform: translateY(0) translateX(0); opacity: 0.4; }
  50% { transform: translateY(-20px) translateX(10px); opacity: 0.7; }
}

@keyframes pulse {
  0%, 100% { opacity: 1; transform: scale(1); }
  50% { opacity: 0.8; transform: scale(1.02); }
}

@keyframes glow {
  0%, 100% { box-shadow: 0 0 20px rgba(101,228,255,0.3); }
  50% { box-shadow: 0 0 40px rgba(101,228,255,0.5), 0 0 60px rgba(184,156,255,0.3); }
}

@keyframes shimmer {
  0% { background-position: -200% 0; }
  100% { background-position: 200% 0; }
}

@keyframes slideUp {
  from {
    opacity: 0;
    transform: translateY(20px);
  }
  to {
    opacity: 1;
    transform: translateY(0);
  }
}

a {
  color: inherit;
  text-decoration: none;
  transition: color 0.2s ease;
}

a:hover {
  color: var(--cyan);
}

/* Shell container */
.shell {
  width: min(1180px, calc(100% - 34px));
  margin: 0 auto;
}

/* ==================== HERO SECTION ==================== */
.hero {
  padding: 80px 0 48px;
  text-align: center;
  animation: slideUp 0.6s ease-out;
}

.eyebrow {
  display: inline-block;
  color: var(--cyan);
  text-transform: uppercase;
  letter-spacing: .22em;
  font-size: .78rem;
  font-weight: 800;
  margin-bottom: 16px;
  padding: 6px 14px;
  border-radius: 999px;
  background: rgba(101,228,255,.1);
  border: 1px solid rgba(101,228,255,.2);
  animation: pulse 4s ease-in-out infinite;
}

h1 {
  margin: 12px 0 16px;
  font-size: clamp(2.7rem, 8vw, 6.8rem);
  line-height: .86;
  letter-spacing: -.08em;
  max-width: 960px;
  margin-left: auto;
  margin-right: auto;
  background: linear-gradient(135deg, var(--text), var(--cyan), var(--violet));
  background-clip: text;
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  text-fill-color: transparent;
}

.hero p {
  max-width: 780px;
  color: var(--text2);
  font-size: 1.12rem;
  line-height: 1.7;
  margin: 0 auto;
  font-weight: 400;
}

.hero strong {
  color: var(--text);
  font-weight: 600;
}

/* ==================== TOOLBAR ==================== */
.toolbar {
  position: sticky;
  top: 0;
  z-index: 5;
  padding: 18px 0;
  backdrop-filter: blur(24px) saturate(1.2);
  -webkit-backdrop-filter: blur(24px) saturate(1.2);
  background: linear-gradient(to bottom, 
    rgba(7,9,18,.95), 
    rgba(7,9,18,.82));
  border-bottom: 1px solid var(--line);
  transition: all 0.3s ease;
}

.toolbar.scrolled {
  padding: 14px 0;
  box-shadow: 0 8px 40px rgba(0,0,0,0.4);
}

.toolbar-row {
  display: grid;
  grid-template-columns: 1fr auto;
  gap: 16px;
  align-items: center;
}

.searchbox {
  display: flex;
  gap: 14px;
  align-items: center;
  padding: 14px 18px 14px 18px;
  border: 1px solid var(--line);
  border-radius: 999px;
  background: var(--glass2);
  box-shadow: 
    inset 0 1px 0 rgba(255,255,255,.08),
    0 8px 32px rgba(0,0,0,.25);
  transition: all 0.25s ease;
  backdrop-filter: blur(12px);
}

.searchbox:focus-within {
  border-color: rgba(101,228,255,.5);
  box-shadow: 
    0 0 0 3px rgba(101,228,255,.15),
    inset 0 1px 0 rgba(255,255,255,.08),
    0 8px 40px rgba(0,0,0,.35);
}

.searchbox span {
  color: var(--cyan);
  font-weight: 900;
  font-size: 1.05rem;
  transition: color 0.2s ease;
}

.searchbox input {
  flex: 1;
  min-width: 240px;
}

.searchbox input::placeholder {
  color: #7a88a1;
}

.searchbox input:focus {
  outline: none;
}

.view-count {
  color: var(--muted);
  font-weight: 800;
  white-space: nowrap;
  font-size: 0.9rem;
  padding: 10px 14px;
  border-radius: 999px;
  background: var(--glass);
  border: 1px solid var(--line2);
}

.filters {
  display: flex;
  flex-wrap: wrap;
  gap: 10px;
  margin-top: 14px;
}

/* ==================== BUTTONS ==================== */
button.filter,
button.reader-btn {
  cursor: pointer;
  color: #eaf3ff;
  border: 1px solid rgba(255,255,255,.14);
  background: var(--glass);
  border-radius: 999px;
  padding: 8px 14px;
  font: inherit;
  font-size: .86rem;
  font-weight: 900;
  letter-spacing: 0.02em;
  transition: all 0.22s cubic-bezier(0.4, 0, 0.2, 1);
  position: relative;
  overflow: hidden;
}

button.filter::before,
button.reader-btn::before {
  content: "";
  position: absolute;
  inset: 0;
  background: linear-gradient(180deg, 
    rgba(255,255,255,.1) 0%,
    rgba(255,255,255,.03) 100%);
  opacity: 0;
  transition: opacity 0.22s ease;
}

button.filter:hover,
button.reader-btn:hover {
  transform: translateY(-2px);
  border-color: rgba(101,228,255,.6);
  background: rgba(101,228,255,.2);
  box-shadow: 0 8px 24px rgba(101,228,255,.25);
}

button.filter:hover::before,
button.reader-btn:hover::before {
  opacity: 1;
}

button.filter.active {
  transform: translateY(-1px);
  border-color: rgba(101,228,255,.7);
  background: rgba(101,228,255,.25);
  color: var(--text);
}

/* Special button styles for accent buttons */
button.reader-btn.style-pink {
  border-color: rgba(255,112,184,.4);
  background: rgba(255,112,184,.12);
  color: var(--pink);
}

button.reader-btn.style-pink:hover {
  border-color: var(--pink);
  background: rgba(255,112,184,.25);
  color: var(--pink2);
}

button.reader-btn.style-cyan {
  border-color: rgba(101,228,255,.4);
  background: rgba(101,228,255,.12);
  color: var(--cyan);
}

button.reader-btn.style-cyan:hover {
  border-color: var(--cyan);
  background: rgba(101,228,255,.25);
}

input {
  width: 100%;
  border: 0;
  outline: 0;
  background: transparent;
  color: var(--text);
  font: inherit;
  font-size: 1rem;
}

input::placeholder {
  color: #7a88a1;
}

input:focus {
  outline: none;
}

/* ==================== STATS ==================== */
.stats {
  display: grid;
  grid-template-columns: repeat(5, minmax(0, 1fr));
  gap: 14px;
  margin: 28px 0 36px;
}

.stat {
  border: 1px solid var(--line);
  border-radius: 24px;
  padding: 20px;
  background: linear-gradient(145deg, 
    rgba(255,255,255,.09), 
    rgba(255,255,255,.04));
  min-height: 116px;
  transition: all 0.25s ease;
  position: relative;
  overflow: hidden;
}

.stat::before {
  content: "";
  position: absolute;
  top: -50%;
  left: -50%;
  width: 200%;
  height: 200%;
  background: radial-gradient(circle, 
    rgba(101,228,255,.1) 0%, 
    transparent 70%);
  opacity: 0;
  transition: opacity 0.3s ease;
}

.stat:hover {
  transform: translateY(-4px);
  border-color: rgba(101,228,255,.4);
  box-shadow: 0 12px 40px rgba(101,228,255,.2);
}

.stat:hover::before {
  opacity: 0.3;
}

.stat b {
  display: block;
  font-size: 1.55rem;
  line-height: 1.2;
  font-weight: 900;
  letter-spacing: -0.02em;
  background: linear-gradient(135deg, var(--cyan), var(--violet));
  background-clip: text;
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  text-fill-color: transparent;
}

.stat span {
  color: var(--muted2);
  font-size: .86rem;
  font-weight: 500;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  margin-top: 8px;
  display: block;
}
/* ==================== CARDS GRID ==================== */
.grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(310px, 1fr));
  gap: 20px;
  padding: 12px 0 80px;
}

.card {
  position: relative;
  overflow: hidden;
  min-height: 252px;
  padding: 24px;
  border-radius: 30px;
  background: linear-gradient(145deg, 
    rgba(19,28,48,.98), 
    rgba(11,16,30,.92));
  border: 1px solid var(--line);
  box-shadow: 
    0 12px 48px rgba(0,0,0,.45),
    inset 0 1px 0 rgba(255,255,255,.04);
  transition: 
    transform 0.3s cubic-bezier(0.4, 0, 0.2, 1),
    border-color 0.25s ease,
    box-shadow 0.3s ease;
}

.card::before {
  content: "";
  position: absolute;
  inset: -1px;
  opacity: 0.65;
  background: 
    radial-gradient(circle at top right, 
      rgba(101,228,255,.24), 
      transparent 48%),
    radial-gradient(circle at bottom left, 
      rgba(255,112,184,.18), 
      transparent 45%);
  pointer-events: none;
  transition: opacity 0.3s ease;
}

.card::after {
  content: "";
  position: absolute;
  inset: -2px;
  border-radius: 32px;
  border: 1px solid transparent;
  background: linear-gradient(145deg, 
    rgba(255,255,255,.12), 
    rgba(255,255,255,.04));
  opacity: 0;
  transition: opacity 0.25s ease, border-color 0.25s ease;
  z-index: -1;
}

.card:hover {
  transform: translateY(-6px) scale(1.01);
  border-color: rgba(101,228,255,.55);
  box-shadow: 
    0 20px 70px rgba(0,0,0,.55),
    0 8px 32px rgba(101,228,255,.15);
}

.card:hover::before {
  opacity: 0.85;
}

.card:hover::after {
  opacity: 1;
  border-color: rgba(101,228,255,.2);
}

.card.chain {
  border-color: rgba(255,211,106,.38);
}

.card.chain::before {
  background: 
    radial-gradient(circle at top right, 
      rgba(255,211,106,.28), 
      transparent 48%),
    radial-gradient(circle at bottom left, 
      rgba(184,156,255,.22), 
      transparent 45%);
}

.card.chain:hover {
  border-color: rgba(255,211,106,.6);
  box-shadow: 
    0 20px 70px rgba(0,0,0,.55),
    0 8px 32px rgba(255,211,106,.25);
}

.card > * {
  position: relative;
}

/* Card animation on load */
@keyframes cardIn {
  from {
    opacity: 0;
    transform: translateY(30px);
  }
  to {
    opacity: 1;
    transform: translateY(0);
  }
}

.card {
  animation: cardIn 0.4s ease-out backwards;
}

.card:nth-child(1) { animation-delay: 0.02s; }
.card:nth-child(2) { animation-delay: 0.04s; }
.card:nth-child(3) { animation-delay: 0.06s; }
.card:nth-child(4) { animation-delay: 0.08s; }
.card:nth-child(5) { animation-delay: 0.1s; }
.card:nth-child(6) { animation-delay: 0.12s; }
.card:nth-child(7) { animation-delay: 0.14s; }
.card:nth-child(8) { animation-delay: 0.16s; }
.card:nth-child(9) { animation-delay: 0.18s; }
.card:nth-child(10) { animation-delay: 0.2s; }
.card:nth-child(11) { animation-delay: 0.22s; }
.card:nth-child(12) { animation-delay: 0.24s; }

.num {
  display: inline-flex;
  align-items: center;
  gap: 9px;
  color: var(--cyan);
  font-weight: 900;
  letter-spacing: 0.08em;
  font-size: 0.95rem;
  transition: color 0.2s ease;
}

.card:hover .num {
  color: var(--cyan2);
}

.num::before {
  content: "";
  width: 10px;
  height: 10px;
  border-radius: 50%;
  background: var(--green);
  box-shadow: 
    0 0 20px var(--green),
    0 0 40px var(--green2);
  animation: pulse 3s ease-in-out infinite;
}

.card h2 {
  margin: 16px 0 12px;
  font-size: 1.38rem;
  line-height: 1.14;
  letter-spacing: -0.04em;
  color: var(--text);
  transition: color 0.2s ease;
}

.card:hover h2 {
  color: var(--text2);
}

.card p {
  margin: 0 0 22px;
  color: var(--muted2);
  line-height: 1.55;
  font-size: 0.95rem;
}

.tags, .meta-tags {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}

.tag {
  color: #e2efff;
  border: 1px solid rgba(255,255,255,.16);
  background: rgba(255,255,255,.06);
  border-radius: 999px;
  padding: 6px 11px;
  font-size: .76rem;
  font-weight: 800;
  letter-spacing: 0.04em;
  transition: all 0.2s ease;
  backdrop-filter: blur(10px);
}

.tag:hover {
  border-color: rgba(101,228,255,.4);
  background: rgba(101,228,255,.12);
  color: var(--cyan);
  transform: translateY(-1px);
}

.tag-routing {
  border-color: rgba(184,156,255,.3);
  background: rgba(184,156,255,.1);
  color: rgba(184,156,255,.9);
}

.tag-transport {
  border-color: rgba(255,211,106,.3);
  background: rgba(255,211,106,.1);
  color: rgba(255,211,106,.9);
}

.tag-application {
  border-color: rgba(255,112,184,.3);
  background: rgba(255,112,184,.1);
  color: rgba(255,112,184,.9);
}

.tag-security {
  border-color: rgba(125,255,168,.3);
  background: rgba(125,255,168,.1);
  color: rgba(125,255,168,.9);
}

.tag-monitoring {
  border-color: rgba(101,228,255,.3);
  background: rgba(101,228,255,.1);
  color: rgba(101,228,255,.9);
}

.tag-update-chain {
  color: #1b1300;
  border-color: rgba(255,211,106,.8);
  background: linear-gradient(135deg, var(--amber), #ff9f6a);
  font-weight: 900;
  box-shadow: 0 4px 16px rgba(255,211,106,.25);
}

.open {
  display: inline-flex;
  margin-top: 22px;
  color: var(--text);
  font-weight: 900;
  font-size: 0.95rem;
  letter-spacing: 0.04em;
  transition: all 0.2s ease;
}

.open::after {
  content: "→";
  margin-left: 9px;
  color: var(--pink);
  transition: transform 0.2s ease, color 0.2s ease;
}

.open:hover {
  color: var(--cyan);
}

.open:hover::after {
  transform: translateX(4px);
  color: var(--pink2);
}

.empty {
  display: none;
  color: var(--muted);
  padding: 48px 0 90px;
  text-align: center;
  font-size: 1.1rem;
}

.empty.display {
  display: block;
  animation: slideUp 0.4s ease-out;
}
.toplink {
  color: var(--cyan);
  font-weight: 900;
  font-size: 0.9rem;
  transition: all 0.2s ease;
}

.toplink:hover {
  color: var(--cyan2);
  text-shadow: 0 0 12px rgba(101,228,255,.5);
}

.progress {
  position: fixed;
  top: 0;
  left: 0;
  height: 4px;
  width: 0;
  z-index: 20;
  background: linear-gradient(90deg, var(--cyan), var(--violet), var(--pink), var(--amber));
  background-size: 400% 100%;
  box-shadow: 0 0 28px rgba(101,228,255,.7);
  transition: width 0.3s ease;
  animation: shimmer 8s linear infinite;
}

/* ==================== DOC LAYOUT ==================== */
.doc-layout {
  width: min(1160px, calc(100% - 32px));
  margin: 0 auto;
  padding: 40px 0 90px;
  animation: slideUp 0.5s ease-out;
}

.reader-tools {
  display: flex;
  flex-wrap: wrap;
  gap: 12px;
  align-items: center;
  justify-content: space-between;
  margin: 20px 0;
  padding: 14px 16px;
  border: 1px solid var(--line);
  border-radius: 999px;
  background: var(--glass2);
  backdrop-filter: blur(16px);
  box-shadow: 0 8px 32px rgba(0,0,0,.2);
}

.reader-tools .group {
  display: flex;
  flex-wrap: wrap;
  gap: 10px;
}

.doc-hero {
  margin: 24px 0 28px;
  padding: 32px 36px;
  border: 1px solid var(--line);
  border-radius: 32px;
  background: linear-gradient(145deg, 
    rgba(19,28,48,.98), 
    rgba(12,17,31,.92));
  box-shadow: 
    0 12px 50px rgba(0,0,0,.45),
    inset 0 1px 0 rgba(255,255,255,.04);
  position: relative;
  overflow: hidden;
}

.doc-hero::before {
  content: "";
  position: absolute;
  inset: -1px;
  opacity: 0.5;
  background: 
    radial-gradient(circle at top right, 
      rgba(101,228,255,.18), 
      transparent 45%),
    radial-gradient(circle at bottom left, 
      rgba(184,156,255,.14), 
      transparent 42%);
  pointer-events: none;
}

.doc-hero h1 {
  font-size: clamp(2.1rem, 5.5vw, 5rem);
  max-width: none;
  line-height: 1.05;
  letter-spacing: -0.06em;
  margin: 0 0 12px;
  color: var(--text);
  background: linear-gradient(135deg, var(--text), var(--cyan));
  background-clip: text;
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  text-fill-color: transparent;
}

.doc-hero .eyebrow {
  margin-bottom: 12px;
  animation: none;
  background: rgba(101,228,255,.08);
  border: 1px solid rgba(101,228,255,.2);
}

.note {
  margin: 20px 0 0;
  padding: 18px 22px;
  border-left: 4px solid var(--cyan);
  border-radius: 16px;
  color: #e2efff;
  background: rgba(101,228,255,.07);
  box-shadow: 0 4px 20px rgba(101,228,255,.1);
  font-size: 0.98rem;
  line-height: 1.6;
}

.reader-grid {
  display: grid;
  grid-template-columns: minmax(0, 1fr) 280px;
  gap: 20px;
  align-items: start;
}

.doc-body {
  position: relative;
  isolation: isolate;
  overflow: hidden;
  padding: 38px 40px;
  border: 1px solid var(--line);
  border-radius: 30px;
  background: rgba(6,9,17,.88);
  box-shadow: 
    0 28px 100px rgba(0,0,0,.45),
    inset 0 1px 0 rgba(255,255,255,.03);
}

.doc-body.focus {
  max-width: 840px;
  margin: 0 auto;
  font-size: 1.06rem;
  line-height: 1.8;
}

.doc-body::before {
  content: "";
  position: absolute;
  inset: -1px;
  z-index: 0;
  opacity: 0.4;
  background: 
    radial-gradient(circle at top right, 
      rgba(101,228,255,.12), 
      transparent 45%),
    radial-gradient(circle at bottom left, 
      rgba(184,156,255,.1), 
      transparent 42%);
  pointer-events: none;
  border-radius: 31px;
}

.doc-body > * {
  position: relative;
  z-index: 1;
}

.doc-body pre {
  white-space: pre-wrap;
  color: #e2efff;
  font: .93rem/1.72 "IBM Plex Mono", "SFMono-Regular", Consolas, "Liberation Mono", monospace;
  background: transparent;
  padding: 0;
  border-radius: 0;
  margin: 0;
  overflow-x: auto;
}

.doc-body.comfy pre,
.doc-body.comfy {
  font-size: 1.08rem;
  line-height: 1.8;
}

.doc-body table {
  max-width: 100%;
  border-collapse: collapse;
  margin: 18px 0;
}

.doc-body table th,
.doc-body table td {
  padding: 10px 14px;
  border: 1px solid var(--line2);
}

.doc-body table th {
  background: var(--glass);
  color: var(--cyan);
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  font-size: 0.85rem;
}

.doc-body, .doc-body p, .doc-body td, .doc-body li, .doc-body pre {
  color: #e2efff;
  line-height: 1.7;
}

.doc-body a {
  color: var(--cyan);
  text-decoration: underline;
  text-underline-offset: 3px;
  transition: all 0.2s ease;
}

.doc-body a:hover {
  color: var(--cyan2);
  text-shadow: 0 0 12px rgba(101,228,255,.4);
}

.doc-body a[href^="#section-"] {
  display: inline-block;
  padding: 0.02rem 0.44rem;
  border-radius: 999px;
  background: rgba(101,228,255,.1);
  box-shadow: inset 0 0 0 1px rgba(101,228,255,.18);
  text-decoration: none;
  font-weight: 800;
}

.doc-body a[href^="#page-"] {
  color: var(--muted);
  text-decoration-color: rgba(255,255,255,.24);
}

.doc-body a.rfc-local {
  color: var(--green);
  font-weight: 900;
  text-decoration-color: rgba(125,255,168,.55);
}

.doc-body a.rfc-external {
  color: var(--amber);
  font-weight: 900;
  text-decoration-style: dotted;
}

.doc-body a.rfc-local:after {
  content: " local";
  font-size: .68em;
  color: var(--green);
  text-transform: uppercase;
  margin-left: .25em;
}

.doc-body a.rfc-external:after {
  content: " external";
  font-size: .68em;
  color: var(--amber);
  text-transform: uppercase;
  margin-left: .25em;
}

.doc-body h1, .doc-body h2, .doc-body h3 {
  color: var(--text);
  margin: 24px 0 16px;
  line-height: 1.2;
}

.doc-body h1 {
  font-size: clamp(2rem, 4vw, 3.2rem);
  border-bottom: 2px solid var(--line);
  padding-bottom: 12px;
}

.doc-body h2 {
  font-size: clamp(1.5rem, 3vw, 2.1rem);
  border-bottom: 1px solid var(--line2);
  padding-bottom: 8px;
  color: var(--cyan);
}

.doc-body h3 {
  font-size: 1.35rem;
  color: var(--violet);
}

.source-banner {
  display: grid;
  grid-template-columns: minmax(0, 1.45fr) minmax(220px, .95fr);
  gap: 18px;
  margin: 0 0 22px;
  padding: 22px 24px;
  border: 1px solid rgba(101,228,255,.2);
  border-radius: 24px;
  background:
    linear-gradient(145deg, rgba(101,228,255,.11), rgba(184,156,255,.08)),
    rgba(8,12,24,.82);
  box-shadow:
    0 16px 48px rgba(0,0,0,.28),
    inset 0 1px 0 rgba(255,255,255,.05);
}

.source-kicker {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 10px;
  color: var(--cyan);
  font-size: .78rem;
  font-weight: 900;
  letter-spacing: .16em;
  text-transform: uppercase;
}

.source-kicker::before {
  content: "";
  width: 10px;
  height: 10px;
  border-radius: 999px;
  background: linear-gradient(135deg, var(--cyan), var(--violet));
  box-shadow: 0 0 14px rgba(101,228,255,.45);
}

.source-banner strong {
  display: block;
  margin-bottom: 8px;
  font-size: 1.22rem;
  line-height: 1.2;
  color: var(--text);
}

.source-banner p {
  margin: 0;
  color: var(--text2);
  max-width: 60ch;
}

.source-meta {
  display: flex;
  flex-wrap: wrap;
  align-content: start;
  gap: 10px;
  justify-content: flex-end;
}

.source-chip {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  min-height: 42px;
  padding: 10px 14px;
  border: 1px solid rgba(255,255,255,.1);
  border-radius: 999px;
  background: rgba(7,10,19,.56);
  color: var(--text2);
  font-size: .85rem;
  font-weight: 700;
  letter-spacing: .02em;
}

.source-chip::before {
  content: "";
  width: 8px;
  height: 8px;
  border-radius: 999px;
  background: var(--amber);
  box-shadow: 0 0 12px rgba(255,211,106,.35);
}

.rfc-source-shell {
  display: grid;
  gap: 18px;
}

.rfc-page {
  position: relative;
  padding: 20px 22px 24px;
  border: 1px solid rgba(255,255,255,.09);
  border-radius: 26px;
  background:
    linear-gradient(180deg, rgba(255,255,255,.035), rgba(255,255,255,.015)),
    rgba(10,14,28,.82);
  box-shadow:
    0 18px 46px rgba(0,0,0,.28),
    inset 0 1px 0 rgba(255,255,255,.04);
  overflow: hidden;
}

.rfc-page::before {
  content: "";
  position: absolute;
  inset: 0 auto 0 0;
  width: 4px;
  background: linear-gradient(180deg, var(--cyan), var(--violet));
  opacity: .9;
}

.rfc-page.is-cover {
  background:
    radial-gradient(circle at top right, rgba(101,228,255,.08), transparent 34%),
    linear-gradient(180deg, rgba(255,255,255,.045), rgba(255,255,255,.018)),
    rgba(10,14,28,.9);
}

.rfc-page.is-contents::after {
  content: "jump links live here";
  position: absolute;
  top: 18px;
  right: 18px;
  padding: 7px 10px;
  border-radius: 999px;
  border: 1px solid rgba(101,228,255,.18);
  background: rgba(101,228,255,.08);
  color: var(--cyan);
  font-size: .7rem;
  font-weight: 900;
  letter-spacing: .14em;
  text-transform: uppercase;
}

.rfc-page-top {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  margin: 0 0 14px;
}

.rfc-page-label {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  padding: 8px 12px;
  border-radius: 999px;
  border: 1px solid rgba(255,255,255,.1);
  background: rgba(7,11,20,.62);
  color: var(--text2);
  font-size: .74rem;
  font-weight: 900;
  letter-spacing: .16em;
  text-transform: uppercase;
}

.rfc-page-label::before {
  content: "";
  width: 7px;
  height: 7px;
  border-radius: 999px;
  background: var(--green);
  box-shadow: 0 0 10px rgba(125,255,168,.38);
}

.rfc-page-meta {
  margin: 0 0 18px;
  padding: 14px 16px;
  border: 1px solid rgba(255,255,255,.08);
  border-radius: 18px;
  background: rgba(255,255,255,.03);
  color: var(--muted);
  font-size: .82rem;
  line-height: 1.75;
}

.rfc-page-meta a:not([href]) {
  color: var(--muted);
  text-decoration: none;
  border-bottom: 1px dashed rgba(255,255,255,.12);
}

.rfc-page-meta a[href] {
  font-weight: 700;
}

.rfc-page pre + pre,
.rfc-page details + pre,
.rfc-page pre + details,
.rfc-page details + details {
  margin-top: 16px;
}

.rfc-page .header-reference-panel,
.rfc-page .arp-flowchart-panel,
.rfc-page .modern-ascii-diagram {
  margin-top: 20px;
  margin-bottom: 20px;
}

.modern-ascii-diagram {
  position: relative;
  padding: 22px;
  border: 1px solid rgba(101,228,255,.26);
  border-radius: 26px;
  background:
    radial-gradient(circle at 16% 12%, rgba(101,228,255,.22), transparent 32%),
    radial-gradient(circle at 86% 18%, rgba(184,156,255,.2), transparent 34%),
    linear-gradient(145deg, rgba(9,15,32,.96), rgba(5,8,18,.94));
  box-shadow:
    0 22px 70px rgba(0,0,0,.34),
    inset 0 1px 0 rgba(255,255,255,.08),
    0 0 42px rgba(101,228,255,.08);
  overflow: hidden;
}

.modern-ascii-diagram::before {
  content: "";
  position: absolute;
  inset: -40% -20% auto;
  height: 120px;
  background: linear-gradient(90deg, transparent, rgba(101,228,255,.2), transparent);
  transform: rotate(-8deg);
}

.modern-diagram-kicker {
  position: relative;
  display: inline-flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 14px;
  color: var(--cyan);
  font-size: .76rem;
  font-weight: 900;
  letter-spacing: .16em;
  text-transform: uppercase;
}

.modern-diagram-kicker::before {
  content: "";
  width: 9px;
  height: 9px;
  border-radius: 999px;
  background: linear-gradient(135deg, var(--cyan), var(--violet));
  box-shadow: 0 0 16px rgba(101,228,255,.55);
}

.modern-diagram-grid {
  position: relative;
  display: grid;
  gap: 9px;
}

.modern-diagram-row {
  display: grid;
  grid-template-columns: repeat(var(--cell-count, 1), minmax(0, 1fr));
  gap: 9px;
}

.modern-diagram-cell {
  min-height: 48px;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 10px 12px;
  border: 1px solid rgba(255,255,255,.12);
  border-radius: 15px;
  background:
    linear-gradient(180deg, rgba(255,255,255,.08), rgba(255,255,255,.03)),
    rgba(101,228,255,.06);
  color: #f6fbff;
  text-align: center;
  font: 800 .82rem/1.25 Inter, system-ui, sans-serif;
  box-shadow: inset 0 1px 0 rgba(255,255,255,.08);
}

.modern-diagram-row:nth-child(5n+1) .modern-diagram-cell { border-color: rgba(101,228,255,.28); }
.modern-diagram-row:nth-child(5n+2) .modern-diagram-cell { border-color: rgba(184,156,255,.26); }
.modern-diagram-row:nth-child(5n+3) .modern-diagram-cell { border-color: rgba(125,255,168,.24); }
.modern-diagram-row:nth-child(5n+4) .modern-diagram-cell { border-color: rgba(255,211,106,.24); }
.modern-diagram-row:nth-child(5n+5) .modern-diagram-cell { border-color: rgba(255,111,145,.24); }

.modern-diagram-fallback {
  white-space: pre-wrap;
  color: #e2efff;
  font: .86rem/1.55 "IBM Plex Mono", "SFMono-Regular", Consolas, monospace;
}

.doc-body.focus .rfc-source-shell {
  max-width: 78ch;
  margin: 0 auto;
}

.doc-body.comfy .rfc-page {
  padding: 22px 24px 28px;
}

.doc-body.comfy .rfc-page pre {
  font-size: .99rem;
  line-height: 1.82;
}

.toc-panel {
  position: sticky;
  top: 102px;
  max-height: calc(100vh - 140px);
  overflow: auto;
  padding: 20px;
  border: 1px solid var(--line);
  border-radius: 26px;
  background: var(--glass2);
  backdrop-filter: blur(20px);
  box-shadow: 0 12px 40px rgba(0,0,0,.3);
}

.toc-panel::-webkit-scrollbar {
  width: 6px;
}

.toc-panel::-webkit-scrollbar-track {
  background: transparent;
  border-radius: 3px;
}

.toc-panel::-webkit-scrollbar-thumb {
  background: rgba(101,228,255,.3);
  border-radius: 3px;
}

.toc-panel::-webkit-scrollbar-thumb:hover {
  background: rgba(101,228,255,.5);
}

.toc-panel h2 {
  margin: 16px 0 14px;
  font-size: .92rem;
  color: var(--cyan);
  text-transform: uppercase;
  letter-spacing: .16em;
  font-weight: 800;
  padding-bottom: 10px;
  border-bottom: 1px solid var(--line2);
}

.toc-panel a {
  display: block;
  color: var(--muted2);
  font-size: .88rem;
  line-height: 1.35;
  padding: 9px 8px;
  border-bottom: 1px solid var(--line2);
  border-radius: 8px;
  transition: all 0.2s ease;
}

.toc-panel a:hover {
  color: var(--cyan);
  background: rgba(101,228,255,.08);
  padding-left: 14px;
  border-left: 3px solid var(--cyan);
}

.toc-panel .muted {
  color: var(--muted);
  font-size: .86rem;
  padding: 12px 8px;
  font-style: italic;
}
.header-reference-panel,
.detection-questions-panel {
  margin: 0 0 20px;
  border: 1px solid rgba(101,228,255,.28);
  border-radius: 22px;
  background: linear-gradient(145deg, 
    rgba(101,228,255,.12), 
    rgba(255,112,184,.06));
  overflow: hidden;
  box-shadow: 0 8px 32px rgba(101,228,255,.15);
}

.doc-body > .header-reference-panel.inline-header-reference {
  margin: 28px 0 34px;
  box-shadow: 
    0 20px 60px rgba(0,0,0,.35),
    inset 0 1px 0 rgba(255,255,255,.06);
  animation: slideUp 0.5s ease-out;
}

.doc-body > .header-reference-panel.inline-header-reference summary strong {
  font-size: 1.1rem;
  color: var(--text);
}

.doc-body > .header-reference-panel.inline-header-reference .header-note {
  font-size: .94rem;
  color: var(--text2);
}

.doc-body > .header-reference-panel.inline-header-reference .header-diagram-wrap {
  margin-bottom: 20px;
  padding: 14px;
  border-radius: 16px;
  background: rgba(5,7,17,.4);
}

.doc-body > .header-reference-panel.inline-header-reference .header-field-table {
  font-size: .84rem;
  line-height: 1.45;
}
.arp-flowchart-panel {
  position: relative;
  margin: 32px 0 38px;
  padding: 28px;
  border: 1px solid rgba(101,228,255,.35);
  border-radius: 30px;
  overflow: hidden;
  background: 
    radial-gradient(circle at 10% 0%, 
      rgba(101,228,255,.26), 
      transparent 35%),
    radial-gradient(circle at 90% 10%, 
      rgba(255,112,184,.22), 
      transparent 36%),
    linear-gradient(145deg, 
      rgba(11,18,33,.99), 
      rgba(17,22,44,.94));
  box-shadow: 
    0 28px 90px rgba(0,0,0,.42),
    inset 0 1px 0 rgba(255,255,255,.08);
  animation: slideUp 0.6s ease-out;
}

.arp-flowchart-panel:before {
  content: "";
  position: absolute;
  inset: -40%;
  background: conic-gradient(from 120deg, 
    transparent, 
    rgba(101,228,255,.12), 
    transparent, 
    rgba(255,112,184,.1), 
    transparent);
  animation: arpGlow 16s linear infinite;
  opacity: 0.8;
}

.arp-flowchart-panel > * {
  position: relative;
  z-index: 1;
}

.arp-flowchart-kicker {
  display: inline-flex;
  align-items: center;
  gap: 9px;
  padding: 7px 12px;
  border: 1px solid rgba(101,228,255,.32);
  border-radius: 999px;
  color: var(--cyan);
  background: rgba(101,228,255,.1);
  font-size: .72rem;
  font-weight: 900;
  letter-spacing: .16em;
  text-transform: uppercase;
  backdrop-filter: blur(10px);
}

.arp-flowchart-panel h2 {
  margin: 16px 0 10px;
  color: var(--text);
  font-size: clamp(1.4rem, 3.2vw, 2.25rem);
  line-height: 1.15;
  letter-spacing: -0.04em;
}

.arp-flowchart-panel .flow-subtitle {
  margin: 0 0 20px;
  color: #d0dfff;
  max-width: 880px;
  line-height: 1.6;
  font-size: 1.02rem;
}
.arp-flow { display:grid; grid-template-columns: repeat(12, minmax(0, 1fr)); gap: 14px; align-items:stretch; }
.flow-node {
  position: relative;
  min-height: 96px;
  padding: 16px;
  border: 1px solid rgba(255,255,255,.16);
  border-radius: 22px;
  background: linear-gradient(145deg, 
    rgba(255,255,255,.09), 
    rgba(255,255,255,.04));
  box-shadow: 
    inset 0 1px 0 rgba(255,255,255,.08),
    0 4px 16px rgba(0,0,0,.2);
  transition: all 0.25s ease;
}

.flow-node:hover {
  transform: translateY(-2px);
  box-shadow: 
    inset 0 1px 0 rgba(255,255,255,.12),
    0 8px 28px rgba(0,0,0,.35);
}

.flow-node strong {
  display: block;
  color: #f8fbff;
  font-size: .98rem;
  line-height: 1.22;
  font-weight: 800;
  margin-bottom: 6px;
}

.flow-node small {
  display: block;
  margin-top: 8px;
  color: #c0d0e8;
  line-height: 1.4;
  font-size: 0.86rem;
}

.flow-node code {
  color: #ffeb88;
  font-weight: 900;
  font-size: 0.9rem;
}

.flow-node.start {
  grid-column: span 12;
  min-height: auto;
  border-color: rgba(125,255,168,.35);
  background: linear-gradient(90deg, 
    rgba(125,255,168,.18), 
    rgba(101,228,255,.12));
  box-shadow: 0 0 24px rgba(125,255,168,.2);
}

.flow-node.decision {
  grid-column: span 4;
  border-color: rgba(101,228,255,.4);
  background: linear-gradient(145deg, 
    rgba(101,228,255,.18), 
    rgba(184,156,255,.1));
}

.flow-node.action {
  grid-column: span 4;
  border-color: rgba(184,156,255,.32);
  background: linear-gradient(145deg, 
    rgba(184,156,255,.12), 
    rgba(255,255,255,.04));
}

.flow-node.merge {
  grid-column: span 8;
  border-color: rgba(255,211,106,.35);
  background: linear-gradient(145deg, 
    rgba(255,211,106,.16), 
    rgba(255,112,184,.09));
}

.flow-node.reply {
  grid-column: span 6;
  border-color: rgba(125,255,168,.38);
  background: linear-gradient(145deg, 
    rgba(125,255,168,.16), 
    rgba(101,228,255,.1));
}

.flow-node.stop {
  grid-column: span 4;
  border-color: rgba(255,112,184,.35);
  background: linear-gradient(145deg, 
    rgba(255,112,184,.2), 
    rgba(255,255,255,.04));
}

.flow-pill {
  display: inline-flex;
  margin-bottom: 10px;
  padding: 5px 10px;
  border-radius: 999px;
  background: rgba(0,0,0,.3);
  color: var(--cyan);
  font-size: .66rem;
  font-weight: 900;
  letter-spacing: .14em;
  text-transform: uppercase;
  backdrop-filter: blur(10px);
}

.flow-node.stop .flow-pill { color: var(--pink); }
.flow-node.reply .flow-pill { color: var(--green); }
.flow-node.merge .flow-pill { color: var(--amber); }

.flow-arrow {
  grid-column: span 12;
  text-align: center;
  color: var(--cyan);
  font-weight: 900;
  letter-spacing: .2em;
  text-transform: uppercase;
  font-size: .72rem;
  opacity: 0.95;
  padding: 8px 0;
}

.flow-branch {
  display: grid;
  grid-column: span 12;
  grid-template-columns: repeat(12, minmax(0, 1fr));
  gap: 16px;
  margin: 4px 0;
}

.flow-branch .yes-line {
  grid-column: span 8;
  padding: 10px 14px;
  border-left: 3px solid rgba(125,255,168,.6);
  color: var(--green);
  font-size: .74rem;
  font-weight: 900;
  text-transform: uppercase;
  letter-spacing: .16em;
  background: rgba(125,255,168,.08);
}

.flow-branch .no-line {
  grid-column: span 4;
  padding: 10px 14px;
  border-left: 3px solid rgba(255,112,184,.6);
  color: var(--pink);
  font-size: .74rem;
  font-weight: 900;
  text-transform: uppercase;
  letter-spacing: .16em;
  background: rgba(255,112,184,.08);
}
@keyframes arpGlow { to { transform: rotate(1turn); } }
.header-reference-panel summary,
.detection-questions-panel summary {
  cursor: pointer;
  list-style: none;
  padding: 16px 18px;
  border-bottom: 1px solid var(--line2);
  transition: background 0.2s ease;
}

.header-reference-panel summary:hover,
.detection-questions-panel summary:hover {
  background: rgba(101,228,255,.08);
}

.header-reference-panel summary::-webkit-details-marker,
.detection-questions-panel summary::-webkit-details-marker {
  display: none;
}

.header-reference-panel summary span,
.detection-questions-panel summary span {
  display: block;
  color: var(--cyan);
  text-transform: uppercase;
  letter-spacing: .16em;
  font-size: .68rem;
  font-weight: 900;
}

.header-reference-panel summary strong,
.detection-questions-panel summary strong {
  display: block;
  margin-top: 6px;
  color: var(--text);
  font-size: 1rem;
  line-height: 1.2;
  font-weight: 700;
}

.header-reference-panel summary:after,
.detection-questions-panel summary:after {
  content: "▾";
  float: right;
  margin-top: -28px;
  color: var(--pink);
  font-weight: 900;
  font-size: 1.1rem;
  transition: transform 0.2s ease, color 0.2s ease;
}

.header-reference-panel[open] summary:after,
.detection-questions-panel[open] summary:after {
  transform: rotate(180deg);
  color: var(--cyan);
}

.header-reference-panel:not([open]) summary,
.detection-questions-panel:not([open]) summary {
  border-bottom: 0;
}

.header-reference-panel:not([open]) summary:after,
.detection-questions-panel:not([open]) summary:after {
  content: "▸";
  color: var(--muted);
}

.header-note {
  margin: 14px 16px;
  color: #e2efff;
  font-size: .88rem;
  line-height: 1.5;
}

.detection-questions-panel ol {
  margin: 14px 18px 18px 36px;
  color: var(--text2);
  font-size: .9rem;
}

.detection-questions-panel li + li {
  margin-top: 8px;
}
.bit-axis {
  margin: 0 16px 8px;
  color: var(--muted2);
  font-size: .74rem;
  font-weight: 900;
  letter-spacing: .1em;
  text-transform: uppercase;
}

.header-diagram-wrap {
  margin: 0 14px 18px;
  overflow-x: auto;
  padding: 14px;
  border: 1px solid rgba(255,255,255,.14);
  border-radius: 18px;
  background: rgba(5,7,17,.65);
  box-shadow: inset 0 8px 24px rgba(0,0,0,.3);
}

.header-bit-layout {
  min-width: 340px;
  width: 100%;
  height: auto;
  display: block;
}

.bit-label {
  fill: #a8b8d4;
  font: 10.5px ui-monospace, SFMono-Regular, Consolas, monospace;
  font-weight: 600;
}

.bit-grid {
  stroke: rgba(255,255,255,.18);
  stroke-width: 1.2;
}

.field-block {
  stroke: rgba(255,255,255,.32);
  stroke-width: 1.2;
}

.field-0 { fill: rgba(101,228,255,.42); }
.field-1 { fill: rgba(184,156,255,.42); }
.field-2 { fill: rgba(255,112,184,.36); }
.field-3 { fill: rgba(125,255,168,.32); }
.field-4 { fill: rgba(255,211,106,.36); }

.field-label {
  fill: #fcfdff;
  font: 9.5px ui-monospace, SFMono-Regular, Consolas, monospace;
  font-weight: 800;
  pointer-events: none;
  text-shadow: 0 2px 4px rgba(0,0,0,.4);
}

.header-field-table {
  width: calc(100% - 28px);
  margin: 0 14px 18px;
  border-collapse: collapse;
  font-size: .78rem;
  line-height: 1.4;
}

.header-field-table th,
.header-field-table td {
  padding: 9px 8px;
  border-top: 1px solid var(--line2);
  vertical-align: top;
}

.header-field-table th {
  color: var(--cyan);
  text-align: left;
  font-size: .72rem;
  text-transform: uppercase;
  letter-spacing: .1em;
  font-weight: 800;
  background: rgba(101,228,255,.06);
  padding: 10px 10px;
}

.header-field-table td:nth-child(2) {
  color: var(--amber);
  font-weight: 900;
  white-space: nowrap;
  font-variant-numeric: tabular-nums;
}

.header-field-table td:nth-child(3) {
  color: var(--text2);
  font-size: 0.88em;
}
footer {
  color: var(--muted2);
  border-top: 1px solid var(--line);
  padding: 32px 0 56px;
  text-align: center;
  font-size: 0.9rem;
}

footer .shell {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 8px;
}

/* ==================== FLASHCARD STYLES ==================== */
.study-overlay {
  position: fixed;
  top: 0;
  left: 0;
  width: 100vw;
  height: 100vh;
  background: var(--bg);
  z-index: 9999;
  display: none;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: 24px;
  backdrop-filter: blur(20px);
}

.study-overlay::before {
  content: "";
  position: fixed;
  inset: 0;
  background: radial-gradient(circle at center, 
    rgba(7,9,18,0.95), 
    rgba(7,9,18,0.85));
  backdrop-filter: blur(12px);
}

.study-overlay.active {
  display: flex;
  animation: fadeIn 0.3s ease;
}

@keyframes fadeIn {
  from { opacity: 0; }
  to { opacity: 1; }
}

.study-header {
  position: absolute;
  top: 24px;
  width: min(840px, 100%);
  display: flex;
  justify-content: space-between;
  align-items: center;
  color: var(--muted2);
  font-size: 0.95rem;
  font-weight: 600;
}

.study-progress-bar {
  position: absolute;
  top: 0;
  left: 0;
  height: 5px;
  background: linear-gradient(90deg, var(--cyan), var(--violet), var(--pink));
  background-size: 200% 100%;
  transition: width 0.3s ease;
  animation: shimmer 10s linear infinite;
  box-shadow: 0 0 28px rgba(101,228,255,.6);
}

.card-container {
  width: min(640px, 100%);
  height: 420px;
  perspective: 1200px;
  cursor: pointer;
}

.flashcard {
  position: relative;
  width: 100%;
  height: 100%;
  text-align: center;
  transition: transform 0.6s cubic-bezier(0.4, 0, 0.2, 1);
  transform-style: preserve-3d;
}

.card-container.flipped .flashcard {
  transform: rotateY(180deg);
}

.card-face {
  position: absolute;
  width: 100%;
  height: 100%;
  backface-visibility: hidden;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: 44px;
  border-radius: 34px;
  border: 2px solid var(--line);
  background: var(--panel);
  box-shadow: 
    0 36px 120px rgba(0,0,0,0.6),
    inset 0 2px 0 rgba(255,255,255,.04);
  transition: all 0.3s ease;
}

.card-face:hover {
  box-shadow: 
    0 40px 140px rgba(0,0,0,0.7),
    inset 0 2px 0 rgba(255,255,255,.06);
}

.card-back {
  transform: rotateY(180deg);
  border-color: var(--cyan);
  background: linear-gradient(145deg, 
    rgba(14,20,36,0.98), 
    rgba(11,16,30,0.94));
}

.card-category {
  position: absolute;
  top: 32px;
  font-size: 0.72rem;
  text-transform: uppercase;
  letter-spacing: 0.24em;
  color: var(--cyan);
  font-weight: 800;
}

.card-prompt {
  font-size: 1.9rem;
  font-weight: 800;
  line-height: 1.18;
  margin: 24px 0;
  color: var(--text);
}

.card-answer {
  font-size: 1.15rem;
  line-height: 1.65;
  color: var(--text2);
  max-width: 100%;
  overflow-y: auto;
  padding-right: 8px;
}

.card-meta {
  position: absolute;
  bottom: 32px;
  font-size: 0.74rem;
  color: var(--muted2);
  letter-spacing: 0.08em;
}

.study-actions {
  margin-top: 44px;
  display: none;
  gap: 18px;
}

.study-actions.visible {
  display: flex;
  animation: slideUp 0.3s ease-out;
}

.srs-btn {
  padding: 14px 28px;
  border-radius: 999px;
  border: none;
  font-weight: 900;
  cursor: pointer;
  font-size: 1rem;
  transition: all 0.25s cubic-bezier(0.4, 0, 0.2, 1);
  letter-spacing: 0.04em;
  box-shadow: 0 8px 24px rgba(0,0,0,0.4);
}

.srs-btn:hover {
  transform: translateY(-3px);
  box-shadow: 0 12px 36px rgba(0,0,0,0.6);
}

.srs-btn:active {
  transform: translateY(-1px);
}

.btn-again {
  background: linear-gradient(145deg, var(--pink), var(--pink2));
  color: var(--bg);
}

.btn-hard {
  background: linear-gradient(145deg, var(--amber), var(--amber2));
  color: var(--bg);
}

.btn-good {
  background: linear-gradient(145deg, var(--cyan), var(--cyan2));
  color: var(--bg);
}

.btn-easy {
  background: linear-gradient(145deg, var(--green), var(--green2));
  color: var(--bg);
}

.study-summary {
  text-align: center;
  display: none;
  padding: 40px 0;
}

.study-summary.active {
  display: block;
  animation: slideUp 0.4s ease-out;
}

.study-summary h1 {
  color: var(--text);
  margin-bottom: 32px;
  font-size: 2.4rem;
  background: linear-gradient(135deg, var(--cyan), var(--violet));
  background-clip: text;
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  text-fill-color: transparent;
}

.summary-grid {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 24px;
  margin: 32px 0 40px;
}

.summary-stat {
  padding: 24px;
  background: var(--panel2);
  border-radius: 24px;
  border: 1px solid var(--line);
  transition: all 0.25s ease;
}

.summary-stat:hover {
  transform: translateY(-4px);
  border-color: rgba(101,228,255,.4);
  box-shadow: 0 12px 40px rgba(101,228,255,.2);
}

.summary-stat b {
  display: block;
  font-size: 2.2rem;
  color: var(--cyan);
  line-height: 1.1;
}

.summary-stat span {
  color: var(--muted2);
  font-size: 0.9rem;
  text-transform: uppercase;
  letter-spacing: 0.1em;
  margin-top: 8px;
  display: block;
}

/* ==================== RESPONSIVE DESIGN ==================== */
@media (max-width: 980px) {
  .reader-grid {
    grid-template-columns: 1fr;
  }
  
  .toc-panel {
    position: relative;
    top: auto;
    max-height: none;
    order: -1;
  }
  
  .stats {
    grid-template-columns: repeat(3, minmax(0, 1fr));
  }
}

@media (max-width: 780px) {
  .toolbar-row {
    grid-template-columns: 1fr;
    gap: 14px;
  }
  
  .stats {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
  
  .hero {
    padding-top: 52px;
  }
  
  .doc-body,
  .doc-hero {
    padding: 22px;
    border-radius: 24px;
  }

  .source-banner {
    grid-template-columns: 1fr;
    padding: 18px;
  }

  .source-meta {
    justify-content: flex-start;
  }

  .rfc-page {
    padding: 18px 18px 20px;
    border-radius: 22px;
  }

  .rfc-page.is-contents::after {
    position: static;
    display: inline-flex;
    margin: 0 0 12px;
  }
  
  .reader-tools {
    border-radius: 24px;
    flex-direction: column;
    align-items: stretch;
  }
  
  .reader-tools .group {
    justify-content: center;
  }
  
  .header-field-table {
    font-size: .74rem;
  }
  
  .arp-flowchart-panel {
    padding: 20px;
    border-radius: 24px;
  }
  
  .flow-node,
  .flow-node.start,
  .flow-node.decision,
  .flow-node.action,
  .flow-node.merge,
  .flow-node.reply,
  .flow-node.stop {
    grid-column: span 12;
  }
  
  .summary-grid {
    grid-template-columns: 1fr;
    gap: 16px;
  }
}

@media (max-width: 480px) {
  .hero {
    padding: 50px 0 32px;
  }
  
  h1 {
    font-size: clamp(2rem, 10vw, 4rem);
  }
  
  .searchbox {
    padding: 12px 14px;
  }
  
  .card {
    min-height: 240px;
    padding: 20px;
  }
  
  .grid {
    grid-template-columns: 1fr;
    gap: 16px;
  }
  
  .stats {
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 10px;
  }
  
  .stat {
    min-height: 100px;
    padding: 16px;
  }
  
  .stat b {
    font-size: 1.35rem;
  }
}

/* Flashcard SRS Overlay */
.study-overlay {
  position: fixed;
  top: 0;
  left: 0;
  width: 100vw;
  height: 100vh;
  background: var(--bg);
  z-index: 9999;
  display: none;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: 20px;
}
.study-overlay.active { display: flex; }
.study-header {
  position: absolute;
  top: 20px;
  width: min(800px, 100%);
  display: flex;
  justify-content: space-between;
  align-items: center;
  color: var(--muted);
  font-size: 0.9rem;
}
.study-progress-bar {
  position: absolute;
  top: 0;
  left: 0;
  height: 4px;
  background: var(--cyan);
  transition: width 0.3s;
}
.card-container {
  width: min(600px, 100%);
  height: 400px;
  perspective: 1000px;
  cursor: pointer;
}
.flashcard {
  position: relative;
  width: 100%;
  height: 100%;
  text-align: center;
  transition: transform 0.6s;
  transform-style: preserve-3d;
}
.card-container.flipped .flashcard { transform: rotateY(180deg); }
.card-face {
  position: absolute;
  width: 100%;
  height: 100%;
  backface-visibility: hidden;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: 40px;
  border-radius: 32px;
  border: 2px solid var(--line);
  background: var(--panel);
  box-shadow: 0 30px 100px rgba(0,0,0,0.5);
}
.card-back {
  transform: rotateY(180deg);
  border-color: var(--cyan);
}
.card-category {
  position: absolute;
  top: 30px;
  font-size: 0.7rem;
  text-transform: uppercase;
  letter-spacing: 0.2em;
  color: var(--cyan);
  font-weight: 800;
}
.card-prompt {
  font-size: 1.8rem;
  font-weight: 800;
  line-height: 1.2;
  margin: 20px 0;
}
.card-answer {
  font-size: 1.1rem;
  line-height: 1.6;
  color: var(--text);
  max-width: 100%;
  overflow-y: auto;
}
.card-meta {
  position: absolute;
  bottom: 30px;
  font-size: 0.7rem;
  color: var(--muted);
}
.study-actions {
  margin-top: 40px;
  display: none;
  gap: 15px;
}
.study-actions.visible { display: flex; }
.srs-btn {
  padding: 12px 24px;
  border-radius: 999px;
  border: none;
  font-weight: 900;
  cursor: pointer;
  font-size: 0.9rem;
  transition: transform 0.2s;
}
.srs-btn:hover { transform: translateY(-2px); }
.btn-again { background: var(--pink); color: var(--bg); }
.btn-hard { background: var(--amber); color: var(--bg); }
.btn-good { background: var(--cyan); color: var(--bg); }
.btn-easy { background: var(--green); color: var(--bg); }

.study-summary {
  text-align: center;
  display: none;
}
.study-summary.active { display: block; }
.summary-grid {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 20px;
  margin: 30px 0;
}
.summary-stat {
  padding: 20px;
  background: var(--panel2);
  border-radius: 20px;
  border: 1px solid var(--line);
}
.summary-stat b { display: block; font-size: 2rem; color: var(--cyan); }

.badge {
  background: var(--pink);
  color: var(--bg);
  font-size: 0.65rem;
  font-weight: 900;
  padding: 2px 6px;
  border-radius: 6px;
  margin-left: 8px;
  vertical-align: middle;
}
.study-progress-card {
  background: linear-gradient(145deg, rgba(101,228,255,0.1), rgba(184,156,255,0.05));
  border: 1px solid rgba(101,228,255,0.2);
  grid-column: span 2;
}
.study-progress-card .btn-group { display: flex; gap: 8px; flex-wrap: wrap; margin-top: 12px; }
.study-progress-card .reader-btn { flex: 1; min-width: fit-content; white-space: nowrap; }
.study-hint {
  position: absolute;
  bottom: 20px;
  color: var(--muted);
  font-size: 0.8rem;
}

/* ==================== DESIGN REFRESH: hierarchy, scanning, accessibility ==================== */
:root {
  --focus-ring: rgba(101, 228, 255, .55);
  --surface-strong: rgba(11, 16, 30, .94);
  --surface-soft: rgba(255, 255, 255, .045);
}

::selection { background: rgba(101,228,255,.28); color: var(--text); }

body { text-wrap: pretty; }

.skip-link {
  position: fixed;
  left: 18px;
  top: 14px;
  z-index: 10000;
  transform: translateY(-140%);
  padding: 10px 14px;
  border-radius: 999px;
  color: #04111a;
  background: var(--cyan);
  font-weight: 900;
  box-shadow: 0 16px 40px rgba(0,0,0,.45);
}
.skip-link:focus { transform: translateY(0); }

:where(a, button, input, textarea, summary):focus-visible {
  outline: 3px solid var(--focus-ring);
  outline-offset: 3px;
  box-shadow: 0 0 0 6px rgba(101,228,255,.12);
}

.sr-only {
  position: absolute;
  width: 1px;
  height: 1px;
  padding: 0;
  margin: -1px;
  overflow: hidden;
  clip: rect(0, 0, 0, 0);
  white-space: nowrap;
  border: 0;
}

.inline-actions {
  display: flex;
  flex-wrap: wrap;
  gap: 10px;
}
.inline-actions.center { justify-content: center; }

.hero {
  position: relative;
  isolation: isolate;
}
.hero::after {
  content: "";
  display: block;
  width: min(760px, 72vw);
  height: 1px;
  margin: 32px auto 0;
  background: linear-gradient(90deg, transparent, rgba(101,228,255,.52), rgba(255,112,184,.32), transparent);
}
.hero-actions {
  display: flex;
  flex-wrap: wrap;
  justify-content: center;
  gap: 10px;
  margin-top: 26px;
}
.hero-action {
  min-height: 44px;
  display: inline-flex;
  align-items: center;
  gap: 8px;
  padding: 10px 15px;
  border: 1px solid rgba(255,255,255,.14);
  border-radius: 999px;
  color: var(--text2);
  background: linear-gradient(145deg, rgba(255,255,255,.085), rgba(255,255,255,.035));
  box-shadow: inset 0 1px 0 rgba(255,255,255,.08), 0 14px 34px rgba(0,0,0,.24);
  font-weight: 850;
  font-size: .9rem;
  transition: transform .18s ease, border-color .18s ease, background .18s ease, color .18s ease;
}
.hero-action:hover {
  transform: translateY(-2px);
  color: var(--text);
  border-color: rgba(101,228,255,.46);
  background: rgba(101,228,255,.11);
}
.hero-action.primary {
  color: #061018;
  border-color: rgba(101,228,255,.72);
  background: linear-gradient(135deg, var(--cyan), var(--violet));
}

.study-plan {
  margin: 26px 0 34px;
  padding: clamp(22px, 3vw, 34px);
  border: 1px solid rgba(101,228,255,.18);
  border-radius: 34px;
  background:
    radial-gradient(circle at top left, rgba(101,228,255,.14), transparent 30%),
    radial-gradient(circle at 85% 12%, rgba(255,112,184,.12), transparent 28%),
    linear-gradient(145deg, rgba(13,20,36,.96), rgba(10,14,28,.92));
  box-shadow:
    0 24px 80px rgba(0,0,0,.34),
    inset 0 1px 0 rgba(255,255,255,.08);
}

.study-plan-intro h2 {
  margin: 10px 0 14px;
  font-size: clamp(2rem, 4vw, 3.3rem);
  line-height: .94;
  letter-spacing: -.05em;
  color: var(--text);
}

.study-plan-intro p {
  max-width: 72ch;
  margin: 0;
  color: var(--text2);
  font-size: 1.02rem;
}

.study-plan-grid,
.study-track-grid {
  display: grid;
  gap: 16px;
  margin-top: 24px;
}

.study-plan-grid {
  grid-template-columns: repeat(3, minmax(0, 1fr));
}

.study-track-grid {
  grid-template-columns: repeat(3, minmax(0, 1fr));
}

.study-card,
.study-track {
  position: relative;
  overflow: hidden;
  padding: 22px;
  border: 1px solid rgba(255,255,255,.1);
  border-radius: 26px;
  background: linear-gradient(160deg, rgba(255,255,255,.055), rgba(255,255,255,.02));
  box-shadow: inset 0 1px 0 rgba(255,255,255,.05);
}

.study-card::before,
.study-track::before {
  content: "";
  position: absolute;
  inset: 0 auto auto 0;
  width: 100%;
  height: 1px;
  background: linear-gradient(90deg, rgba(101,228,255,.45), transparent 60%);
}

.study-card h3,
.study-track h3 {
  margin: 8px 0 12px;
  font-size: 1.28rem;
  line-height: 1.1;
  letter-spacing: -.03em;
  color: var(--text);
}

.study-card p,
.study-track p,
.study-active span {
  color: var(--text2);
}

.study-card-kicker,
.study-track-kicker {
  display: inline-flex;
  align-items: center;
  min-height: 28px;
  padding: 0 10px;
  border-radius: 999px;
  border: 1px solid rgba(101,228,255,.22);
  color: var(--cyan);
  background: rgba(101,228,255,.08);
  text-transform: uppercase;
  letter-spacing: .14em;
  font-size: .7rem;
  font-weight: 900;
}

.study-list {
  margin: 0;
  padding-left: 18px;
  color: var(--text2);
}

.study-list li + li {
  margin-top: 10px;
}

.study-aside {
  margin: 14px 0 0;
  color: var(--muted);
  font-size: .92rem;
}

.if-then-form {
  display: grid;
  gap: 14px;
  margin-top: 14px;
}

.if-then-form label {
  display: grid;
  gap: 8px;
}

.if-then-form label span {
  color: var(--text);
  font-size: .9rem;
  font-weight: 700;
}

.if-then-preview {
  min-height: 74px;
  padding: 14px 16px;
  border: 1px dashed rgba(255,255,255,.14);
  border-radius: 18px;
  color: var(--text2);
  background: rgba(6,10,20,.45);
}

.study-status {
  min-height: 1.2em;
  color: var(--green);
  font-size: .9rem;
  font-weight: 700;
}

.study-status-row {
  display: flex;
  flex-wrap: wrap;
  justify-content: space-between;
  align-items: end;
  gap: 14px;
  margin-top: 24px;
}

.study-active {
  display: grid;
  gap: 5px;
}

.study-active strong {
  color: var(--text);
  font-size: 1.15rem;
}

.study-chip-row {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  margin: 16px 0 18px;
}

.study-chip {
  display: inline-flex;
  align-items: center;
  min-height: 30px;
  padding: 0 11px;
  border-radius: 999px;
  border: 1px solid rgba(255,255,255,.1);
  background: rgba(255,255,255,.05);
  color: var(--text2);
  font-size: .84rem;
  font-weight: 700;
}

.study-track-head {
  display: grid;
  gap: 8px;
}

.study-path-btn.active {
  border-color: rgba(101,228,255,.68);
  box-shadow: 0 0 0 3px rgba(101,228,255,.12);
}

.science-list {
  display: grid;
  gap: 14px;
  margin: 0;
  padding: 0;
  list-style: none;
}

.science-list li {
  display: grid;
  gap: 4px;
  padding-left: 18px;
  border-left: 2px solid rgba(101,228,255,.18);
}

.science-list a {
  color: var(--text);
  font-weight: 800;
}

.science-list span {
  color: var(--muted);
  line-height: 1.5;
}

.toolbar-controls {
  display: flex;
  align-items: center;
  gap: 10px;
  justify-content: flex-end;
}
.view-count { min-height: 38px; display: inline-flex; align-items: center; }

.grid { align-items: stretch; }
.card {
  display: flex;
  flex-direction: column;
}
.card .tags { margin-top: auto; }
.card .open { align-self: flex-start; }
.card p { max-width: 62ch; }
body.card-compact .grid { grid-template-columns: repeat(auto-fill, minmax(250px, 1fr)); gap: 12px; }
body.card-compact .card { min-height: 190px; padding: 18px; border-radius: 22px; }
body.card-compact .card h2 { font-size: 1.12rem; margin: 12px 0 8px; }
body.card-compact .card p { font-size: .87rem; line-height: 1.45; margin-bottom: 14px; }
body.card-compact .open { margin-top: 14px; }

.toc-panel a.active {
  color: var(--text);
  border-color: rgba(101,228,255,.34);
  background: linear-gradient(90deg, rgba(101,228,255,.14), transparent);
  padding-left: 10px;
  border-radius: 10px;
}

/* Interactive RFC graph: contained controls + readable legend */
.map-overlay {
  position: fixed;
  inset: 0;
  z-index: 90;
  display: none;
  overflow: hidden;
  background:
    radial-gradient(circle at 20% 8%, rgba(101,228,255,.18), transparent 30%),
    radial-gradient(circle at 82% 18%, rgba(255,82,168,.14), transparent 28%),
    linear-gradient(180deg, rgba(5,8,18,.98), rgba(2,4,12,.99));
}
.map-overlay.active { display: grid; grid-template-rows: auto 1fr; }
.map-header {
  position: relative;
  z-index: 3;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 18px;
  padding: 18px clamp(18px, 3vw, 36px);
  border-bottom: 1px solid rgba(101,228,255,.14);
  background: rgba(4,8,18,.72);
  backdrop-filter: blur(18px);
  box-shadow: 0 18px 48px rgba(0,0,0,.34);
}
.map-header .eyebrow {
  margin: 0;
  letter-spacing: .18em;
  white-space: nowrap;
}
.map-container {
  position: relative;
  min-height: 0;
  overflow: hidden;
  background-image:
    linear-gradient(rgba(101,228,255,.045) 1px, transparent 1px),
    linear-gradient(90deg, rgba(101,228,255,.045) 1px, transparent 1px);
  background-size: 64px 64px;
}
.map-container svg { display: block; width: 100%; height: 100%; }
.map-legend {
  position: absolute;
  left: clamp(16px, 2.5vw, 30px);
  top: clamp(16px, 2.5vw, 30px);
  z-index: 2;
  width: min(300px, calc(100vw - 32px));
  max-height: calc(100% - 32px);
  overflow: auto;
  padding: 18px;
  border: 1px solid rgba(101,228,255,.20);
  border-radius: 24px;
  color: var(--text);
  background: linear-gradient(145deg, rgba(8,14,30,.92), rgba(6,9,20,.82));
  box-shadow: 0 24px 70px rgba(0,0,0,.42), inset 0 1px 0 rgba(255,255,255,.08);
  backdrop-filter: blur(16px);
}
.legend-group + .legend-group { margin-top: 18px; padding-top: 16px; border-top: 1px solid rgba(255,255,255,.08); }
.legend-group h4 {
  margin: 0 0 12px;
  color: var(--text);
  font-size: .82rem;
  text-transform: uppercase;
  letter-spacing: .14em;
}
.legend-item {
  display: grid;
  grid-template-columns: 22px 1fr;
  align-items: center;
  gap: 10px;
  min-height: 30px;
  color: var(--text2);
  font-size: .93rem;
  line-height: 1.25;
}
.legend-color {
  width: 13px;
  height: 13px;
  border-radius: 999px;
  box-shadow: 0 0 16px currentColor;
}
.legend-line {
  width: 20px;
  height: 0;
  border-radius: 999px;
  border-top: 2px solid rgba(226,232,255,.78);
}
.link {
  fill: none;
  stroke: rgba(226,232,255,.45);
  stroke-width: 1.8;
}
.link.update-chain { stroke: var(--amber); stroke-dasharray: 8 6; }
.link.threat { stroke: var(--pink); stroke-dasharray: 2 5; }
.link.highlight { stroke-width: 3.5; filter: drop-shadow(0 0 8px currentColor); }
.link.dimmed, .node.dimmed { opacity: .18; }
.node { cursor: pointer; transition: opacity .18s ease; }
.node rect {
  rx: 13;
  ry: 13;
  fill: rgba(10,16,32,.92);
  stroke: var(--cyan);
  stroke-width: 1.4;
  filter: drop-shadow(0 12px 18px rgba(0,0,0,.45));
}
.node-link rect { stroke: var(--violet); }
.node-routing rect, .node-security rect { stroke: var(--cyan); }
.node-transport rect { stroke: var(--amber); }
.node-application rect { stroke: var(--pink); }
.node-monitoring rect { stroke: var(--green); }
.node text {
  fill: var(--text);
  font-size: 10px;
  font-weight: 800;
  text-anchor: middle;
  pointer-events: none;
}
.node .node-rfc { fill: var(--muted); font-size: 9px; font-weight: 700; }

.doc-body pre { max-width: 100%; }
.doc-body.focus pre { max-width: 100%; }
.reader-tools { min-height: 58px; }

@media (max-width: 780px) {
  .hero-actions { justify-content: flex-start; }
  .hero-action { width: 100%; justify-content: center; }
  .study-plan { padding: 20px 16px; border-radius: 26px; }
  .study-plan-grid,
  .study-track-grid { grid-template-columns: 1fr; }
  .study-status-row { align-items: stretch; }
  .study-status-row .reader-btn { width: 100%; }
  .searchbox input { min-width: 0; }
  .toolbar-controls { width: 100%; justify-content: space-between; }
  .toolbar-controls .reader-btn { flex: 1; }
  .map-overlay.active { grid-template-rows: auto 1fr; }
  .map-header { align-items: flex-start; flex-direction: column; padding: 14px 16px; }
  .map-header .eyebrow { white-space: normal; }
  .map-legend {
    left: 12px;
    right: 12px;
    top: 12px;
    width: auto;
    max-height: 45%;
    border-radius: 18px;
  }
}

@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after {
    animation-duration: .001ms !important;
    animation-iteration-count: 1 !important;
    scroll-behavior: auto !important;
    transition-duration: .001ms !important;
  }
  .eyebrow, .num::before, .study-progress-bar, .arp-flowchart-panel::before { animation: none !important; }
  .card:hover, .hero-action:hover, button.reader-btn:hover, button.filter:hover { transform: none !important; }
}


"""

INDEX_JS = r"""
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
    const emptyDiv = document.createElement('div');
    emptyDiv.className = 'notes-empty';
    emptyDiv.textContent = rfcNums.length === 0 ? "You haven't added any notes yet." : `No notes match the "${activeNoteFilter}" filter.`;
    notesContainer.appendChild(emptyDiv);
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
"""

DOC_JS = r"""
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
"""

