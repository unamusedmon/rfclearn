# Protocol Prowler

RFCs are where the Internet keeps its ancient laws, protocol gossip, and deeply specific feelings about bit fields.

Protocol Prowler turns that magnificent swamp into a local threat-hunting library you can actually use.

This repo builds an offline-first reference site for network defenders, security researchers, and anyone who has ever opened an RFC and thought, "Ah yes, 38 pages of pure emotional support prose about checksums."

## What This Thing Actually Does

It takes a curated collection of RFCs from the [RFC Editor](https://www.rfc-editor.org/), cleans them up, cross-links them locally, and wraps them in a site designed for people who need to understand protocols without developing a personal grudge against typography.

You get:

- searchable local RFC pages
- protocol relevance notes written for hunters, not historians
- header and packet visualizations for key protocols
- threat-hunting indicators and detection prompts
- local notes and highlights
- built-in spaced-repetition flashcards
- a guided study plan so "I should really learn these RFCs" stops being a yearly wish and becomes a real habit
- EPUB exports for offline reading, bunker mode, and flights where you want to feel like a very tired wizard

## Why It Exists

Reading raw RFCs during an investigation is a little like trying to learn sword fighting by reading municipal plumbing code.

Technically possible.

Spiritually hostile.

This project exists to make protocol knowledge fast to navigate, easier to remember, and far more useful when you are looking at suspicious traffic and asking questions like:

- Is this weird?
- Is this broken?
- Is this malicious?
- Is this BGP doing BGP things again?

## Quick Start

Install dependencies:

```bash
python3 -m pip install -r requirements.txt
```

Build the site and EPUBs:

```bash
python3 build_rfc_collection.py
```

Open the site:

```bash
xdg-open site/index.html
```

If you want to serve it locally:

```bash
python3 -m http.server 8765 --directory site
```

Then browse to:

```text
http://127.0.0.1:8765
```

## How To Use It Without Becoming An RFC Monk

The homepage includes a built-in study system because the best study plan is the one that does not feel like a hostage negotiation.

The basic loop is:

1. Pick one study track instead of licking the entire protocol encyclopedia in one sitting.
2. Read one RFC or one major section for 10 to 15 minutes.
3. Close it and recall three things from memory before rereading.
4. Run `Study Due` to do low-stakes retrieval practice.
5. Leave one short note about a field, threat clue, or edge case worth remembering.

If recall feels slightly annoying, that is not failure. That is your brain being forced to do a push-up.

### Suggested 6-sprint path

- `Packet Skeleton Crew`: RFC 768, 791, 792, 793, 826
- `Boot, Name, Find`: RFC 1035, 1123, 2131, 2782
- `Routes, Lies, and Routers`: RFC 1122, 2328, 2460, 4271
- `Tunnels and Trust Issues`: RFC 4301, 4303
- `Web and Mail Drama Desk`: RFC 2616, 5321, 7230, 7540
- `Logs, Flows, and Receipts`: RFC 3954, 7011

After that, use the `update-chain` tag when you want the lore expansion pack.

### Tiny if-then plan

If you want to actually keep going, make the cue stupidly specific:

`If it is after coffee, then I read one RFC section and do 10 due cards.`

Not:

`At some point, when the vibes are right, I will become a protocol scholar.`

The vibes are lazy and cannot be trusted.

## Why The Study Plan Works

This is not just motivational theater with nicer gradients.

The study flow is based on durable findings from learning and motivation research:

- `Spacing`: distributed practice improves long-term retention better than cramming. Source: [Cepeda et al. (2006)](https://doi.org/10.1037/0033-2909.132.3.354)
- `Retrieval practice`: testing yourself beats passive restudy for durable learning. Source: [Adesope et al. (2017)](https://doi.org/10.3102/0034654316689306)
- `Low-stakes quizzing with feedback`: practice tests improve learning across contexts, and feedback helps more. Source: [Yang et al. (2021)](https://doi.org/10.1037/bul0000309)
- `Autonomy and competence support`: motivation improves when learners get a manageable path and some real choice. Source: [Wang et al. (2024)](https://doi.org/10.1016/j.lmot.2024.102015)
- `Interest and relevance`: reading motivation improves most when the material feels meaningful, not when it merely exists in your general direction. Source: [de Nooijer et al. (2024)](https://doi.org/10.1007/s10648-023-09719-3)
- `Implementation intentions`: specific if-then plans make follow-through more likely. Source: [Gollwitzer & Sheeran (2006)](https://doi.org/10.1016/S0065-2601(06)38002-1)

In short:

- read less at a time
- come back more often
- recall before rereading
- use concrete cues
- give your brain a reason to care

Miraculously, this works better than highlighting a paragraph until it looks like a radioactive banana.

## Outputs

Running the builder generates:

```text
site/                                      Static website
epub/rfc-threat-hunting-complete.epub     Complete EPUB
epub/rfc-threat-hunting-by-category.epub  Category-grouped EPUB
```

## Testing

Run tests:

```bash
python3 -m unittest discover -s tests -v
```

Syntax-check the builder:

```bash
python3 -m py_compile build_rfc_collection.py
```

## What You Will Probably Learn Faster Here

- Why TTL weirdness matters
- Why ARP is less a protocol and more a trust exercise gone wrong
- Why DNS can be both useful and slightly criminal-looking
- Why SMTP has spent decades politely asking people to stop doing cursed things
- Why BGP is proof that civilization is a collaborative art project

## License

Use it freely.

If it helps you understand packets better, excellent.

If it causes you to develop strong opinions about extension headers, that is between you and destiny.
