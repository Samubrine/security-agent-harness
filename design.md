# AEGIS interface design system

The visual language for the AEGIS web app (Laravel views in `resources/views`, styles in
`resources/css`). It is derived from a reference board for a dark, green-accented security
product. **Only the style is taken from the reference, not its content:** no VPN copy, country
lists, pricing, people photos or globe of servers. Every component below is specified for what
AEGIS actually shows: conversations with an agent, tool calls, live progress, approvals, findings,
evidence and reports.

A rendered specimen of these tokens and components lives in
[`docs/design/specimen.html`](docs/design/specimen.html). Open it in a browser next to this file.

---

## 1. Character

| Trait | What it means in practice |
|---|---|
| **Dark, quiet, technical** | Near-black canvas (`#080808`), almost no colour. Content sits on the canvas, not in boxes. |
| **One green** | A single deep security green is the only accent: labels, links, "done" states, glows. It is used sparingly, so when it appears it means something. |
| **Terminal headlines** | Headings are set in a light **monospace, uppercase**. Reading text is a clean neo-grotesque sans. The contrast between the two is the main typographic idea. |
| **Drawn on a grid** | Pages look drafted: 1px hairlines frame the content column and split sections into cells, with small bright **dots where lines meet**. Separation comes from lines, not shadows or gaps. |
| **Light instead of shadow** | Depth is a faint green **glow** behind a focal object, or a lighter surface. There are no drop shadows. |
| **Soft controls on hard structure** | The grid is square-cornered; anything you can press is a **pill**. |

Tagline for the style: *a security console drawn on graph paper, with one green light on.*

---

## 2. Colour

All values were sampled from the reference pixels, then adjusted only where contrast required it
(see §11). The theme is **dark-first**. Light tokens are in §2.6 for the existing theme switch.

### 2.1 Neutrals

| Token | Hex | Role | Reference |
|---|---|---|---|
| `--bg` | `#080808` | Page canvas, frame cells | Measured `#080808` (56% of the board) |
| `--bg-deep` | `#000000` | Inset panels: footer, code blocks, report body | Footer link panel |
| `--surface-1` | `#121212` | List rows, stat tiles, inputs, tool-step rows | Country rows `#121212`–`#131313` |
| `--surface-2` | `#1c1c1c` | Floating cards, secondary buttons, chips, popovers | Floating "Try now" card `#1c1c1c` |
| `--surface-3` | `#242424` | Hover state of surface-2, pressed rows | Derived (+8) |
| `--line` | `#161616` | Hairlines: frame, section and cell dividers (decorative) | Stat row dividers `#161616` |
| `--line-strong` | `#262626` | Borders of cards and rows that must read as separate | Derived |
| `--line-input` | `#666666` | Borders of form controls (3:1 rule, §11) | Not in the reference: added for accessibility |
| `--grid-dot` | `#d9d9d9` | Intersection dots on the frame | Bright 3px dots on line crossings |

### 2.2 Text

| Token | Hex | Role | Measured |
|---|---|---|---|
| `--text-strong` | `#ececec` | Display and titles, numbers, active nav | Headings `#ebedec` / `#f1f3f2` |
| `--text` | `#a3a3a3` | Body copy | Hero body `#a6a6a6` / `#969696` |
| `--text-muted` | `#868686` | Captions, stat labels, metadata, nav links | Stat labels `#8d8d8d`–`#919191` |
| `--text-faint` | `#5c5c5c` | Disabled text and placeholders only, never information | Derived |
| `--text-on-mint` | `#080808` | Text on the mint primary button | Button text |

### 2.3 Accent green

| Token | Hex | Role | Measured |
|---|---|---|---|
| `--accent` | `#27916b` | Brand green: icon strokes, eyebrow labels, progress fills, done dots | Announcement bar `#27916b`, saturated greens `#209068` |
| `--accent-text` | `#34b386` | Green **text** of any size on any dark surface (links, "Connected") | Brighter than measured `#238262` so small text passes 4.5:1 everywhere |
| `--accent-bar` | `#1f7a59` | Status/announcement bar background (white text) | Reference `#27916b` darkened for 4.5:1 |
| `--mint` | `#e8f4f0` | Primary button fill; the only light surface | Primary pill `#e7f3ef`–`#ebf7f3` |
| `--accent-wash` | `#11201d` | Tinted background of hero areas, behind the glow | Hero bg `#11201d` / `#101f1c` |
| `--accent-glow` | `rgba(39,145,107,.28)` | Radial glow behind focal icons, charts and live widgets | Glow peak `#195b45` |
| `--accent-deep` | `#02261a` | Duotone shadows, chart fill base, selected-row tint | Photo duotone `#02261a` |
| `--duo-mid` | `#5c8577` | Duotone mid-tone | Quantised `#5c8577` |
| `--duo-light` | `#b1c3bd` | Duotone highlight | Quantised `#b1c3bd` |

### 2.4 Status and severity

The reference has one red ("LIVE" dot, `#d00020`) and one orange ("threats blocked", `#d1872d`).
AEGIS needs a five-step severity scale, built around those two and the green.

| Token | Dot / fill | Text on dark | Meaning in AEGIS |
|---|---|---|---|
| `--critical` | `#d00020` | `#ff6b6b` | Critical finding, failed tool call, policy *deny*, LIVE indicator |
| `--high` | `#d1872d` | `#e0943a` | High finding, **approval needed**, warning chips |
| `--medium` | `#a8962f` | `#d4c15a` | Medium finding |
| `--low` | `#3d7a64` | `#7fb39f` | Low finding |
| `--info` | `#4a4a4a` | `#868686` | Informational |
| `--success` | `#27916b` | `#34b386` | Done step, *allow*, agreement, fact check passed |

Severity is never colour alone. It is always a dot **plus** a word: `● CRITICAL`.

### 2.5 Usage rules

- Green covers less than about 5% of any screen. The reference is about 3% green.
- Only one mint (light) element per view region: the primary action.
- Red is for things that are wrong or happening *now*: critical, failed, live. It is never used for decoration.
- Do not mix in other hues: no blue links, no purple charts.

### 2.6 Light theme (for the existing theme switch)

The design is dark. The light mapping keeps the structure and the single green.

| Token | Light value |
|---|---|
| `--bg` | `#f6f7f6` |
| `--bg-deep` | `#ffffff` |
| `--surface-1` | `#eeefee` |
| `--surface-2` | `#e4e6e5` |
| `--line` / `--line-strong` | `#e1e4e2` / `#cdd2cf` |
| `--line-input` | `#8a8f8c` |
| `--text-strong` / `--text` / `--text-muted` | `#0d1110` / `#3e4542` / `#5d6461` |
| `--accent-text` | `#1d7655` |
| `--mint` (primary button) | `#0f2a22` with `#e8f4f0` text |
| Severity text | critical `#b3261e`, high `#9a5a0f`, medium `#7a6a10`, low `#2f6b55` |

---

## 3. Typography

### 3.1 Families

| Token | Stack | Use |
|---|---|---|
| `--font-display` | `"Geist Mono", "JetBrains Mono", "IBM Plex Mono", ui-monospace, monospace` | Display, section and card titles (UPPERCASE), eyebrow labels, numbers, code, run ids |
| `--font-sans` | `"Geist", "Inter", "Segoe UI", system-ui, sans-serif` | Body, buttons, nav, form fields, chat text |

Load both with `npm i @fontsource-variable/geist @fontsource-variable/geist-mono` and import them in
`resources/css/app.css`. Vite then bundles the fonts, so the app works offline in the lab. The
fallbacks are close in metrics, so nothing breaks while the fonts are missing.

### 3.2 Scale (desktop; root 16px)

| Token | Family / weight | Size / line | Tracking | Case | Reference use → AEGIS use |
|---|---|---|---|---|---|
| `display-xl` | mono 300 | `clamp(36px, 4.6vw, 56px)` / 1.08 | `-0.01em` | UPPER | Hero headline → home "IS YOUR LAB SAFE?" |
| `display-l` | mono 300 | `clamp(28px, 3vw, 40px)` / 1.12 | `0` | UPPER | Section title → page titles, report title |
| `display-m` | mono 400 | 24px / 1.2 | `0` | UPPER | Footer CTA → panel headings |
| `title` | mono 400 | 15px / 1.35 | `0.02em` | UPPER | Card title ("BLAZING FAST") → card, finding, step titles |
| `stat` | mono 400, tabular | `clamp(28px, 2.6vw, 36px)` / 1 | `-0.01em` | as is | "99.9%", "256-BIT" → counts, CVSS, durations |
| `stat-s` | mono 400, tabular | 18px / 1.1 | `0` | as is | Mini tiles ("150+") |
| `body-l` | sans 400 | 17px / 1.6 | `0` | Sentence | Lead paragraph under a title |
| `body` | sans 400 | 15px / 1.6 | `0` | Sentence | Chat answers, descriptions |
| `body-s` | sans 400 | 13px / 1.5 | `0` | Sentence | Captions, stat labels, metadata, tool output summaries |
| `ui` | sans 500 | 14px / 1 | `0` | Sentence | Buttons, nav, chips |
| `label` | mono 500 | 11px / 1.4 | `0.14em` | UPPER | Eyebrow ("FAST CONNECT") → section kicker, column headers, chip text |
| `code` | mono 400 | 13px / 1.6 | `0` | as is | JSON payloads, run ids, hashes, CVE ids inline |

On mobile (< 640px) the body text stays the same size and only the display sizes shrink, through
the `clamp()` values above.

### 3.3 Rules

- Monospace, uppercase, light: titles only. Running text is never uppercase.
- Keep headings short (2–6 words). The reference never wraps a display headline past three lines.
- The eyebrow is an **8–14 character** kicker in `--accent` above a display title, with 16px space below it.
- Numbers use the mono face with `font-variant-numeric: tabular-nums`, so columns of figures line up.
- CVE ids, run ids, hashes, ports and versions are always in `code` style, never in the sans face.
- Text columns are at most 64ch wide. The reference keeps paragraphs to about 60 characters.

---

## 4. Space, layout and the grid frame

### 4.1 Spacing scale (4px base)

`--space-1` 4 · `--space-2` 8 · `--space-3` 12 · `--space-4` 16 · `--space-5` 20 · `--space-6` 24 ·
`--space-8` 32 · `--space-10` 40 · `--space-12` 48 · `--space-16` 64 · `--space-24` 96 · `--space-32` 128

| Context | Value |
|---|---|
| Inside a frame cell / card | 32px desktop, 20px mobile |
| Inside rows, tiles, chips | 12–16px block, 16–20px inline |
| Between eyebrow → title → lead → actions | 16 → 16 → 24 |
| Between page sections (bands) | 96px desktop, 64px mobile |
| Gap between pill buttons | 12px |

### 4.2 The frame

The frame is the most recognisable feature of the reference, and every page uses it.

```
 ·───────────────────────────────────────────────────────────────·   ← --line, dots at crossings
 │  LABEL                                                        │
 │  DISPLAY TITLE                                 [ floating ]   │   one container, max 1280px,
 │  lead text …                                                  │   left/right borders = --line
 │  ( secondary )  ( PRIMARY )                                   │
 ·───────────────┬───────────────┬───────────────┬───────────────·   ← section divider, full width
 │     99.9%     │      10M+     │    256-BIT    │     24/7      │   stat row: cells split by
 │    caption    │    caption    │    caption    │    caption    │   vertical hairlines, no gaps
 ·───────────────┴───────────────┴───────────────┴───────────────·
 │  CELL TITLE                   │  CELL TITLE                   │   bento: 2–3 columns,
 │  text …                       │  text …                       │   cells share borders
 │  GET STARTED →                │  [ live widget ]              │
 ·───────────────────────────────┴───────────────────────────────·
```

- **Container:** `max-width: 1280px; margin-inline: auto; border-inline: 1px solid var(--line)`.
- **Bands:** each section is a band with `border-top: 1px solid var(--line)`. Bands touch each other; spacing is padding inside them.
- **Cells:** a band splits into cells with `border-left: 1px solid var(--line)` (except the first). Use 2, 3 or 4 columns. On mobile, cells stack and the dividers turn horizontal.
- **Dots:** a 3px `--grid-dot` circle at each place where a band divider meets the container border (a `::before` on the band, at `left:-2px; top:-2px`, and mirrored on the right). Use dots at band corners only, not on every cell.
- Content never touches the frame lines. Cells always have padding.

### 4.3 App layout

The reference is a marketing site with a top nav. AEGIS is a tool, so it keeps the frame and adds
navigation that suits a tool:

```
┌──────────────────────────────────────────────────────────────────────────┐
│ SIGNED LAB SCOPE · lab-2026-09 · MODEL openai/gpt-oss-120b · ● AGENT IDLE │  status bar (--accent-bar)
├──────────────────────────────────────────────────────────────────────────┤
│ ◆ AEGIS     Agent  Investigations  Reports          ( theme )  ( FL ▾ )   │  top nav, 64px
├──────────┬───────────────────────────────────────────────────────────────┤
│          │                                                               │
│ (left    │   framed content column (max 1280)                            │
│  rail on │                                                               │
│  wide    │                                                               │
│  screens │                                                               │
│  only:   │                                                               │
│  convo   │                                                               │
│  list)   │                                                               │
└──────────┴───────────────────────────────────────────────────────────────┘
```

- **Status bar** (24–28px): this replaces the reference's announcement bar with something useful: the scope id, the model in use, and agent status (a pulsing dot while a turn runs). Text is `label` style, white on `--accent-bar`. A link in it is underlined, as in the reference.
- **Top nav** (64px, `--bg`, bottom `--line`): logo mark and wordmark on the left, section links in the centre (`ui`, `--text-muted`, active = `--text-strong`), and on the right an icon button for the theme and a `surface-2` pill with the user's initials.
- **Workspace sub-views** (Overview, Findings, Evidence, Trace, Activity, Report) become a **tab strip** at the top of the frame: `label` style, active tab = `--text-strong` with a 2px `--accent` underline. They no longer sit in a sidebar.
- **Conversation rail** (≥ 1200px only): a 280px column inside the frame, separated by a vertical hairline, listing conversations as rows (§5.7). Below 1200px it is the conversation list page.

### 4.4 Breakpoints

| Name | Min width | Changes |
|---|---|---|
| `sm` | 0 | One column; cells stack (the stat row stays 2×2); nav links move into a horizontal scroller under the logo; status bar shows the scope only; floating cards hidden |
| `md` | 640px | Two-column bento; stat row 2×2 |
| `lg` | 960px | Three-column bento; stat row 1×4; floating cards appear |
| `xl` | 1200px | Conversation rail; content max 1280px |

No horizontal page scroll at any width: the frame gets `overflow-x: clip`, so the corner dots cannot push the page 1px wider on phones. Tables and JSON scroll inside their own container.

---

## 5. Components

Every component lists its tokens, states and the AEGIS view it serves. Radii: frame cells **0**,
rows **8px**, cards and tiles **12px**, icon tiles **10px**, pills **999px**.

### 5.1 Buttons

| Variant | Look | Use in AEGIS |
|---|---|---|
| **Primary** | `--mint` fill, `--text-on-mint`, `ui` text, pill, 40px tall, padding 0 18px; faint glow `0 0 24px rgba(232,244,240,.10)` | Send, Approve and run again, Run investigation, Continue. **At most one per region.** |
| **Secondary** | `--surface-2` fill, `--text-strong`, no border, pill | Decline, View report, Cancel, Sign in |
| **Ghost link** | `label` style in `--accent-text`, uppercase, followed by `→` | "OPEN FULL REPORT →", "VIEW EVIDENCE →" |
| **Icon** | 36px circle, `--surface-2`, 18px line icon in `--text-muted` | Theme toggle, copy JSON, close |
| **Danger** | Secondary with `--critical` text (`#ff6b6b`) | Delete conversation, Delete account |

States: hover = surface one step lighter (mint → `#ffffff`); active = 1px inset; focus =
`outline: 2px solid var(--accent-text); outline-offset: 3px`; disabled = 40% opacity, no glow;
loading = the label stays and a 14px spinner sits in front of it. The button never changes width.

### 5.2 Eyebrow + title block

```
SIGNED LAB SCOPE                         ← label, --accent
IS YOUR LAB SAFE?                        ← display-xl, --text-strong
Ask in your own words. The agent …       ← body-l, --text, max 56ch
( View past runs )  ( ASK THE AGENT )    ← secondary + primary
```
Left-aligned on app pages. Centred only for the empty state of a page and the report cover.

### 5.3 Stat row

A row of 2–4 frame cells, centred: `stat` number in `--text-strong`, `body-s` caption in
`--text-muted` 8px below. In AEGIS it holds counts on the conversation list (conversations, tool
calls, investigations, findings) and on an investigation (findings, confirmed/possible, evidence
records, provider calls). A critical count may use `--critical` text, but only when it is above zero.

### 5.4 Mini stat tile

`--surface-1`, radius 12, padding 12px 16px, `stat-s` value with a `body-s` caption. They sit in a
row with 8px gaps inside a cell (the "150+ / 6.4k+ / 99.9%" tiles). In AEGIS: CVSS score, ports
open, time taken, beside a finding or a tool step.

### 5.5 Frame cell (feature / bento)

Padding 32px. Content from top to bottom: an icon tile (40px, radius 10, `--surface-1`, 1px
`--line-strong`, 18px green line icon), 20px gap, `title`, 8px gap, `body-s` `--text`, then
optionally a live widget at the bottom (§5.12) or a ghost link. In AEGIS: the **skill cards**
(Port scan, Log analysis, Entry point, Version check), each with its required inputs as a checklist
(§5.9) and a "RUN →" ghost link.

### 5.6 Floating card

`--surface-2`, radius 12, padding 16px, max 260px, no border, no shadow. A small row of
avatars or icons at the top, `body-s` text, then a `ui` link with `→`. It floats in a hero corner
(the "Secure internet anywhere" card). In AEGIS: on the home hero, "Last run · run-…" with its
finding count and an "Open →" link. Hidden below `lg`.

### 5.7 List row

`--surface-1`, radius 8, 48–56px tall, padding 0 16px, 6px gap between rows; a leading marker, a
label in `ui` `--text-strong`, optional `body-s` meta, and a trailing `→` in `--text-muted`. Hover
moves the background to `--surface-2` and the arrow 2px right. These are the reference's country
rows. In AEGIS: conversation rows, investigation run rows, finding rows (the leading marker is the
severity dot, with a `label` severity word before the title), and evidence records.

### 5.8 Chips and status

| Chip | Look | AEGIS use |
|---|---|---|
| **Status text** | `body-s` in `--accent-text`, no background ("Connected") | "Completed", "Allowed", "Agreement" |
| **Live** | `--surface-1` pill, red 6px dot with a 1.2s pulse, `label` "LIVE" in `--text-strong`, then `body-s` meta | Agent turn in progress: "● LIVE · step 3 · 12s" |
| **Warning** | `--surface-2` pill, 14px warning icon and text in `--high` text colour | "Approval needed", "1 source conflict" |
| **Severity** | 8px dot + `label` word in severity text colour, no background | Findings, everywhere |
| **Count** | `--surface-2` pill, `label` text | Tab counts, "3 tool calls" |

### 5.9 Checklist

Rows of an 18px outlined circle check in `--accent`, 12px gap, `body-s` `--text`, 10px between
rows (the pricing feature lists). In AEGIS: the capabilities a skill uses, the completion criteria
of a run, and the items in the fact check that passed. A failed item swaps the icon for a circled ×
in `--critical`.

### 5.10 Form controls

- **Text field / textarea:** `--surface-1` fill, 1px `--line-input` border, radius 12, padding 12px 14px, `body` text, placeholder `--text-faint`. Focus changes the border to `--accent-text` and adds a 3px ring at `rgba(52,179,134,.25)`.
- **Select:** the same as a text field, with a 16px chevron in `--text-muted`.
- **Composer:** the textarea and the primary Send pill in one `--surface-1` container (radius 16, padding 8px). Suggested prompts sit above it as secondary pills in `body-s` that scroll horizontally on mobile.
- **Checkbox:** 18px, radius 5, `--line-input` border; when checked, `--accent` fill with a `--bg` tick.
- **Field label:** `label` style, `--text-muted`, 8px above the field. Error text: `body-s`, `--critical` text, with an icon.

### 5.11 Chat

| Element | Spec |
|---|---|
| **User message** | Right-aligned, max 640px, `--surface-2`, radius 16 16 4 16, padding 12px 16px, `body` `--text-strong`. Meta above it (`body-s` `--text-muted`): name · time. |
| **Agent turn** | Full width of the column, **no bubble**. Header row: logo mark + "AEGIS" in `label` + time + chips (tool calls, tokens). Then the route (5.12), then the answer, then the fact check, then any pending action. |
| **Answer text** | Rendered markdown in `body`, `--text`; headings use `title`; lists get 6px between items; inline code is `code` on `--surface-1`; links are `--accent-text`, underlined. Max 68ch. |
| **Reasoning toggle** | Ghost link "SHOW REASONING ▾"; opens a `--bg-deep` panel with `body-s` `--text-muted`. |

### 5.12 Agent route and live progress (the signature widget)

This is AEGIS's equivalent of the reference's "IP Masking / LIVE" widget, and it is where the
"agentic" behaviour becomes visible. The design is the same while running and when finished.

```
 ● LIVE   step 3 · 14s                                        (live chip, only while running)
 ├─ ✓  Read the question and decided what to do                               0.8s
 ├─ ✓  RUN_INVESTIGATION  version check · lab-web-01                          3.1s
 │     ├ ✓ Verified the signed scope
 │     ├ ✓ Necessity gate: network scan + asset inventory (independent sources)
 │     ├ ! Policy: needs approval for the asset inventory (MCP)
 │     └ ✓ Investigation finished · 5 findings · 1 conflict
 ├─ ●  LOOKUP_CVE  CVE-2020-1938                                              …
 └─ ○  Write the answer
```

- **Spine:** a 1px `--line-strong` vertical line. Nodes are 10px circles: done = `--accent` fill; active = `--accent` ring with a pulse; waiting = `--line-input` ring; failed = `--critical` fill; needs approval = `--high` ring with "!".
- **Main step:** `title` for the tool name, `body-s` `--text-muted` for its arguments, and the duration right-aligned in `code` `--text-muted`.
- **Harness sub-steps:** indented 20px, `body-s`, `--text-muted`. Consecutive repeats collapse into "×n".
- **Expanded tool step:** `--surface-1` card, radius 12, padding 16px. Contents: an icon tile, the title and a status chip, a 2px progress bar (`--surface-3` track, `--accent` fill; it disappears at completion), the findings as list rows (§5.7), cross-checks as rows of "source A says x · source B says y" with an agreement/conflict chip, and the evidence hash in `code`. The full JSON sits behind "TECHNICAL DETAILS ▾" in a `--bg-deep` code panel.

### 5.13 Pending-action card (approval / missing detail)

`--surface-1`, radius 12, 1px border in `--high` (approval) or `--accent` (missing detail), padding 20px.

```
 ⚠ APPROVAL NEEDED                                        policy verdict: ask
 The harness skipped one step of the version check on lab-web-01:
 • the asset inventory (MCP server) · service.enumerate
   because its request was built after reading attacker-controlled data
 ( APPROVE AND RUN AGAIN )   ( Decline )
 Approving answers "yes" to exactly these requests for one rerun.
```

The heading uses `label` with an icon in the border colour; the body is `body-s`; there is one
primary and one secondary button. After it is answered, the card collapses to a single `body-s`
line: "✓ You approved this step · 06:41".

### 5.14 Fact check strip

A full-width row under the answer: `--surface-1`, radius 8, padding 10px 14px, `body-s`.

- **All supported:** a green circled check, then "Fact check · 5 of 5 facts match the evidence (CVE ids, CVSS, run ids)".
- **Issues:** an orange warning icon, then "Fact check · 4 of 5 match", then a checklist of the claims that failed, each with its CVE or run id in `code` and the reason.

### 5.15 Findings and evidence

- **Finding row:** a list row (§5.7). It shows a severity dot and word, the title in `ui`, a status chip ("Confirmed" in `--accent-text`; "Possible · needs checking" in `--text-muted`), and CVE ids in `code`. Opening it shows a detail drawer.
- **Detail drawer:** slides in from the right, 480px wide (full screen on mobile), `--bg` with a `--line` left border. It contains the eyebrow and title, the claims as a checklist, the evidence records as rows with hash and source, and a ghost link "VIEW IN TRACE →".
- **Trace timeline:** the same spine style as §5.12, with `code` timestamps in the left column.
- **Report:** a `--bg-deep` panel with a 64ch column, `display-m` headings, `body` text, and tables with `--line` borders and a `label` header row.

### 5.16 Data visualisation

- **Severity distribution:** horizontal bars 8px tall, radius 4, on a `--surface-1` track, in the severity fill colours, with a `label` name on the left and a `stat-s` count on the right.
- **Activity over time:** an area chart with no axes or grid. The fill is a vertical gradient from `rgba(39,145,107,.35)` down to transparent, with a 1.5px `--accent` line. A single hover tooltip is a `--surface-2` pill. This is the reference's "Usage analytics" treatment.
- **Scope map (home hero visual):** the reference's dotted globe becomes a **dotted network map**. Authorised hosts are dots on a dot grid in `--line-strong`, with lab-web-01, lab-web-02 and lab-logs as `--accent` nodes joined by thin arcs and wrapped in an `--accent-glow`. It is decorative and gets `aria-hidden`; the same information is in text next to it.
- Colour in charts follows §2.4 only. Never use a rainbow of categories.

### 5.17 Icon tile and icons

Icons are line icons with a 1.5px stroke at 18 or 20px (Lucide is a good match), coloured
`--accent` inside tiles and `--text-muted` elsewhere. The hero focal icon (the reference's lock on
a shield) is a 96px glass shield: `--surface-2` at 70% opacity, a 1px `rgba(232,244,240,.12)`
border and a `--mint` glyph, set on a 240px `--accent-glow`. AEGIS uses it once, on the
empty home state and on the login page.

### 5.18 Footer

A band with two cells: the left `--bg` cell holds the logo, a `display-m` line and the primary/
secondary buttons; the right `--bg-deep` cell holds `label` column headers with `body-s`
links. Below them is a row of three icon-tile + title + caption items, then a legal line in
`body-s` `--text-muted`. In the app, only the legal line is used (version · Kelompok 6 · PBKK). The
full footer is only for the login page.

---

## 6. Elevation, glow and texture

| Level | How |
|---|---|
| 0 Canvas | `--bg` |
| 1 Rows, tiles, inputs | `--surface-1` |
| 2 Floating cards, menus, tooltips | `--surface-2` |
| 3 Drawers, dialogs | `--bg` + `--line-strong` border + backdrop `rgba(0,0,0,.6)` with 4px blur |
| Focus of attention | `radial-gradient(closest-side, var(--accent-glow), transparent)` behind the element, 1.5–2.5× its size |

`box-shadow` is used only for the faint mint glow on the primary button and for focus rings.

**Photography:** this is optional and only for login and marketing pages. Use a three-stop
duotone gradient map, `--accent-deep` → `--duo-mid` → `--duo-light`, at 90% opacity on `--bg`,
grain-free, framed by hairlines. Never use colour photos.

---

## 7. Motion

| Token | Value | Use |
|---|---|---|
| `--ease` | `cubic-bezier(.2,.7,.2,1)` | Everything |
| `--dur-fast` | 120ms | Hover, press, colour changes |
| `--dur` | 200ms | Expand/collapse, chip changes, row arrow nudge |
| `--dur-slow` | 360ms | Drawer, dialog |
| `--pulse` | 1.2s ease-in-out infinite, opacity 1 → .3 | LIVE dot, active route node, status-bar agent dot |

There is one choreographed moment: on the home page, the scope-map arcs draw in once (600ms,
staggered 80ms). Everything else moves only in answer to the user or to agent progress. A new
route step fades in over 120ms; it does not slide. With `prefers-reduced-motion: reduce`, all
animation stops and the pulse becomes a static ring.

---

## 8. Voice in the interface

The reference copy is short and imperative. AEGIS keeps that, about its own work:

- Kicker plus headline: `SIGNED LAB SCOPE` / `IS YOUR LAB SAFE?`; `AGENT ACTIVITY` / `WHAT THE AGENT DID`.
- Buttons say what will happen: "Run investigation", "Approve and run again", "Open full report".
- The agent speaks in the first person in answers. The interface itself does not. Errors state the cause and the fix: "The language model could not be reached. Check LLM_BASE_URL and your network."
- Technical identifiers stay exact (CVE ids, versions, run ids), set in the mono face.

---

## 9. Page recipes

### 9.1 Home / conversations (`chat.index`)

```
[status bar]
[top nav]
┌ frame ───────────────────────────────────────────────────────────────┐
│ SIGNED LAB SCOPE                                  ┌ floating card ┐  │
│ IS YOUR LAB SAFE?                                 │ Last run …    │  │
│ lead                                              └───────────────┘  │
│ [ composer: ask a question …            ( ASK THE AGENT ) ]          │
│ (prompt) (prompt) (prompt)                    dotted scope map →     │
├───────────────┬───────────────┬───────────────┬──────────────────────┤
│ conversations │ tool calls    │ investigations│ open findings        │ stat row
├───────────────┴───────────────┴───────────────┴──────────────────────┤
│ RECENT CONVERSATIONS                                                 │
│ [row →] [row →] [row →]                                              │
├───────────────────────┬───────────────────────┬──────────────────────┤
│ PORT SCAN             │ LOG ANALYSIS          │ VERSION CHECK        │ skill cells (bento)
│ ✓ capabilities…       │ ✓ …                   │ ✓ … (MCP)            │
│ RUN →                 │ RUN →                 │ RUN →                │
└───────────────────────┴───────────────────────┴──────────────────────┘
```

### 9.2 Conversation (`chat.show`)

The title block (`display-l`, with the mode and start time in `body-s`) is followed by the thread
in one cell 760px wide, centred in the frame: user messages, then agent turns with route, answer,
fact check and pending action. The composer sticks to the bottom of the frame, with the live
progress (§5.12) rendered **above the composer** while a turn runs. The Week 9 query inspector
stays as a collapsed band at the bottom with the `label` "QUERY INSPECTOR · PERTEMUAN 9".

### 9.3 Investigation workspace (`investigations.index`)

The page has a title block, a run selector (select field) with a status chip, and a "+ New
investigation" secondary pill. Below sits the tab strip (§4.3). Overview shows a stat row, then
a two-cell band with the objective and severity bars, then finding rows. The other tabs are
Findings (rows with a filter field), Evidence (rows), Trace (spine timeline with a playback
control), Activity (rows) and Report (`--bg-deep` reading panel).

### 9.4 Login

The page splits into two cells. The left cell holds the logo, the eyebrow "AGENTIC SECURITY
INVESTIGATION", a `display-l` headline, a short lead, and the form (fields + primary pill). The
right cell (`lg` and up) shows the glass shield on its glow over the dotted scope map. The full
footer (§5.18) sits below.

---

## 10. Implementation

### 10.1 CSS custom properties

Put these in `resources/css/aegis.css`, replacing the current token block.

```css
:root {
  color-scheme: dark;
  --bg:#080808; --bg-deep:#000; --surface-1:#121212; --surface-2:#1c1c1c; --surface-3:#242424;
  --line:#161616; --line-strong:#262626; --line-input:#666; --grid-dot:#d9d9d9;
  --text-strong:#ececec; --text:#a3a3a3; --text-muted:#868686; --text-faint:#5c5c5c; --text-on-mint:#080808;
  --accent:#27916b; --accent-text:#34b386; --accent-bar:#1f7a59; --mint:#e8f4f0;
  --accent-wash:#11201d; --accent-glow:rgba(39,145,107,.28); --accent-deep:#02261a;
  --duo-mid:#5c8577; --duo-light:#b1c3bd;
  --critical:#d00020; --critical-text:#ff6b6b; --high:#d1872d; --high-text:#e0943a;
  --medium:#a8962f; --medium-text:#d4c15a; --low:#3d7a64; --low-text:#7fb39f; --info:#4a4a4a;
  --font-display:"Geist Mono Variable","Geist Mono","JetBrains Mono","IBM Plex Mono",ui-monospace,monospace;
  --font-sans:"Geist Variable","Geist","Inter","Segoe UI",system-ui,sans-serif;
  --radius-row:8px; --radius-card:12px; --radius-tile:10px; --radius-pill:999px;
  --ease:cubic-bezier(.2,.7,.2,1); --dur-fast:120ms; --dur:200ms; --dur-slow:360ms;
  --frame-max:1280px;
}
:root[data-theme=light] { color-scheme: light; /* values from §2.6 */ }
body { background:var(--bg); color:var(--text); font:400 15px/1.6 var(--font-sans); }
```

### 10.2 Tailwind (`tailwind.config.js`)

Preflight stays disabled, as it is now. Tailwind is only for layout utilities. Colour comes from
the variables, so both themes work:

```js
theme: { extend: {
  colors: { bg:'var(--bg)', surface:{1:'var(--surface-1)',2:'var(--surface-2)',3:'var(--surface-3)'},
            line:'var(--line)', accent:{DEFAULT:'var(--accent)', text:'var(--accent-text)'}, mint:'var(--mint)' },
  fontFamily: { display:'var(--font-display)', sans:'var(--font-sans)' },
  borderRadius: { row:'8px', card:'12px', tile:'10px' },
  maxWidth: { frame:'1280px' },
}}
```

### 10.3 Mapping from the current classes

| Current | Becomes |
|---|---|
| `.sidebar` + `.nav` | Top nav (§4.3) + workspace tab strip |
| `.topbar` / `.environment` | Status bar |
| `.panel` | Frame band or cell (no radius, hairline borders) |
| `.stat` / `.stats` | Stat row (§5.3) |
| `.finding-row`, `.session-row` | List row (§5.7) |
| `.steps` / `.step` / `.live-steps` | Agent route (§5.12) |
| `.action-card` | Pending-action card (§5.13) |
| `.fact-check` | Fact-check strip (§5.14) |
| `.button.primary` / `.button` | Primary / secondary pill |
| `.severity`, `.severity-dot` | Severity chip (§5.8) |
| `.rendered-report` | Answer text / report panel (§5.11, §5.15) |

---

## 11. Accessibility

Each token pair was measured with the WCAG 2.1 formula; rerun `python3 docs/design/contrast_check.py` after changing a token. Text needs 4.5:1
(AA); large text and UI boundaries need 3:1.

| Pair | Ratio | Result |
|---|---|---|
| `--text-strong` on `--bg` | 16.95 | AA, AAA |
| `--text` on `--bg` | 7.94 | AA, AAA |
| `--text` on `--surface-2` | 6.76 | AA |
| `--text-muted` on `--bg` / `--surface-1` / `--surface-2` | 5.50 / 5.15 / 4.68 | AA |
| `--accent` on `--bg` (eyebrows, icons) | 5.10 | AA |
| `--accent-text` on `--bg` / `--surface-1` | 7.57 / 7.08 | AA, AAA |
| white on `--accent-bar` | 5.27 | AA (the reference's `#27916b` bar gives 3.93: fails, so it is darkened) |
| `--text-on-mint` on `--mint` (primary button) | 17.77 | AA, AAA |
| `--critical-text` on `--bg` | 7.22 | AA |
| `--high-text` on `--bg` / `--surface-1` | 8.07 / 7.55 | AA |
| `--medium-text` on `--bg` | 11.04 | AA |
| `--low-text` on `--bg` | 8.44 | AA |
| `--critical` dot on `--bg` (non-text) | 3.53 | 3:1 |
| `--line-input` on `--surface-1` (field border) | 3.26 | 3:1 |
| `--line` on `--bg` | 1.11 | Decorative only, so it is never the only cue |

Further rules:

- Focus is always visible: a 2px `--accent-text` outline with 3px offset. It is never removed.
- Severity, status and route nodes always pair colour with a word or symbol (✓ ! × ●).
- Live regions: the route list has `aria-live="polite"`; the final answer moves focus to the turn heading.
- Hit targets are at least 40px tall for pills and 44px for list rows on touch.
- Uppercase is achieved with `text-transform`, never typed in capitals, so screen readers read words normally.
- Respect `prefers-reduced-motion` (§7) and keep layouts working at 200% zoom.

---

## 12. Do and don't

| Do | Don't |
|---|---|
| Separate sections with hairlines and padding | Add drop shadows or gaps between frame cells |
| Keep green for meaning (done, allowed, links, kickers) | Tint whole panels green, or use green for decoration |
| One mint primary button per region | Two light buttons side by side |
| Mono uppercase for short titles and labels | Uppercase sentences or body text |
| Put exact ids (CVE, run, hash) in mono | Paraphrase or round technical identifiers |
| A glow behind one focal element per view | Glows behind every card |
| Show the agent's route the same way live and afterwards | A separate "loading" design that disappears |
| Use the duotone only for optional imagery | Colour photos, stock "hacker" imagery, globes of countries |

---

## 13. Reference analysis (how this was derived)

- **Colours:** the reference board (1600×1200) was sampled pixel by pixel. Dominant and quantised palettes were taken per region (announcement bar, hero, rows, floating card, buttons, photo duotone), and the peak text colours were measured per text role. The adjusted values in §2 are the measured ones, moved only where §11 required it.
- **Type:** identified from zoomed crops. The headlines are a light geometric monospace with even widths, uppercase, at about 2.9× their size on the board. Body and UI text is a neo-grotesque sans. Geist Mono and Geist are the closest freely licensed match (SIL OFL).
- **Structure:** zoomed crops of the stat row and the frame corners show 1px `#161616` lines and about 3px bright dots at the intersections. The rows show radius 8; the floating card, tiles and pricing cards show radius 12; every button is a pill.
- **Not taken:** the product content and imagery (VPN, countries, pricing, people, the globe). These are replaced by AEGIS content and the dotted scope map.
