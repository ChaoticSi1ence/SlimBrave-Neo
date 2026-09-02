# Known bugs — `experiment/fluent-gui`

Running list of defects found in the Fluent GUI beta (`SlimBrave.ps1`).

---

## 1. Status text overlaps the action buttons after Apply

**Reported:** 2026-09-02 (found on a secondary desktop; not visible on the main laptop)
**Severity:** Cosmetic, but the message is the only feedback Apply gives — when it's
unreadable the user can't tell what happened.

### Symptom

After clicking **Apply Settings**, the status message in the bottom bar runs to the
right, underneath the **Export / Import / Re-sync / Reset / Apply Settings** buttons.
The text shows through the gaps between buttons and is cut off behind them, and the
tail of the message continues past the right edge of the window where it can't be
read at all.

### Cause

The bottom bar paints its status string with no width bound and no clipping:

- `SlimBrave.ps1:1800-1802` — `$bar` is a fixed `930 x 68` panel at `x=250`.
- `SlimBrave.ps1:1810` — `$g.DrawString($script:statusText, $capFont, $b, 20, 26, $SF)`
  draws from `x=20` with no layout rectangle, so GDI+ renders the full string on one
  line however long it is.
- `SlimBrave.ps1:1897-1900` — the button row starts at a hardcoded `$bx=430`.

That leaves the status text exactly **410 px** of runway before it reaches the Export
button. The buttons are separate child `Panel` controls, so the overflowing text is
painted onto the bar *behind* them and bleeds through the 8 px gaps.

The Apply message is built at `SlimBrave.ps1:1428` and, when a leaked-prefs repair ran,
has `Get-RepairNote` (`SlimBrave.ps1:1296-1308`) appended. Measured at 100% scaling:

| Status message | Text ends at | Fits in 410 px? |
|---|---|---|
| `Ready` | x=55 | yes |
| `Applied 47 policies. Restart Brave, then check brave://policy.` | x=332 | yes |
| ...same, plus the "Also cleaned N leaked profile prefs" note | **x=681** | **no — 251 px under the buttons** |
| ...same, plus the "Brave is running, so leaked profile prefs were left alone..." note | far past the bar | **no** |

So the longest and most important messages — the ones that ran a repair or need the
user to close Brave and re-run — are exactly the ones that get buried.

### Fix sketch

`Fit-Text` already exists at `SlimBrave.ps1:1924` and does binary-search ellipsis
truncation against a pixel width; the row captions use it. Reuse it here — truncate the
status string to `$bx_first - 20 - padding` before drawing, and put the untruncated text
in a tooltip or the window title so nothing is lost. Better still, don't hardcode the
budget: track the leftmost button's `x` when the row is built and measure against that.

---

## 2. Button row runs off the right edge of the window at >100% display scaling

**Reported:** 2026-09-02 (same session — this is why the desktop showed it and the
laptop didn't; the two machines run different display scaling.)
**Severity:** Functional. At 150% the Apply Settings button is partly unclickable.

### Symptom

The **Apply Settings** button — and at higher scaling, Reset too — extends past the
right edge of the bar and off the form, so it is clipped or unreachable.

### Cause

The app opts into per-monitor DPI awareness V2 (`SlimBrave.ps1:63-100`), which tells
Windows *not* to bitmap-scale it — the app takes responsibility for its own layout. But:

- every coordinate is a hardcoded pixel literal (`$form.ClientSize = 1180, 760` at
  `SlimBrave.ps1:1643`; bar at `250, 692` sized `930 x 68`),
- while every font is specified in **points** (`SlimBrave.ps1:1649-1658`), so GDI+ grows
  the glyphs with DPI,
- and button width is derived from the rendered text at `SlimBrave.ps1:1816`
  (`MeasureText($label,$btnFont).Width + 34`).

Text-derived widths grow with scaling; the container they're packed into does not.
Modelled across scale factors (button row starts at x=430, bar inner width 930):

| Scaling | Button row ends at | Overflow |
|---|---|---|
| 100% | x=909 | fits, 21 px to spare |
| 125% | x=966 | **36 px past the bar** |
| 150% | x=1031 | **101 px past the bar** |
| 175% | x=1120 | **190 px past the bar** |

There is only 21 px of slack at 100%, so the row overflows as soon as scaling moves off
100%. And because the bar sits at `x=250` with width `930` inside an `1180`-wide client
area, its right edge is already flush with the form — overflow leaves the window
entirely. `FormBorderStyle = FixedSingle` with `MaximizeBox = $false`
(`SlimBrave.ps1:1644-1645`) means the user can't resize to recover.

Bug 1 gets worse on the same axis: the status text's 410 px budget is fixed while the
text itself grows, so it starts colliding with the buttons at 150% even for the short
`Applied N policies...` message with no repair note.

### Fix sketch

Right-anchor the button row instead of left-positioning it: lay the buttons out from the
bar's right edge leftward, so the row grows into the free space in the middle rather than
off the form. Then derive the status text's width budget from wherever the leftmost
button landed. A broader fix is to scale the hardcoded layout constants by
`CreateGraphics().DpiX / 96`, but the anchor change fixes this bar without touching the
rest of the pixel grid.

---

*Both issues are layout-only. Policy writing, Export/Import and Reset behave correctly —
only the reporting of the result is affected.*
