# Adaptive IAM workspace design

The console helps a person sign in, review access and inspect security decisions. Every result comes from the API. The separate Orbit SaaS relying party is linked from navigation.

## Visual decisions

The user's palette is white, black and orange. Light mode uses white surfaces (`#ffffff`), a neutral canvas (`#f5f6f7`), near-black text (`#18191b`) and orange actions (`#c64b0a`). Dark mode uses charcoal surfaces (`#1b1c1f`), a black canvas (`#121315`), light text (`#f4f4f5`) and brighter orange (`#ff9a52`). Muted green, amber and red carry security status only.

Segoe UI with a local system fallback keeps the app readable on Windows. Body copy is 14–15 px, forms are 15 px (16 px on phones), supporting text is 12–13 px, panel headings are 18 px and page headings are 28–29 px. Never shrink content to fit a crowded view.

The visual signature is a quiet white/charcoal workspace with one orange primary action. Active navigation has strong black/white contrast. Panels group real tasks, with borders communicating separation. Avoid decorative gradients, fake charts and repeated sign-in prompts.

## Layout

```text
236 px navigation       Toolbar: current page, theme, identity
                        Page title and short purpose
Overview                Main action or live workspace state
Security                Tabs for longer workflows
Risk lab                Readable form / actual result
Attack lab              Secondary details disclosed on request
Access requests
Audit ledger
Experiments
Developer portal

Orbit SaaS              Footer with research environment status
API connection
```

Below 960 px navigation becomes a vertical menu with an explicit open/close control, backdrop, Escape handling and focus containment. It never becomes a horizontal strip. Narrow pages use one column, wrapped tabs, 44 px controls and tables that scroll inside their panel. Target widths include 390 px and 437 px.

React Router provides real page URLs and browser back/forward behavior. `/connect?request_id=...` remains the website consent entry. The sidebar stays consistent on every page.

## Hierarchy and interactions

- Signed-out Overview has one sign-in entry and a short explanation. Public experiments and risk checks remain discoverable.
- Experiments starts with keyboard-accessible study links. Stable section anchors and URL model-family state support shared links and browser history; all evidence panels remain available, including retry states.
- Access, Security and Developer pages use tabs to focus each task. Context customization, model details, hashes and protocol diagnostics use disclosure sections.
- One offline banner explains recovery. A compact sidebar indicator reports connection state.
- Sign-in stays in a focused dialog. Scenario customization is secondary to identity and verification.
- Success appears only after server confirmation. The client never grants access or fabricates activity.
- Session tokens remain in sessionStorage. Theme preference alone is in localStorage. Authorization stays server-enforced.
- Visible focus, keyboard navigation, reduced motion and both themes are required.

## Brief review

The previous decision journey repeated sign-in prompts and reduced mobile text to 9–11 px. It was removed in favor of a clear entry state, plain task names and fewer simultaneous controls. This administrative workspace prioritizes legibility and traceable decisions.

The stylesheet consolidates repeated top-level selectors and groups responsive behavior at the end. Extend existing primitives before adding layout rules.

## Verification

Run `npm run build` for TypeScript and production assets. The root workflow checks the actual browser at desktop and phone widths, both themes, menu navigation, consent, sign-in and protected actions. A passing build alone does not establish completed browser verification.
