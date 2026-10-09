# Adaptive IAM design system

The subject is contextual identity and collective access authorization. This is a research workbench: assessments, grants, votes, integrations, and experiments use actual API results.

## Tokens

| Token | Light | Dark | Purpose |
| --- | --- | --- | --- |
| Canvas | `#f5f5f5` | `#101010` | Quiet work area |
| Surface | `#ffffff` | `#191919` | Functional regions |
| Ink | `#171717` | `#f3f3f3` | Main content |
| Navigation | `#111111` | `#090909` | Persistent rail |
| Orange | `#c2410c` | `#fb923c` | Action, focus, and assessment |
| Muted | `#666666` | `#aaaaaa` | Supporting text |

The user's final palette direction is white, black, and orange. Low-risk verified states are monochrome, with amber and muted red reserved for risk semantics. Orange controls use white text in light mode and black text in dark mode for contrast.

Type uses locally available Segoe UI with a humanist system fallback. Headings have compact spacing, labels stay in sentence case, and tabular numerals align measurements. Core sizes are 10, 12, 14, 16, 20, 28, and 34 px. Borders communicate group boundaries. Controls use 7 px radii and panels 12 px; status indicators are round.

## Layout

Left-aligned content uses a fixed navigation rail and flexible workspace. The centerpiece is a horizontal assessment journey: identity context, model risk, adaptive policy, and collaborative resource access. The small graph uses actual LR, RF, and ensemble probabilities. On mobile, the journey becomes a two-column sequence and navigation remains swipeable.

```text
Navigation       Workspace / Overview                      Theme / Identity
                 Access, with context.                     Run a context check
Overview         [identity] → [risk probabilities] → [policy] → [resource]
Risk lab
Access requests  Workspace metrics, separated by quiet rules
Audit ledger     Recent decisions                 Policy boundaries
Experiments      Requests in motion
Connected apps   Research evidence
```

## Brief review and refinement

Identical metric cards and decorative charts would feel like an ordinary admin template. Instead, one large decision journey anchors the page; open metrics, meaningful tables, and clear request details provide the rest. A black rail and orange data traces connect the identity theme. Data absence is visible rather than filled with invented examples. Light and dark modes are equally designed.

## Interaction rules

- Show successful actions only after API confirmation. Keep failures actionable.
- Label seeded demo identities and credentials explicitly. Keep bearer tokens in sessionStorage; theme alone goes in localStorage.
- Use the API's current policy thresholds rather than hardcoded chart ranges.
- Public assessments do not create sessions. MFA, votes, grants, and resource reads remain server-enforced.
- Connected apps use exact registered callbacks and PKCE. Consent never creates a resource grant.
- Support visible keyboard focus, modal focus containment, semantic forms, reduced motion, and narrow screens.

## Verification

`npm run build` checks TypeScript and produces the static application. The root workflow separately checks actual browser behavior for theme, risk assessment, identity, request/reviewer workflow, consent, and responsive layout.
