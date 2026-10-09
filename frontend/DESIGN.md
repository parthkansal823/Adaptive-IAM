# Aegis design system

The subject is contextual identity and collective access authorization. The interface is a research workbench: every assessment, grant, vote, and experiment is backed by the API.

## Tokens

| Token | Light | Dark | Purpose |
| --- | --- | --- | --- |
| Canvas | `#f3f6fa` | `#101827` | Quiet work area |
| Surface | `#ffffff` | `#162135` | Raised functional regions |
| Ink | `#13213c` | `#e7edf6` | Main content |
| Navy | `#111d33` | `#0d1626` | Persistent navigation |
| Blue | `#3478e5` | `#76a7fb` | Action and assessment |
| Teal | `#16867b` | `#65c8b8` | Verified state |

Type uses locally available Segoe UI with a humanist system fallback; headings have compact spacing, labels stay in sentence case, and tabular numerals align measurements. Core sizes are 12, 13, 14, 16, 20, 28, and 34 px. Borders communicate group boundaries; radius varies by hierarchy: 8 px controls, 12 px panels, fully round status indicators.

## Layout

Left-aligned content uses a fixed navigation rail and a flexible workspace with a maximum width. The unique centerpiece is a horizontal assessment journey: identity context, risk score, policy response, access decision. A measured waveform comes from actual assessment component values. The route collapses into a vertical sequence on small screens.

```text
┌───────────┬───────────────────────────────────────────────────────┐
│ Aegis     │ Workspace / Overview                       Theme User │
│           ├───────────────────────────────────────────────────────┤
│ Overview  │ Adaptive access, in context.              Run a check │
│ Risk lab  │ [context] ── [risk signal] ── [policy] ── [access]     │
│ Requests  │                                                       │
│ Ledger    │ Actual session metrics     │ Recent decisions         │
│ Research  │ Resource access            │ Workflow summary         │
│           │                                                       │
│ API state │ Research notes and direct links to experiments        │
└───────────┴───────────────────────────────────────────────────────┘
```

## Brief review and refinement

Identical metric cards and decorative charts would make this feel like an ordinary admin template. Instead, use one large decision route, a compact row of separated measurements, open tables, and a restrained scientific workbench layout. Data visualizations are clearly labeled with real measured values or no-data states. Light and dark modes are equally designed. Only user-triggered transitions animate; reduced motion is honored.

## Interaction rules

- Never fabricate activity or show successful actions before the API confirms them.
- Authentication explicitly labels the local seeded demo credentials. Session tokens live in sessionStorage; theme preferences alone live in localStorage.
- Assessment inputs are editable and deterministic presets are named for their context.
- Errors explain the failed action and provide retry. Offline state remains visible.
- Keyboard focus, semantic forms, chart text alternatives, narrow-screen navigation, and clear contrast are part of the interface.
