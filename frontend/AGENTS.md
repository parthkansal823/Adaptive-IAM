# Frontend scope

- React + TypeScript + Vite; vanilla CSS. Keep this dependency set small.
- Read `DESIGN.md` before changing layout or tokens. Both themes and mobile are required.
- `src/api.ts` defines the backend contract. Real API results only; do not fabricate charts, activity, or successful actions.
- Store bearer tokens in sessionStorage, theme only in localStorage. Use the server's identity for votes.
- Run `npm run build` for frontend changes. Keep errors actionable and controls keyboard accessible.
- Load only the files needed for the task. Use `rg` before reading whole directories.
