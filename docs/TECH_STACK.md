# Technology decisions

Reviewed against official documentation on **14 October 2026**. These choices fit the existing IAM provider, separate relying-party website and reproducible Python experiments. Upstream capabilities do not measure this project's speed or establish production readiness.

## Selected implementation

| Layer | Repository choice | Reason |
| --- | --- | --- |
| IAM console | React / React DOM **19.3.0**, TypeScript **7.0.2** | Preserve typed security flows while updating supported tooling. React 19.3 adds stable view transitions and fragment refs; an upgrade need not enable every new API. |
| Console build | Vite **8.3.4**, React plugin **6.1.2** | Static console delivery with the existing Python API. Vite 8 uses Rolldown/Oxc; vendor benchmark figures are not application measurements. |
| Console navigation | React Router DOM **7.18.4** | URL-based navigation, browser history and stable page entry points without introducing a second policy server. Route and browser verification are part of this upgrade. |
| JavaScript runtime | **Node.js 24 LTS** in Docker builds/website and CI | A supported LTS line shared by UI tooling and the Node relying party. Its stricter OpenSSL defaults make integration checks important. |
| Provider / experiments | **Python 3.13**, FastAPI **0.141.1**, Pydantic **2.13.5**, Uvicorn **0.53.0** | Keep policy, identity and Python model execution together. API/analysis Docker images and CI share a Python minor line; requirement files hold exact pins. |
| Business website | Separate Node server and reusable OIDC SDK | Orbit's server owns PKCE, code exchange and tokens, and checks current provider permissions before each protected response. Business records are sample data. |
| Local persistence | SQLite policy store and audit chain | Suitable for a single-host research prototype. Hash chaining is local tamper evidence, not distributed trust or a horizontally scaled database. |
| Web3 | Solidity registry, local EVM mode and optional Besu QBFT | Preserve explicit chain/client configuration and fail-closed grant checks. See [Web3 upgrades](WEB3_UPGRADES.md) and [operations](WEB3_NETWORK.md) for topology, signer restrictions, readings and trust limitations. |

The pins are in [frontend/package.json](../frontend/package.json) and [backend/requirements.txt](../backend/requirements.txt). Docker base tags select runtime lines; they are not immutable image digests. An independent deployment should lock reviewed image digests and maintain a patching process.

Primary references: [React 19.3](https://react.dev/blog/2026/09/09/react-19-3), [TypeScript 7.0](https://devblogs.microsoft.com/typescript/announcing-typescript-7-0/), [Vite 8 and React plugin 6](https://vite.dev/blog/announcing-vite8), [React Router modes](https://reactrouter.com/start/modes), [Node 22 to 24 migration](https://nodejs.org/en/blog/migrations/v22-to-v24), and [FastAPI container deployment](https://fastapi.tiangolo.com/deployment/docker/).

## Alternatives and next deployment boundary

**Next.js 16.2 was reviewed.** It supplies server-rendered React and updated Turbopack tooling. The authenticated console already has a Python authority, and Orbit demonstrates a server-side relying party. Migration would introduce another runtime and authentication integration to validate; it would not resolve layout/navigation problems by itself. Next.js is not installed. Revisit it for server-rendered public content or a larger full-stack React product. This is a project-specific decision. [Next.js 16.2 release](https://nextjs.org/blog/next-16-2).

**PostgreSQL 18 is a future multi-instance option.** The official project identifies this database release; it is not installed or configured here. Migration needs a portable storage layer with SQLAlchemy/Alembic, verified constraints and data, concurrent grant/token transition tests, backup/restore procedures, and durable shared website sessions. A connection-string change would leave current SQLite SQL and transaction assumptions unresolved. [PostgreSQL project FAQ](https://www.postgresql.org/about/press/faq/).

Redis, external observability backends, managed key custody and public-chain deployments remain deployment choices, not implemented services. Add them for a measured operational requirement and validate failures before claiming support. LLMs and Web3 remain subordinate to verified identity and server policy; neither may create an authorization bypass.

## Verification and evidence

Verified on 14 October: Python 3.13 backend **112 discovered tests including six skips**, all **23 Node SDK/SaaS HTTP tests**, all **15 Node 24 contract/RPC fixture checks**, and the final TypeScript 7 / Vite 8 / React Router build passed. All console routes were reviewed at **1440px and 390px**, in both themes, including menu focus/Escape behavior and horizontal-overflow checks. A live risk assessment also completed; its displayed score is an individual diagnostic, not a benchmark improvement.

Orbit home/plans and login redirect passed browser checks. After the user's explicit authorization, browser consent, Aisha's dashboard and the protected report with an actual live read grant returned successfully (HTTP 200). Project search returned one Usage result; the On track filter returned two projects. Account settings and all authenticated website routes were also checked at 390px without document overflow; light and dark views were reviewed. The live Docker OIDC smoke and all 11 isolated live Ganache checks passed. [Browser captures](images/README.md) record the inspected views.

All five phases in the [live Besu artifact](../experiments/qbft-failover-results.json) passed: baseline, primary-reader outage with failover and a newly confirmed anchor, another single-validator outage, two-validator outage denying access/new anchors, and recovery with on-chain revocation. These are crash tests on one administrative host, not independent production consensus validation. [Web3 upgrades](WEB3_UPGRADES.md) explains the findings; [SAAS_WEBSITE.md](SAAS_WEBSITE.md) explains the business journey.

No new model accuracy, performance multiplier or production scale is implied. Experiment JSON files and the research report remain the model evidence. Original research assets remain preserved.
