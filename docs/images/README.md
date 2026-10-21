# Verified browser previews

## Redesign verified on 14 October 2026

Current Docker builds use React 19.3, TypeScript 7 and Vite 8. The console routes were inspected at 1440px and 390px; the SaaS workspace was inspected on desktop and at 390px. Document widths stayed within the viewport. Navigation, focus, Escape dismissal, themes, project filters and the authorized local OAuth consent journey were checked against the running API.

- [Console overview, light](repair-overview-light.jpg): clear signed-out entry and research tools.
- [Risk assessment, dark](repair-risk-dark.jpg): submitted suspicious scenario and actual model response, explicitly synthetic.
- [Security, narrow dark](repair-security-mobile-dark.jpg): readable factor controls without exposing enrolled credentials.
- [Orbit home, dark](repair-orbit-home-dark.jpg): sample business records clearly identified.
- [Orbit dashboard, light](repair-orbit-dashboard-light.jpg): actual Aisha demo identity after OAuth/OIDC sign-in.
- [Protected report, dark](repair-orbit-report-dark.jpg): existing live read grant checked before returning the report.
- [Orbit account, narrow light](repair-orbit-account-mobile-light.jpg): identity and session information from the provider.

Browser report access was checked with an existing synthetic grant. No-grant, revocation, session mismatch and provider outage behavior are separately covered by the HTTP/SDK tests. Local screenshots and test data are not production security evidence. Sessions and grants expire.

## Earlier captures

Captured from the local Docker prototype on 10 October 2026, using the seeded Aisha demo identity and synthetic resources. These screenshots show UI behavior, not deployment accuracy or production security evidence.

- [Dark console](console-dark.jpg) and [light console](console-light.jpg): live API connection, evaluated sign-in, completed demo MFA and active resource grant.
- [Narrow consent screen](consent-mobile.jpg): verified at a 400-pixel viewport without horizontal document overflow.
- [Connected website](website-protected.jpg): OAuth/OIDC sign-in followed by a server permission check before the protected page is returned.
- [Compact console preview](console-preview.jpg): current overview for sharing in the project handoff.

The console and website run at `http://127.0.0.1:5173/` and `http://127.0.0.1:3001/`. Grants and sessions expire; screenshots are historical captures rather than current access guarantees.

## New verified views

- [Security, dark](security-v2-dark.jpg): password verification for first enrollment, server factor/session state. No factor secrets are captured.
- [Attack Lab, dark](attack-lab-v2-dark.jpg): actual running-model response to a fake-vote claim and separate human/grant checks; the diagnostic creates no grant.
- [Developer Portal, light](developer-v2-light.jpg): actor-scoped organization/app views and callback diagnostics with unregistered status explicit.
- [Developer mobile](developer-v2-mobile.jpg) and [Security mobile](security-v2-mobile.jpg): checked at 400-pixel viewport, document width 385 pixels; tables scroll within their container.

Passkey cryptographic verification and TOTP/recovery behavior were tested in isolated Linux, using software-generated P-256 responses. These screen captures do not claim physical authenticator enrollment.
