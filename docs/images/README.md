# Verified browser previews

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
