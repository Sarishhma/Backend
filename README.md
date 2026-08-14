# Auth System 

A backend authentication system built from first principles to understand real-world auth architecture — not just implement it, but understand *why* each piece exists.

## Overview

This project implements a complete, production-style authentication flow: user registration with OTP verification, JWT-based sessions with refresh token rotation, and httpOnly cookie storage — built to deeply understand statelessness, token lifecycle, and the security tradeoffs behind common auth patterns.

## Tech Stack

- **Runtime:** Node.js
- **Framework:** Fastify
- **ORM:** Prisma
- **Database:** PostgreSQL
- **Auth:** JWT (access + refresh tokens), httpOnly cookies
- **Password hashing:** bcrypt

## Features Implemented

### Registration & Verification
- User signup with email/password
- OTP (One-Time Password) generation and email-based verification before account activation
- Password hashing with bcrypt (understood and chosen over SHA-256 for its adaptive cost factor and resistance to brute-force/rainbow-table attacks)

### Authentication & Session Management
- Login issuing a short-lived **access token** and a longer-lived **refresh token**
- **Refresh token rotation** — each refresh request issues a new refresh token and invalidates the old one, limiting the damage window if a token is ever leaked
- **httpOnly cookies** for token storage — chosen over localStorage specifically to mitigate XSS-based token theft, since JavaScript cannot access httpOnly cookie contents
- Logout endpoint that clears cookies and invalidates the active refresh token server-side

### Security Principles Applied
- Stateless request authentication via JWT, understood in the context of HTTP's stateless nature
- "Never trust the client" — all validation and authorization checks enforced server-side, not assumed from client state
- CORS configuration to control which origins can interact with the API
- Awareness of CSRF risk with cookie-based auth, and mitigations considered (SameSite cookie attributes, CSRF tokens where relevant)
- TLS/HTTPS as the transport-layer assumption underpinning cookie and token security


## What's Next

Planned additions to extend this into a more complete, production-grade auth system:

- [ ] **Role-Based Access Control (RBAC)** — middleware to guard routes by user role/permission
- [ ] **Rate limiting** on login and OTP endpoints to prevent brute-force and OTP-spam abuse
- [ ] **Account lockout / backoff** after repeated failed login attempts
- [ ] **Password reset flow** (forgot password via email token, separate from OTP signup flow)
- [ ] **Session management dashboard** — list active sessions/devices, allow user to revoke individual sessions (not just "logout all")
- [ ] **Refresh token reuse detection** — detect and respond to a stolen/replayed refresh token being reused after rotation (a common real-world attack signal)
- [ ] **Audit logging** for auth events (login, logout, failed attempts, password changes)
- [ ] **Multi-factor authentication (MFA)** beyond signup OTP — e.g. optional TOTP-based 2FA for login
- [ ] **OAuth / social login** (Google, GitHub) as an alternative auth method
- [ ] **Email verification resend with cooldown** to prevent OTP spam
- [ ] **API documentation** (Swagger/OpenAPI via Fastify plugin)
- [ ] **Test coverage** — unit tests for services, integration tests for auth flow end-to-end

## Learning Goals

This project is intentionally built to understand *architecture*, not just to ship features:
- Why JWT over sessions (and the tradeoffs — statelessness vs. revocability)
- Why httpOnly cookies over localStorage for token storage
- Why refresh rotation matters and what attack it defends against
- The full lifecycle of a token from issuance to expiry to rotation to revocation

## License

Personal learning project.
