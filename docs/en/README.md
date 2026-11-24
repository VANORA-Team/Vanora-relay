# Vanora Relay Documentation Hub

[← Back to Home](../../README.en.md) · [简体中文](../README.md) | **English**

Welcome to the official **Vanora Relay** documentation. Guides are organized by role and technical topic so you can deploy a relay, integrate desktop or mobile clients, implement custom protocol clients, or audit the security model.

---

## Start by Goal

- **I want to self-host an account-free public relay** → [Server Deployment & Operations §3 Self-Hosted Node](deployment.md#3-self-hosted-node-relay_channelself-account-free)
- **I want to embed remote access into a desktop app or control another PC** → [Desktop Adapter Guide](desktop.md)
- **I am building an Android or iOS app** → [Mobile SDK Integration Guide](mobile.md)
- **I want to implement a custom non-Go client or inspect the wire protocol** → [Protocol & Custom Client Reference](protocol.md)
- **I want to evaluate trust boundaries or run the security test suite** → [Security Model & Verification](security.md)

---

## Core Guides

| Document | Audience | Summary |
| :--- | :--- | :--- |
| **[Server Deployment & Operations](deployment.md)** | Ops / Self-Hosters | Channel modes, complete env matrix, account-free self-hosting (`systemd` / Caddy / Nginx), CN/GLOBAL strict isolation, pre-auth rate limits & entitlement API |
| **[Desktop Adapter Guide](desktop.md)** | Desktop Users / Integrators | `vanora-desktop` CLI, dual-site Sidecar hot-switching & JSONL commands, PC-to-PC control (`remote.*` & `ctl`), complete `desktop.json` ACL & approval guard schema |
| **[Mobile SDK Integration](mobile.md)** | Android / iOS Developers | Android AAR & iOS XCFramework builds, 4-channel constructors & isolated stores, multi-desktop PairNet, Kotlin/ObjC snippets & event-loop contract |
| **[Protocol & Custom Clients](protocol.md)** | Protocol / Non-Go Authors | Official & self-hosted sequence diagrams, AES-256-GCM 16-char pairing codes, PairNet epoch sync, Ed25519 wire signing, DataChannel framing & business RPC |
| **[Security Model & Verification](security.md)** | Security Reviewers | Zero-trust boundaries, cryptographic guarantees, signaling/TURN defense-in-depth quotas, strict security tests, fuzzing & Linux netns labs |

---

## Architecture & Low-Level Module Specs

| Document | Language | Description |
| :--- | :---: | :--- |
| **[Architecture Design & Acceptance](design.md)** | English | Trust boundaries, connection migration, offline resume, revocation semantics, and E2E acceptance matrix |
| **[External Identity Authority Contract](../../internal/identity/README.md)** | English | `vanc1` device certificate & `vanl1` lease formats plus `/v1/identity/*` HTTP API contract |
| **[STUN / TURN Internals & Byte Accounting](../../internal/ice/README.md)** | English | `internal/ice` grant lifecycle, deduplicated byte accounting, peer IP filtering & full `TURN_*` options |
| **[Security Test Suite README](../../test/security/README.md)** | zh-CN | `test/security/` test layout, strict/heavy toggles, fuzzing & WSL2 network-namespace lab instructions |
