# Open Agent Exchange Protocol (OAEP)

[![Spec Version](https://img.shields.io/badge/spec-v1.0--RC-blue)](./RFC%20OAEP%20v1.0-RC.md)
[![Status](https://img.shields.io/badge/status-CODE%20FREEZE-snowflake)](./RFC%20OAEP%20v1.0-RC.md)
[![License](https://img.shields.io/badge/license-MIT%2Fwm-green)](LICENSE)

> **⚠️ STATUS ALERT: CODE FREEZE**
>
> This specification is currently a **Release Candidate (v1.0-RC)**.
> We are in **Code Freeze**. No new features will be added. We are currently soliciting feedback strictly for security audits, edge-case handling, and implementation bugs.

## 📖 Introduction

The **Open Agent Exchange Protocol (OAEP)** is the foundational "Layer 0" of the Open Agent Protocol (OAP) framework. It establishes the mathematical ground truth for autonomous AI agents to interact without centralized intermediaries.

In an era of centralized "Walled Gardens," OAEP provides the necessary primitives for:
*   **Self-Sovereign Identity:** Agents own their identifiers (DIDs).
*   **Mutual Authentication:** Cryptographic proof of control over keys.
*   **Trust Establishment:** Transporting Verifiable Credentials (VCs) to prove properties (e.g., "Verified Merchant").
*   **Secure Communication:** Establishing ephemeral, encrypted sessions (Perfect Forward Secrecy).

OAEP is designed to be **transport agnostic**. It runs over HTTP/WebSocket, Bluetooth LE, NFC, or async message queues.

## 📂 The Specification

The full normative specification is available here:

👉 **[READ THE SPECIFICATION (v1.0-RC)](RFC%20OAEP%20v1.0-RC.md)**

### Table of Contents (Quick Links)
*   [Section 1: Introduction & Motivation](RFC%20OAEP%20v1.0-RC.md#section-1-introduction)
*   [Section 3: Data Model (Profiles & Manifestos)](RFC%20OAEP%20v1.0-RC.md#section-3-data-model)
*   [Section 5: The Handshake Protocol](RFC%20OAEP%20v1.0-RC.md#section-5-the-handshake-protocol)
*   [Section 7: Security Considerations](RFC%20OAEP%20v1.0-RC.md#section-7-security-considerations)
*   [Section 8: Implementation Guidelines](RFC%20OAEP%20v1.0-RC.md#section-8-implementation-guidelines)

## ⚡ Technical Highlights

Implementers should be aware of the following mandatory technologies defined in OAEP v1.0:

| Component | Standard / Requirement |
| :--- | :--- |
| **Identity** | `did:key` (Ad-hoc/P2P) & `did:web` (Domain-bound) |
| **Data Format** | JSON-LD (Canonicalized via JCS) |
| **Signatures** | **Ed25519** (EdDSA) |
| **Key Agreement** | **X25519** (ECDH) |
| **Encryption** | **ChaCha20-Poly1305** (AEAD) |
| **Hashing** | **BLAKE3** |
| **Discovery** | OPRF-based Private Set Intersection (PSI) |

## 🛠 Reference Implementations

The OAP Foundation maintains the official reference implementations. Please use these libraries instead of rolling your own crypto.

*   **Rust (Core):** [`oap-foundation/oap-core-rs`](https://github.com/oap-foundation/oap-core-rs) *(Official Reference)*
*   **Python:** [`oap-foundation/oap-python`](https://github.com/oap-foundation/oap-python)
*   **JavaScript/WASM:** [`oap-foundation/oap-js`](https://github.com/oap-foundation/oap-js)

## 🧪 Conformance Testing

To ensure your implementation is compliant with v1.0, run it against the **Test Vectors** provided in this repository.

```bash
# Example: Validating your handshake logic
npm test -- --vectors ./test-vectors/handshake-v1.json
```

See [Section 8.5](RFC%20OAEP%20v1.0-RC.md#85-testen--konformität-conformance-testing) for details on the "Echo Bot" integration test.

## 🤝 Contributing & Feedback

Since we are in **Code Freeze**, we are **NOT** accepting Feature Requests at this time. We are accepting:

1.  **Security Vulnerability Reports:** If you find a flaw in the handshake or crypto-agility, please open an issue immediately with the tag `[SECURITY]`.
2.  **Ambiguity Clarifications:** If a section of the RFC is unclear or contradictory.
3.  **Typo/Grammar Fixes:** Pull Requests are welcome.

Please refer to `CONTRIBUTING.md` for our Code of Conduct and PR guidelines.

## 📄 License

This specification text is licensed under the **Creative Commons Attribution 4.0 International (CC BY 4.0)**.
Reference code and schemas are licensed under **MIT**.

---
**Maintained by the OAP Foundation**
*Building the decentralized agent economy.*