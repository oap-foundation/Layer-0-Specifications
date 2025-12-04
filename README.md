# OAP Layer 0: Identity & Trust

[![Spec Status](https://img.shields.io/badge/status-CODE%20FREEZE-snowflake)](./RFC%20OAEP%20v1.0-RC.md)
[![Protocol](https://img.shields.io/badge/protocol-OAEP-blue)](./RFC%20OAEP%20v1.0-RC.md)
[![License](https://img.shields.io/badge/license-CC%20BY%204.0-green)](LICENSE)

> **The Bedrock of the Autonomous Economy.**
>
> This repository contains the normative specifications for **Layer 0** of the Open Agent Protocol (OAP) framework. It defines how digital agents prove their identity, establish mutual trust, and negotiate secure communication channels without centralized intermediaries.

## 🔐 Scope of Layer 0

Layer 0 provides the **Root of Trust** for the entire stack. Before any message can be transported (Layer 1) or any transaction settled (Layer 2), agents must answer two fundamental questions:
1.  **"Who are you?"** (Authentication via DIDs)
2.  **"Can I trust you?"** (Verification via Credentials)

### Primary Specifications

| Acronym | Protocol Name | Version | Status | Description |
| :--- | :--- | :--- | :--- | :--- |
| **OAEP** | **Open Agent Exchange Protocol** | `1.0-RC` | ❄️ Freeze | The handshake protocol for mutual authentication, capability negotiation, and session key derivation. |

👉 **[READ THE OAEP SPECIFICATION](./RFC%20OAEP%20v1.0-RC.en.md)**

## ⚡ Key Technologies

Layer 0 mandates a specific set of cryptographic primitives to ensure a unified "Web of Trust":

### 1. Decentralized Identifiers (DIDs)
We support two specific methods to balance privacy and reputation:
*   **`did:key`**: For ephemeral, private, peer-to-peer interactions (e.g., a burner wallet for a specific negotiation).
*   **`did:web`**: For long-lived, reputation-based identities bound to a DNS domain (e.g., `did:web:shop.example.com`).

### 2. The Agent Profile (VC)
Identity is more than a public key. Agents exchange **Verifiable Credentials (VCs)** during the handshake to prove properties:
*   *"I am a certified Merchant."*
*   *"I am an accredited Medical Practitioner."*
*   *"I am a human-verified account."*

### 3. Cryptographic Agility
The current mandatory cipher suite (`OAEP-v1-2026`) uses:
*   **Signatures:** Ed25519
*   **Key Agreement:** X25519 (ECDH)
*   **Hashing:** BLAKE3
*   **Serialization:** JSON-LD with JCS Canonicalization

## 🏗 Relation to Other Layers

Layer 0 does **not** handle message transport or business logic. It provides the **Session Keys** and **Principal Identity** that higher layers rely on.

```mermaid
graph TD
    L2[Layer 2: Application<br>(OACP, OAPP, OAFP)] -->|Payload| L1
    L1[Layer 1: Transport<br>(OATP, Blind Relays)] -->|Encrypted Packets| L0
    L0[Layer 0: Trust<br>(OAEP, DIDs, VCs)] -->|Session Keys| Handshake
    style L0 fill:#f9f,stroke:#333,stroke-width:4px
```

*   **Layer 0 (This Repo):** "Alice and Bob agree on encryption keys."
*   **Layer 1 (OATP):** "Alice sends encrypted shards to Bob via relays."
*   **Layer 2 (OACP):** "Alice buys a book from Bob."

## 🛠 Implementation

The OAP Foundation provides a reference implementation of the Layer 0 logic in Rust. This library handles the complex state machine of the OAEP handshake and the correct verification of DID documents.

*   **Reference Core:** [`oap-foundation/oap-core-rs`](https://github.com/oap-foundation/oap-core-rs)

**⚠️ Security Warning:** Do not attempt to implement the cryptographic handshake from scratch unless you are a cryptography expert. Use the reference core to ensure protection against Replay Attacks, Unknown Key-Share Attacks, and Timing Attacks.

## 🤝 Contributing

We are currently in **Code Freeze** for v1.0.
We welcome feedback regarding:
*   Security vulnerabilities in the handshake logic.
*   Ambiguities in the DID resolution steps.
*   Edge cases in Verifiable Credential validation.

Please see `CONTRIBUTING.md` for details.

## 📄 License & Legal

### Specification License (Copyleft)
The specification text, architecture definitions, and protocol logic contained in this repository are licensed under the **Creative Commons Attribution-ShareAlike 4.0 International License (CC BY-SA 4.0)**.

[![License: CC BY-SA 4.0](https://img.shields.io/badge/License-CC%20BY--SA%204.0-lightgrey.svg)](https://creativecommons.org/licenses/by-sa/4.0/)

**Intent of this License:**
The goal of using CC BY-SA 4.0 is to permanently protect the open nature of this standard.
*   **ShareAlike:** If you modify, extend, or build upon this specification (e.g., creating a "Layer 2.5"), you **must** distribute your contributions under the same **CC BY-SA 4.0** license.
*   **No Proprietary Forks:** It is legally prohibited to create a proprietary, closed-source version or extension of this specification text. All derivatives must remain free and open to the community.

### Note on Implementation
To facilitate broad adoption, the use of the concepts, data structures (JSON-LD), and logic defined in this specification to create **software implementations** (libraries, applications, agents) is permitted without triggering the ShareAlike clause for the software itself.

However, any changes to the **specification document itself** remain subject to the ShareAlike requirement.

---
**Maintained by the OAP Foundation**
