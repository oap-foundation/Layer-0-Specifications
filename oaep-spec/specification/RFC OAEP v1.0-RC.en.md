# RFC: Open Agent Exchange Protocol (OAEP)
**Version:** 1.0 (PROPOSED STANDARD)
**Status:** CODE FREEZE
**Date:** 2025-11-25

**Section 1: Introduction**

## 1. Introduction

The Internet, originally conceived as a decentralized network, has evolved over the last two decades into a topology of centralized platforms and "walled gardens." In this architecture, identity, data, and the ability to interact are inextricably linked to specific providers (Identity Providers, IdPs).

With the rise of autonomous AI agents ("Personal AI"), this centralized model is reaching its limits. An AI agent acting on behalf of a user requires an identity that is mathematically verifiable but administratively independent.

The **Open Agent Exchange Protocol (OAEP)** lays this foundation. It is the protocol for **Layer 0** of the OAP framework. It defines how digital entities prove their identity, establish trust, and negotiate a secure basis for communication.

### 1.1 Motivation

The necessity for OAEP arises from three fundamental deficits of existing standards (such as OAuth 2.0, OIDC, or X.509) in the context of a decentralized agent economy:

1.  **Dependence on Central Trust Anchors (Root of Trust):**
    Classical PKI and federated identity systems depend on hierarchical chains of trust (Certificate Authorities or IdP servers). If the central anchor fails or withdraws trust (de-platforming), the agent loses its ability to act. OAEP replaces this hierarchy with a "Web of Trust" and Decentralized Identifiers (DIDs), where identity validation is performed directly through cryptography rather than administrative confirmation.

2.  **Lack of Offline and P2P Capability:**
    Modern AI agents increasingly operate "Local-First" (on the end device) or in direct peer-to-peer networks. Protocols that require a "call home" to an authentication server for every interaction create latency, security risks, and metadata trails. OAEP enables Mutual Authentication even in completely isolated environments (e.g., via Bluetooth LE or local networks), provided the cryptographic keys are available.

3.  **Missing Semantics for Agent Capabilities:**
    In a world of heterogeneous AI agents, the question "Who are you?" is inseparable from the question "What can you do?". Existing protocols strictly separate identity from capability discovery. OAEP integrates these steps into an efficient handshake process. An agent not only identifies itself but also signals, via cryptographic signature, which protocols (e.g., Commerce, Governance) it supports and which versions it speaks.

### 1.2 Scope

OAEP is designed as a **foundational protocol**. Its scope is strictly delimited to ensure modularity and security.

**In Scope (Part of OAEP):**
*   **Identity Management:** The creation, management, and resolution of Decentralized Identifiers (DIDs).
*   **Verifiable Credentials (VCs):** The transport and validation of proofs of properties (e.g., "Is a verified merchant", "Is of legal age") within the connection establishment.
*   **Handshake & Authentication:** The cryptographic process (Challenge-Response) to ensure that the counterpart possesses the private key corresponding to the claimed identity.
*   **Capability Negotiation:** The negotiation of supported application protocols (Layer 1) and encryption parameters.
*   **Session Establishment:** The derivation of temporary session keys (Ephemeral Keys) for subsequent communication.

**Out of Scope (Not part of OAEP v1.0):**
*   **Message Transport:** OAEP does not define how data packets are routed or stored across the network. This is the task of the *Open Agent Message Protocol (OAMP)*.
*   **Content Payload:** The structure of trade offers, social media posts, or payments is defined in the respective application protocols (OACP, SFP, OAPP). OAEP merely provides the secure tunnel for this data.
*   **Consensus Mechanisms:** OAEP is not a blockchain. It uses Distributed Ledgers (where necessary) only as a directory service (Registry) for public keys, not for transaction processing.
*   **Session Resumption:** OAEP v1.0 defines the initial, full handshake. Mechanisms for accelerated session resumption without renewed PKI operations (e.g., 0-RTT or Fast Reconnect after network changes) are the task of the transport layer (OAMP) or will be specified in future protocol extensions.

### 1.3 Design Philosophy

The architecture of OAEP follows four non-negotiable design principles that technically codify the values of digital sovereignty:

1.  **Self-Sovereignty:**
    Control over identity and key material remains exclusively with the user (Principal) or their agent. There are no "Master Keys" or "Backdoors" for platform operators. Revocation of identity is possible only by the owner themselves.

2.  **Privacy by Design & Minimal Disclosure:**
    By default, an agent discloses only the absolutely necessary information during the handshake. The use of *Zero-Knowledge Proofs (ZKPs)* is explicitly supported to prove properties (e.g., "Solvency available") without disclosing the underlying data (e.g., account balance).

3.  **Transport Agnosticism:**
    OAEP operates on the Application Layer. It does not presuppose a specific transport layer. An OAEP handshake must function over HTTPS just as well as over WebSockets, BLE (Bluetooth Low Energy), NFC, or asynchronous message queues.

4.  **Cryptographic Agility:**
    Given the threat of quantum computers (Post-Quantum Era), OAEP does not statically commit to individual algorithms. The protocol includes mechanisms for versioning and negotiating cryptographic methods (Cipher Suites), allowing the entire ecosystem to migrate seamlessly to more secure algorithms (e.g., Post-Quantum Cryptography) without breaking the architecture.

---

**Section 2: Terminology & Definitions**

## 2. Terminology and Definitions

To ensure an unambiguous interpretation of this protocol and interoperable implementations, the central terms are defined in this section. Wherever possible, OAEP references established terms from the W3C specifications for *Decentralized Identifiers (DID) v1.0* and *Verifiable Credentials (VC) v1.1*.

The keywords "MUST", "MUST NOT", "SHOULD", and "MAY" in this document are to be interpreted as described in RFC 2119.

### 2.1 Roles and Actors

In an OAEP interaction, entities assume specific roles. An entity can hold multiple roles simultaneously depending on the context.

*   **Principal:**
    The legal or natural entity that exercises ultimate control over an identity. This can be a human user, a company, or an organization. The Principal is the rightful owner of the private key material.

*   **Agent (Software Agent):**
    A software instance that acts autonomously or semi-autonomously on behalf of a Principal. In the context of OAEP, the Agent is the technical endpoint that executes the protocol, performs cryptographic operations, and makes decisions based on the Principal's instructions (e.g., a "Personal AI" on a smartphone).

*   **Issuer:**
    A trusted entity that verifies claims about a Principal and confirms them in the form of cryptographically signed *Verifiable Credentials* (e.g., a bank confirming creditworthiness, or the OAP Association confirming the authenticity of a shop).

*   **Verifier:**
    The role of an agent that receives a proof of identity or a credential from another agent, verifies its cryptographic signature, and validates its validity (e.g., revocation status).

*   **Relay:**
    An infrastructure node that enables the transport of OAEP handshake messages when a direct P2P connection is not possible (e.g., due to NAT/Firewalls). A relay in the OAP context is "blind"; it forwards encrypted packets without access to identities or content.

### 2.2 Identity and Addressing

OAEP uses the DID format as the primary mechanism for identification.

*   **DID (Decentralized Identifier):**
    A globally unique, persistent identifier that requires no central registration authority.
    *   *Format:* `did:<method>:<unique-idstring>`
    *   *Example:* `did:key:z6MkhaXgBZDvotDkL5257m5NrJFGM64Da4i72...`

*   **DID Document:**
    A JSON-LD document associated with a DID. It contains the public cryptographic keys (Verification Methods) and Service Endpoints (URLs) necessary to interact with the agent. In the OAP ecosystem, the DID Document is the "Source of Truth" for an agent's reachability.

*   **DID Method:**
    The specific set of rules for how a DID is created, resolved, and updated. OAEP mandates the support of specific methods (see Section 3.3), primarily `did:key` (for ephemeral/local identities) and `did:web` (for domain-bound, institutional identities).

### 2.3 Trust Artifacts (Credentials)

Identity alone does not create trust. OAEP uses signed data structures to make properties provable.

*   **Verifiable Credential (VC):**
    A tamper-evident digital proof. A VC contains statements about a subject (the Principal), metadata (Issuer, validity period), and a cryptographic signature from the Issuer.
    *   *OAP Context:* The most important VC in OAEP is the **AgentProfile**, which links basic data like display name and avatar to the DID.

*   **Verifiable Presentation (VP):**
    A data packet that an agent sends to a Verifier. It can contain one or more VCs. Crucially, the agent ("Holder") signs the presentation itself to prove that the VCs actually belong to it (Proof of Possession).

*   **Zero-Knowledge Proof (ZKP):**
    A cryptographic method allowing an agent to prove a property of a VC without disclosing the data itself.
    *   *Example:* Proving "Age > 18" without transmitting the date of birth.

### 2.4 Cryptographic Infrastructure

The security of OAEP relies on asymmetric cryptography and local key management.

*   **Wallet (Keystore/Vault):**
    The software or hardware component that stores private keys. In the OAP standard, the Wallet MUST be designed so that private keys never leave the device's storage area unencrypted. Hardware-backed environments (Secure Enclave, TEE) are preferred.

*   **Key Rotation:**
    The process of exchanging cryptographic keys for an existing identity. OAEP supports rotation to ensure security for long-lived identities (e.g., companies) without changing the identifier (the DID), provided the DID method supports this.

*   **Handshake:**
    The sequence of messages defined in this RFC, where two agents exchange identities, mutually authenticate, and negotiate a shared session key.

*   **Session Keys:**
    Temporary symmetric keys generated during the handshake (e.g., via Diffie-Hellman Key Exchange). They are used to efficiently encrypt subsequent data transport (via OAMP). They offer *Perfect Forward Secrecy* (PFS).

### 2.5 Protocol Semantics

*   **Capability:**
    A defined function or supported higher-order protocol (Layer 1) that an agent masters. Capabilities are signaled in the handshake via standardized URIs (e.g., `https://oap.dev/protocols/commerce/v1`).

*   **Manifest:**
    A public, signed list of capabilities and metadata that an agent can provide before the actual handshake to enable discovery.

---

**Section 3: Data Model**

## 3. Data Model

OAEP enforces strict semantics via **JSON-LD**.

**Cryptographic Integrity & Canonicalization (OAEP Signature Profile):**
1.  **Structure:** The object to be signed MUST be a valid JSON-LD document in **compacted form**.
2.  **Exclusion:** The `proof` attribute is removed before processing.
3.  **Canonicalization:** The object MUST be normalized according to **RFC 8785 (JSON Canonicalization Scheme - JCS)**.

### 3.1 The Agent Profile

The central data object in the OAEP handshake is the **AgentProfile**. It serves as a digital business card and representation of the agent to third parties.

To prevent spoofing, the AgentProfile MUST NOT be transmitted as a simple JSON object. It MUST be structured as a **W3C Verifiable Credential (VC)**. This guarantees, through the cryptographic signature in the `proof` field, that the data originates from the rightful owner of the identity (in the case of a Self-Signed Credential) or was validated by a trusted entity.

#### 3.1.1 Structure of the AgentProfile
A valid AgentProfile Credential MUST contain the following properties:

*   **@context:** Reference to the JSON-LD contexts used (W3C v1 and OAEP v1).
*   **type:** Must contain `["VerifiableCredential", "AgentProfile"]`.
*   **issuer:** The DID of the issuer (usually identical to the Subject for Self-Sovereign Profiles).
*   **issuanceDate:** Creation timestamp in strict **RFC 3339** format (e.g., `2026-03-15T10:00:00Z`).
*   **credentialSubject:** The actual content of the profile.
    *   `id`: The DID of the agent.
    *   `name`: (Optional) Display name of the agent.
    *   `description`: (Optional) Short description.
    *   `avatar`: (Optional) URI to a profile picture or hash of an image.
*   **proof:** The cryptographic signature.

#### 3.1.2 Example: Self-Signed AgentProfile (JSON-LD)

```json
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://w3id.org/oaep/v1"
  ],
  "id": "urn:uuid:3978344f-8596-4c3a-a978-8fcaba3903c5",
  "type": ["VerifiableCredential", "AgentProfile"],
  "issuer": "did:key:z6MkhaXgBZDvotDkL5257m5NrJFGM64Da4i72...",
  "issuanceDate": "2026-03-15T10:00:00Z",
  "credentialSubject": {
    "id": "did:key:z6MkhaXgBZDvotDkL5257m5NrJFGM64Da4i72...",
    "type": "PersonalAgent",
    "name": "Lena's Personal AI",
    "description": "Authorized purchasing and planning agent.",
    "avatar": "https://storage.think.systems/avatars/lena_ai_v1.png"
  },
  "proof": {
    "type": "Ed25519Signature2020",
    "created": "2026-03-15T10:00:00Z",
    "verificationMethod": "did:key:z6MkhaXgBZDvotDkL5257m5NrJFGM64Da4i72...#z6MkhaXgBZDvotDkL5257m5NrJFGM64Da4i72...",
    "proofPurpose": "assertionMethod",
    "proofValue": "z58DAdFGe9S8..." 
  }
}
```

### 3.2 Capability Manifesto

Since OAEP is modular, agents must negotiate which application protocols (Layer 1) they support before beginning an interaction. This negotiation occurs via the **Capability Manifesto**.

The Manifesto is a list of supported protocol URIs and versions. It SHOULD be embedded as part of the `credentialSubject` in the AgentProfile to save round-trips, but MAY be loaded as a separate Credential.

#### 3.2.1 Data Structure
The `capabilities` field is an array of objects with the following fields:
*   `protocol`: The unique URI of the standard (e.g., OACP).
*   `version`: Semver-compatible version (e.g., "1.0.0").
*   `role`: (Optional) The agent's role in this protocol (e.g., "Merchant" or "Buyer").

#### 3.2.2 Example Excerpt (within credentialSubject)

```json
"capabilities": [
  {
    "protocol": "https://w3id.org/oacp", 
    "version": "1.0",
    "role": "Buyer"
  },
  {
    "protocol": "https://w3id.org/oapp",
    "version": "1.0",
    "supportedAssets": ["EUR", "OAP"]
  },
  {
    "protocol": "https://w3id.org/sfp",
    "version": "0.9"
  }
]
```

### 3.3 Supported DID Methods

To avoid fragmentation, OAEP v1.0 mandates support ("MUST implement") for two specific DID methods. An OAEP-compliant agent MUST be able to resolve and verify these identifiers.

#### 3.3.1 did:key (For P2P & Ephemeral)
*   **Purpose:** Ad-hoc interactions, private chats.
*   **Mechanism:** The public key is encoded directly in the DID string. No resolution via a server or blockchain is necessary ("self-certifying").
*   **Key Specification:** OAEP v1.0 mandates **Ed25519** (Multicodec `0xed`) for signatures.
*   **Encryption:** For encryption (Key Agreement), separate, ephemeral **X25519** keys MUST be generated during the handshake (Perfect Forward Secrecy).
*   **Advantage:** Works offline, extremely fast, maximum privacy (disposable identities possible).
*   **Disadvantage:** No key rotation possible (if compromised, the identity must be abandoned).

#### 3.3.2 did:web (For Institutions & Trust)
*   **Purpose:** Companies, shops, authorities, public figures.
*   **Mechanism:** The DID is bound to a DNS domain (e.g., `did:web:think.systems`). The DID Document is hosted at a known URL (`/.well-known/did.json`).
*   **Advantage:** Leverages existing trust in the DNS system (SSL certificates). Users can intuitively verify: "Am I really talking to zalando.de?". Enables key rotation.
*   **Disadvantage:** Dependent on DNS and web server availability.

#### 3.3.3 Future Methods (Optional / Draft)
OAEP is designed so that further methods can be added (e.g., `did:dht` or `did:ion` for decentralized persistence without DNS). In Version 1.0, however, these are optional to keep client implementation complexity low.

### 3.4 Service Endpoints (Reachability)

Every resolved DID Document of an agent MUST contain at least one Service Endpoint of type `OAPEndpoint`. This defines the technical address for message transport (Layer 0).

```json
"service": [
  {
    "id": "#oap-comm",
    "type": "OAPEndpoint",
    "serviceEndpoint": "https://relay.think.systems/v1/inbox/12345",
    "routingKeys": ["did:key:RelayKey..."] 
  }
]
```
This enables message routing even if the agent (e.g., a smartphone) is behind a firewall or offline (Store-and-Forward via Relay).

---

**Section 4: The Discovery Process**

## 4. The Discovery Process

In a decentralized ecosystem, there is no central directory service listing all participants and their addresses. OAEP therefore defines mechanisms for agents to discover communication partners and retrieve the technical information necessary for connection establishment.

The discovery process is divided into three scenarios:
1.  **Explicit Invitation:** Direct exchange of identifiers (Out-of-Band).
2.  **Implicit Discovery:** Finding contacts based on known attributes (e.g., phone numbers) while strictly preserving privacy.
3.  **Resolution:** The technical step from abstract ID (DID) to concrete connection parameters.

### 4.1 Out-of-Band Discovery (Explicit Invitation)

This method is used when an interaction is initiated through an external channel (physical meeting, email, website). To ensure interoperability between different OAP-compatible wallets and agents, OAEP defines a standardized URI scheme.

#### 4.1.1 The `oap` URI Scheme
Agents MUST be able to process URIs conforming to the following scheme:

`oap:connect?did=<did>&label=<optional_name>`

*   **oap:** The protocol prefix.
*   **connect:** The action (here: request connection).
*   **did:** The full Decentralized Identifier of the target agent.
*   **label:** (Optional) A URL-encoded, human-readable name (e.g., "Th!nk%20Store") displayed to the user before the handshake.

#### 4.1.2 QR Codes
For physical interactions (e.g., at a checkout or exchanging contacts between two smartphones), the URI MUST be encoded in a QR code (Quick Response Code).
*   **Error Correction:** Level M or higher SHOULD be used.
*   **Format:** Alphanumeric mode.

### 4.2 Privacy-Preserving Contact Discovery (PSI)

One of the biggest privacy issues with classic messengers is uploading the entire address book in plain text to central servers ("Contact Upload"). OAEP rejects this approach. To nevertheless find users whose phone number or email address is known to an agent, OAEP uses **Private Set Intersection (PSI)**.

This mechanism allows an agent (client) and a discovery server to determine which contacts they have in common (intersection) without the server learning the client's input data and without the client downloading the server's entire database.

OAEP standardizes PSI based on **Ristretto255** and OPRF.

#### 4.2.1 The Protocol (OPRF-based PSI)

OAEP standardizes a PSI method based on an *Oblivious Pseudo-Random Function (OPRF)*. To ensure interoperability and prevent cryptographic attacks via subgroups, the **Ristretto255** group MUST be used for all OPRF operations.

**HMAC-SHA256** is specified as the Pseudo-Random Function (PRF) for finalizing the output.

**Process:**

1.  **Preparation (Client):** Client blinds inputs ($B = P_x \cdot r$).

2.  **Request (Client -> Server):**
    *   The agent sends the blinded elements ($B$).
    *   **Normative Batch Size:** The maximum number of elements per request (`MAX_BATCH_SIZE`) is fixed at **1000 elements**. Clients MUST split larger quantities into sequential requests.

3.  **Evaluation (Server):**
    *   **DoS Protection:** The server MUST reject requests exceeding `MAX_BATCH_SIZE` with `ERR_RATE_LIMIT`.
    *   The server MUST implement rate-limiting based on the **Token Bucket Algorithm** (see Section 8.3.3).

4.  **Unblinding (Client):**
    *   The agent removes its random factor $r$ by multiplying with the inverse ($r^{-1}$): $U = E \cdot r^{-1} = (P_x \cdot r \cdot k) \cdot r^{-1} = P_x \cdot k$.
    *   The result $U$ is now the OPRF result, depending only on the input $x$ and the server key $k$.

5.  **Comparison (Local):**
    *   To form the final intersection, the client calculates the hash of the unblinded element: $H_{final} = \text{HMAC-SHA256}(key=\text{"OAEP-PSI-v1"}, data=U)$.
    *   This value is compared against the list of hash values provided by the server for all registered users (e.g., as a Bloom Filter or Golomb-Compressed Set to save bandwidth).

6.  **Match:** Upon a match, the agent has found an OAP user and can resolve the corresponding DID.

### 4.3 DID Resolution

Once an agent knows a DID (via 4.1 or 4.2), it must resolve it into a **DID Document** to begin the handshake. The resolver is a component in the OAP SDK that follows different strategies depending on the DID method.

#### 4.3.1 Resolution of `did:key`
For this method, no network access is required for the **resolution step** (Offline Resolution).
1.  The resolver extracts the Multicodec value and expands it into the DID Document.
2.  **In-Band Transport Rule:** Since `did:key` documents often do not contain a `service` entry, the agent MUST assume in this case that the transport channel already exists "In-Band" (e.g., response via the same WebSocket/TCP socket the request came from). Aborting with `ERR_DID_RESOLUTION` is FORBIDDEN in this case.

#### 4.3.2 Resolution of `did:web`
Here, the Domain Name System (DNS) acts as the trust anchor.
1.  The resolver parses the DID: `did:web:example.com:user:alice` becomes the URL `https://example.com/user/alice/.well-known/did.json`.
2.  The agent performs an HTTPS GET Request.
3.  **Security Check:** The connection MUST be secured via TLS (HTTPS). The domain's certificate MUST be valid.
4.  The returned JSON document is parsed. The agent extracts:
    *   `verificationMethod`: The counterpart's public keys.
    *   `service`: The URL of the OAMP Relay (Inbox) to which the first handshake message ("Hello") must be sent.

#### 4.3.3 Caching Guidelines
To protect privacy and reduce network load, resolved DID Documents SHOULD be locally cached. The cache validity period is determined by HTTP Cache Headers (for `did:web`) or is unlimited (for `did:key`, as it is immutable). However, before critical transactions (e.g., payments via OAPP), a fresh live resolution MUST be performed to ensure keys have not been rotated or revoked.

---

**Section 5: The Handshake Protocol**

## 5. The Handshake Protocol

After an agent has resolved the counterpart's DID (see Section 4), it initiates the handshake protocol. The goal of this process is to establish a **mutually authenticated, encrypted session**.

The OAEP handshake is stateful. It ensures that:
1.  Both parties possess control over the private keys of their respective DIDs (**Authentication**).
2.  Both parties agree on a common set of application protocols (**Negotiation**).
3.  A set of fresh symmetric keys is generated for subsequent communication (**Session Establishment**).

### 5.1 State Machine

The OAEP handshake is a stateful process. To prevent protocol confusion and attacks (e.g., state exhaustion), implementations MUST strictly manage connection status using the following state machine.

The lifecycle of a session is defined by five main states:

1.  **`IDLE`**: The initial state. No context exists.
2.  **`AWAIT_RESPONSE`** (Initiator only): `ConnectionRequest` sent; waiting for response.
3.  **`AWAIT_ACK`** (Responder only): `ConnectionResponse` sent; waiting for finalization.
4.  **`ACTIVE`**: Handshake successful. Session keys derived. OAMP messages can be exchanged.
5.  **`FAILED`**: An error occurred. Temporary state for error handling/cleanup.

#### 5.1.1 Transition Matrix

The following table defines the **only permissible transitions**. Any message received in a state for which no transition is defined MUST be ignored or treated as an error.

| Role | Current State | Event / Incoming Message | Action / Check | New State |
| :--- | :--- | :--- | :--- | :--- |
| **Initiator** | `IDLE` | *Start Handshake* | Send `ConnectionRequest` (Store `EphemeralKey_A` & `Nonce_A`). Start Timer. | `AWAIT_RESPONSE` |
| **Responder** | `IDLE` | Receive `ConnectionRequest` | Validate Schema & Timestamp. Generate `EphemeralKey_B` & `Nonce_B`. Sign Transcript. Send `ConnectionResponse`. Start Timer. | `AWAIT_ACK` |
| **Initiator** | `AWAIT_RESPONSE` | Receive `ConnectionResponse` | 1. Verify signature over transcript.<br>2. Verify `negotiatedSuite`.<br>3. Derive Session Keys.<br>4. Send `ConnectionAcknowledge`. | `ACTIVE` |
| **Responder** | `AWAIT_ACK` | Receive `ConnectionAcknowledge` | 1. Verify signature over transcript.<br>2. Derive Session Keys. | `ACTIVE` |
| **Both** | `ACTIVE` | Receive `OAMP Message` | Decrypt and process payload. | `ACTIVE` |
| **Both** | *All* | Receive `OAEPError` | Log error. Delete all Ephemeral Keys. | `FAILED` -> `IDLE` |
| **Both** | *All except IDLE* | **Timeout** (Default: 30s) | Delete all Ephemeral Keys. | `FAILED` -> `IDLE` |

#### 5.1.2 Error Handling & Timeouts

To prevent resource exhaustion (DoS), the following normative rules apply for state transitions in case of errors:

1.  **Unexpected Message:** If a message arrives that is not expected in the current state (e.g., `ConnectionAcknowledge` in `IDLE`), the agent MUST **silently drop** this message. It MUST NOT send an `OAEPError` to prevent "Reflection Attacks".
2.  **Invalid Signature:** If the cryptographic check in `AWAIT_RESPONSE` or `AWAIT_ACK` fails, the agent MUST respond with an `OAEPError` (Code: `ERR_AUTH_SIG_INVALID`) and immediately transition to `FAILED`.
3.  **Timeout:** If the timer expires before the next expected state is reached, the handshake MUST be aborted. All temporary keys (`EphemeralKey`) and nonces MUST be immediately and securely deleted from memory. No retry occurs at the protocol level (this is the responsibility of the application).

### 5.2 The Protocol Sequence

The standard handshake consists of three messages (3-Way Handshake), analogous to TCP but at the application layer.

To mathematically exclude **Man-in-the-Middle attacks** and **Unknown Key-Share Attacks**, signatures MUST NOT be formed over individual values (like just the nonce). Instead, every signature MUST be over a deterministic **Handshake Transcript** that binds all security-critical parameters of both parties.

#### 5.2.1 Definition of the Handshake Transcript

The transcript is a JSON object representing the negotiated state of the session. Before hashing or signing, this object MUST be normalized according to **RFC 8785 (JCS)**.

The transcript object `T` has the following structure:

```json
{
  "header": {
    "suite": "OAEP-v1-2026",       // The negotiated Cipher Suite
    "created": "2026-..."          // Timestamp of the Request
  },
  "initiator": {
    "did": "did:key:alice...",     // DID of Agent A
    "nonce": "...",                // Nonce of Agent A
    "ephemeralKey": "..."          // Public Key for ECDH of A
  },
  "responder": {
    "did": "did:web:bob...",       // DID of Agent B
    "nonce": "...",                // Nonce of Agent B
    "ephemeralKey": "..."          // Public Key for ECDH of B
  }
}
```

The **Transcript Hash** $H_T$ is calculated as:
$$H_T = \text{HashFunction}_{\text{Suite}}(\text{JCS}(T))$$

#### 5.2.2 The Sequence

**Phase 1: Connection Request (SYN)**
The Initiator (Agent A) sends the `ConnectionRequest`.
*   **Action:** Generation of `Nonce_A` and `EphemeralKey_A`.
*   **Content:** DID A, Timestamp, `Nonce_A`, `EphemeralKey_A`, list of `supportedSuites`.
*   *Note:* No signature yet, as B's parameters are unknown.

**Phase 2: Connection Response (SYN-ACK)**
The Receiver (Agent B) selects a suite, generates `Nonce_B` and `EphemeralKey_B`.
*   **Transcript Construction:** Agent B constructs the transcript object `T` locally from A's values and its own values.
*   **Signature (Authentication & Binding):** Agent B calculates $H_T$ and signs this hash with its *long-term* private identity key:
    $$\text{Sig}_B = \text{Sign}(\text{PrivKey}_B, H_T)$$
*   **Content:** DID B, `Nonce_B`, `EphemeralKey_B`, `negotiatedSuite`, and `Sig_B` (in the `proof` field).

**Phase 3: Connection Acknowledge (ACK)**
The Initiator (Agent A) receives the response.
*   **Validation:** Agent A also constructs the transcript `T` locally and calculates $H_T$. It verifies `Sig_B` against this hash. If this fails, the handshake aborts.
*   **Signature (Mutual Authentication):** To confirm the channel, Agent A now signs the same hash $H_T$ with its *long-term* private key:
    $$\text{Sig}_A = \text{Sign}(\text{PrivKey}_A, H_T)$$
*   **Content:** `Sig_A` (in the `proof` field) and the final `CapabilityManifest`.

**Result:**
Once B receives the message and verifies `Sig_A` against the transcript, the session is established. Both parties have proven that they (1) control their DIDs and (2) see the same Ephemeral Keys for encryption.

*Important: Signatures are mandatorily performed over the hash of the JCS-normalized transcript of all parameters.*

### 5.3 Message Formats (JSON-LD)

All handshake messages MUST follow the schema below. All timestamps MUST conform to the **RFC 3339** format.

#### 5.3.1 ConnectionRequest (Example)

The Initiator proposes a list of Cipher Suites (`supportedSuites`) it supports.

```json
{
  "@context": ["https://w3id.org/oaep/v1"],
  "type": "ConnectionRequest",
  "id": "urn:uuid:a1b2c3d4-e5f6-7890-1234-567890abcdef",
  "from": "did:key:z6MkInitiator...",
  "to": "did:web:target.com",
  "created": "2026-05-20T10:00:00Z",
  "body": {
    "nonce": "r4nd0m-string-12345",
    "keyExchange": {
      "supportedSuites": ["OAEP-v1-2026", "OAEP-v2-PQ-Hybrid"],
      "publicKey": "BASE64_EPHEMERAL_KEY_A" 
    },
    // Optional: Embedded AgentProfile VC (not yet encrypted!)
    "profile": { ... } 
  }
}
```

#### 5.3.2 ConnectionResponse (Example)

The Responder chooses a suite (`negotiatedSuite`) and signs the transcript. The field within `proof` is explicitly named `transcriptHash` to clarify that not just a nonce was signed.

```json
{
  "@context": ["https://w3id.org/oaep/v1"],
  "type": "ConnectionResponse",
  "replyTo": "urn:uuid:a1b2c3d4-...", // ID of the Request
  "from": "did:web:target.com",
  "to": "did:key:z6MkInitiator...",
  "created": "2026-05-20T10:00:01Z",
  "body": {
    "nonce": "r4nd0m-string-67890",
    "keyExchange": {
      "negotiatedSuite": "OAEP-v1-2026",
      "publicKey": "BASE64_EPHEMERAL_KEY_B"
    }
  },
  "proof": {
    "type": "Ed25519Signature2020",
    "verificationMethod": "did:web:target.com#key-1",
    "proofPurpose": "authentication",
    "created": "2026-05-20T10:00:01Z",
    // WARNING: This field represents the hash of the entire 
    // handshake transcript (see 5.2.1), not just a nonce.
    "transcriptHash": "SHA256_HASH_OF_JCS_NORMALIZED_TRANSCRIPT", 
    "jws": "eyJhbGciOiJFZ..."
  }
}
```

#### 5.3.3 ConnectionAcknowledge (Example)

The Initiator confirms the session. Here too, the `transcriptHash` is signed.

```json
{
  "@context": ["https://w3id.org/oaep/v1"],
  "type": "ConnectionAcknowledge",
  "replyTo": "urn:uuid:response-id...",
  "from": "did:key:z6MkInitiator...",
  "to": "did:web:target.com",
  "created": "2026-05-20T10:00:02Z",
  "proof": {
    "type": "Ed25519Signature2020",
    "verificationMethod": "did:key:z6MkInitiator...#key-1",
    "proofPurpose": "authentication",
    "transcriptHash": "SHA256_HASH_OF_JCS_NORMALIZED_TRANSCRIPT",
    "jws": "eyJhbGciOiJFZ..."
  },
  // From here on, encrypted capabilities can follow
  "body": { 
    "capabilities": [...] 
  }
}
```

### 5.4 Capability Negotiation

As part of the `ConnectionRequest` (or at the latest in `ConnectionAcknowledge`), agents exchange their supported protocols (see Section 3.2).

**Intersection Logic:**
1.  Agent A sends list `[OACP v1.0, OAPP v2.0, SFP v1.0]`.
2.  Agent B supports `[OACP v1.0, OAPP v1.0]`.
3.  **Result:** The session is activated for **OACP v1.0**. For OAPP, a fallback to the lowest common denominator (v1.0) occurs (if possible). SFP is disabled as B does not support it.

If the intersection of essential protocols is empty, the handshake MUST be aborted with error `ERR_NO_COMMON_PROTOCOL`.

### 5.5 Session Establishment (Key Derivation)

OAEP implements **Perfect Forward Secrecy (PFS)**. This means that even if the long-term identity key (from the DID) is compromised in the future, recorded past sessions cannot be decrypted.

Upon successful completion of Phases 2 and 3, both parties possess the necessary secrets to initialize the symmetric message channel (OAMP).

#### 5.5.1 The Key Schedule (HKDF)

Input Key Material via ECDH of ephemeral keys. Salt is the Transcript Hash.

To derive session keys, **HKDF** (HMAC-based Extract-and-Expand Key Derivation Function) according to **RFC 5869** MUST be used. The underlying hash algorithm is determined by the Cipher Suite (for `OAEP-v1-2026`, this is `BLAKE3` or `SHA-256`).

The input parameters for HKDF are normatively defined as follows:

1.  **Input Key Material (IKM):**
    The result of the Diffie-Hellman exchange (ECDH) between the ephemeral keys.
    $$IKM = \text{ECDH}(\text{PrivKey}_{\text{Ephemeral\_Local}}, \text{PubKey}_{\text{Ephemeral\_Remote}})$$

2.  **Salt:**
    To cryptographically bind the session keys to the identities and the handshake history, the **Transcript Hash** ($H_T$, see 5.2.1) MUST be used as the Salt.
    $$\text{Salt} = H_T$$

3.  **Info (Context Information):**
    A fixed string for domain separation containing the protocol version.
    $$\text{Info} = \text{"OAEP-v1-Session-Keys"}$$

#### 5.5.2 Derivation of Symmetric Keys

The output of the HKDF-Expand function (length: 64 bytes) is split into two 32-byte keys:

```text
Output_Keying_Material = HKDF-Expand(PRK, Info, L=64)

Split:
1. Client_Write_Key (Bytes 0-31): Key for messages from Initiator to Responder.
2. Server_Write_Key (Bytes 32-63): Key for messages from Responder to Initiator.
```

*   **Initiator (Alice):** Uses `Client_Write_Key` to encrypt and `Server_Write_Key` to decrypt.
*   **Responder (Bob):** Uses `Server_Write_Key` to encrypt and `Client_Write_Key` to decrypt.

**Security Mandate:** Immediately after deriving these keys, the private Ephemeral Keys (`EphemeralKey_A`, `EphemeralKey_B`) and the ECDH result (`IKM`) MUST be securely deleted (overwritten/zeroized) from memory.

#### 5.5.3 AEAD Nonce Management (ChaCha20-Poly1305)

For symmetric encryption of the payload, **ChaCha20-Poly1305** is used. This algorithm requires a unique **Nonce** (96 Bit / 12 Bytes) for every message.

**Warning:** Reusing a nonce with the same key ("Nonce Reuse") results in a total loss of confidentiality.

OAEP mandates the following Nonce scheme:

*   **Implicit Sequence Numbers:**
    Each agent maintains two internal 64-bit counters (Unsigned Integer):
    1.  `send_counter`: Initialized with `0`. Incremented after every send.
    2.  `recv_counter`: Initialized with `0`. Incremented after every successful decryption.

*   **Construction of the Nonce (12 Bytes):**
    The 96-bit Nonce is constructed by **Padding** the 64-bit counter with zeros (Big Endian or Little Endian according to Suite specification, Standard: Little Endian for ChaCha20).
    `Nonce = [0x00, 0x00, 0x00, 0x00] || [64-bit Counter]`

*   **Rules:**
    1.  Nonces are **not** transmitted over the network.
    2.  **Sliding Window (Mandatory):** Due to the asynchronous nature of OAMP (UDP-like or Relay-based), receivers MUST implement a Sliding Window (recommended window size $\ge 64$) for the `recv_counter`. Messages arriving within the window but "out-of-order" MUST be accepted. Messages falling out of the window to the left (too old) MUST be rejected as Replay.
    3.  On counter overflow, Re-Keying MUST occur.

### 5.6 Security Considerations for the Handshake

The handshake is the most critical moment of communication. Since no encrypted channel exists yet, it is vulnerable to replay and timing attacks. Implementations MUST enforce the following security mechanisms.

#### 5.6.1 Replay Protection

An attacker could try to intercept a valid `ConnectionRequest` and send it again later to force a session or overload the server.

*   **Nonce Cache:** Every receiver MUST maintain a cache (e.g., Redis, In-Memory Set) of all seen Nonces.
*   **Check:** If a Nonce appears in an incoming message that already exists in the cache, the message MUST be discarded immediately.
*   **Lifetime:** The cache MUST store Nonces at least as long as the time window for valid timestamps (see 5.6.2) is open (i.e., > 300 seconds).

#### 5.6.2 Time Window & Clock Drift

All handshake messages MUST contain a `created` timestamp in **RFC 3339** format. Since clocks in distributed systems are never perfectly synchronized, OAEP defines a "Window of Acceptance."

The receiver compares the message timestamp $T_{msg}$ with its local system time $T_{now}$.

1.  **Outdated Messages (Past Tolerance):**
    If $T_{msg} < T_{now} - 300\text{s}$ (older than 5 minutes), the message MUST be rejected (`ERR_MSG_EXPIRED`). This limits the need to store Nonces forever.
2.  **Messages from the Future (Future Tolerance):**
    If $T_{msg} > T_{now} + 10\text{s}$ (more than 10 seconds in the future), the message MUST be rejected (`ERR_MSG_FUTURE`).
    *   *Reasoning:* This prevents attacks where an attacker generates messages with future timestamps to use later when the Nonce cache has been cleared. The 10-second tolerance serves to compensate for slight Clock Drift.

**Special Case: IoT Devices without RTC (Real Time Clock)**
For devices without reliable system time (e.g., simple sensors after a reboot):
*   These devices MAY suspend the time check during the handshake ("Relaxed Mode").
*   Instead, they MUST strictly rely on the **cryptographic Challenge-Response**. The device sends its own random Nonce and accepts the connection only if it returns freshly signed.
*   Once a trusted connection is established, the device SHOULD synchronize its time over the network (e.g., via OAMP Time Sync).

#### 5.6.3 TOFU (Trust On First Use) with `did:key`

When using `did:key`, no external trust anchor (like DNS for `did:web`) exists.

*   **First Connection:** The initiator must trust that the Public Key contained in the QR code or link actually belongs to the desired partner.
*   **Persistence:** After the first successful handshake, the agent MUST store the association "Name <-> DID/Key" locally ("Pinning").
*   **Warning:** If the key for a known contact changes (e.g., new DID due to device change), the software MUST explicitly warn the user and require re-verification (e.g., QR scan). Automatic "Re-Trusting" is FORBIDDEN.

*   **Technical Pinning Format:** To ensure client interoperability, pinned identities MUST be stored in the following JSON schema:
    ```json
    {
      "did": "did:key:z6Mk...",
      "label": "Alice AI",
      "pinnedKey": "Multibase_Public_Key_String",
      "firstSeen": "2025-11-23T14:30:00Z",
      "lastVerified": "2026-02-15T09:00:00Z",
      "verificationMethod": "manual_qr_scan"
    }
    ```
*   A deviation from the `pinnedKey` MUST be treated as a fatal security error (`ERR_SECURITY_KEY_MISMATCH`).

#### 5.6.4 DDoS Prevention

The handshake requires expensive cryptographic operations (Signature verification, ECDH). Attackers could use this for *Resource Exhaustion Attacks*.

*   **Silent Drop Policy:** Upon suspicion of an attack (e.g., high frequency of requests from an IP) or with obviously invalid messages (wrong format, outdated timestamp), agents SHOULD **silently drop** the message instead of wasting computing power creating an `OAEPError` response.
*   **Proof of Work (Optional):** Service endpoints MAY require a cryptographic proof of work (e.g., Hashcash) in the `ConnectionRequest` before verifying a signature.

---

**Section 6: Trust & Reputation**

## 6. Trust Model and Reputation

In a decentralized network like the OAP ecosystem, the existence of an identity (DID) is no guarantee of trustworthiness. Any actor can generate any number of DIDs. OAEP therefore strictly separates **Authentication** (proof of identity control, regulated in Section 5) and **Verification** (proof of properties and trustworthiness).

This chapter defines the algorithms and data structures agents use to determine the trust status of a counterpart. OAEP does not rely on a single central "Root CA" (Certificate Authority), but on a federated **Web of Trust** based on W3C Verifiable Credentials.

### 6.1 Verification Logic

An OAEP agent MUST perform a multi-stage check during every handshake and before every critical transaction (e.g., payment, data sharing). The connection status ("Verified" vs. "Unverified") results from the outcome of this chain.

#### Stage 1: Cryptographic Integrity (Proof of Possession)
*   **Check:** Does the signature in the handshake match the public key in the DID Document?
*   **Statement:** "The sender controls this identifier."
*   **Failure:** Upon failure, the connection MUST be disconnected immediately.

#### Stage 2: Identity Binding (Controller Validation)
*   **Check:**
    *   For `did:web`: Does the DID match the domain from which the DID Document was loaded? Is the domain's TLS certificate valid?
    *   For `did:key`: Is the public key correctly encoded in the DID string?
*   **Statement:**
    *   `did:web`: "This agent acts on behalf of the owner of the domain `shop.com`."
    *   `did:key`: "This agent is consistent with its mathematical definition."

#### Stage 3: Credential Validation (Chain Verification)
If an agent presents an `AgentProfile` as a Verifiable Credential (VC) signed by a third party (Issuer) during the handshake:
*   **Check:**
    1.  Is the Issuer's signature under the VC valid?
    2.  Is the Issuer itself trusted? (Check against a local "Trusted Issuer List" or a governance framework).
*   **Statement:** "A trusted entity (e.g., OAP Foundation) confirms that this agent belongs to Company XY."

### 6.2 Revocation & Status Checking

Trust is dynamic. Keys can be stolen, companies can go bankrupt, certificates can expire. Since OAEP does not query central servers ("Is Certificate X still valid?"), a privacy-friendly mechanism for revocation is needed.

OAEP standardizes the use of **Bitstring Status Lists (StatusList2021)** for this purpose.

#### 6.2.1 Mechanism
1.  An Issuer publishes a status list (e.g., as a file on a web server or IPFS). This file is a highly compressed bit map (0/1).
2.  Every issued credential contains a reference to this list and an index (e.g., "Bit #452").
3.  To check the status, the Verifier (the agent) downloads the list.
4.  If Bit #452 is set to `0`, the credential is valid. If set to `1`, it has been revoked.

#### 6.2.2 Advantages & Requirements
*   **Privacy:** The server hosting the list only sees that the *list* was accessed, not *which* specific credential is being checked.
*   **Caching:** Agents SHOULD cache status lists for a defined period (e.g., 1 hour) to reduce network load.
*   **Mandatory:** Agents MUST check revocation status before authorizing a high-risk transaction (e.g., > 50€).

### 6.3 Trust Levels

To make verification complexity understandable to the user (or the controlling AI), OAEP defines four standardized trust levels. The SDK MUST pass these levels to the UI (User Interface).

| Level | Designation | Symbol (UI) | Technical Condition | Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **0** | **Unknown** | ⚪️ Grey / ? | Valid DID, but no known credentials or domain binding. | Anonymous chat, P2P first contact. |
| **1** | **Self-Attested** | 🟡 Yellow | `did:key` with profile data signed only by the creator themselves. Trust based on "Trust on First Use" (TOFU) or manual contact exchange (QR code). | Personal contacts, friends. |
| **2** | **Domain Validated** | 🟢 Green (Lock) | `did:web`. Identity is cryptographically bound to a DNS domain. | Online shops, organizations, cloud services. |
| **3** | **Verified Entity** | ✅ Blue Check / Shield | A Verifiable Credential from a **Root Trust Anchor** (e.g., OAP Foundation, eIDAS Provider) is present and verified. | Banking, authorities, verified merchants. |

### 6.4 Reputation

Beyond hard verification, OAEP supports the exchange of soft reputation data ("Review Scores").

*   **Signed Reviews:** An agent can create a review about another agent (e.g., after a purchase) as a signed object (VC).
*   **Distributed Reputation:** Since there is no central server storing all reviews, agents MUST collect their reputation proofs themselves and present them during the handshake (as part of the profile) or upon request.
*   **Validation:** The receiver checks:
    1.  Are the review signatures genuine?
    2.  Do the reviews come from DIDs with which an OACP transaction actually took place? (Linking purchase receipt and review to complicate fake reviews).

### 6.5 Security Considerations

*   **Trust Anchor Management:** The SDK must ship with a list of standard Trust Anchors (e.g., OAP Foundation Public Keys), but must allow the user to edit this list (Sovereignty).
*   **Phishing Prevention:** For `did:web`, the UI MUST prominently display the domain. The SDK SHOULD detect and warn about "Look-alike" domains (Homograph Attacks).
*   **Metadata Protection:** When retrieving status lists, the agent SHOULD be able to use proxies or anonymization networks (e.g., Tor) to prevent the list host from creating movement profiles.

---

**Section 7: Security Considerations**

## 7. Security Considerations

The security of the entire OAP ecosystem depends on the correct implementation of OAEP. Since OAEP operates in a "Zero-Trust" environment where the network, relays, and potentially counterparts may be compromised, implementers must strictly adhere to the following security guidelines.

### 7.1 Key Management and Storage

The security of a Decentralized Identity (DID) is inextricably linked to the security of the private key.

*   **Secure Storage:**
    Private keys (both long-term identity keys and short-lived session keys) MUST NEVER be stored in plain text in the file system, databases, or code.
    *   On mobile devices, hardware-backed storage (iOS Secure Enclave, Android Keystore/StrongBox) MUST be used.
    *   On servers, HSMs (Hardware Security Modules) or comparable KMS (Key Management Systems) with Enclave technology SHOULD be used.
*   **No Export:**
    Implementations SHOULD prevent private keys from being extracted. All cryptographic operations (Signing, Decrypting) SHOULD take place within the secured hardware environment.
*   **Entropy:**
    Key and Nonce generation MUST use a cryptographically secure pseudo-random number generator (CSPRNG).

### 7.2 Protection against Man-in-the-Middle (MitM) Attacks

Since OAEP uses no central Public Key Infrastructure (PKI), protection against MitM attacks during the initial handshake is critical. An attacker could try to intercept communication, forward messages, or swap keys. Security rests on three pillars:

#### 7.2.1 Channel Binding with `did:web` (Transport Layer Binding)
When using `did:web`, the DNS system serves as the trust anchor.
*   **Mandate:** When resolving the DID Document and sending the `ConnectionRequest`, the HTTPS connection (TLS) MUST be successfully validated.
*   **Abort Condition:** The handshake MUST be aborted immediately if the domain's TLS certificate is invalid, expired, revoked, or self-signed (without a trusted Root CA). This anchors the DID's security in the security of domain ownership.

#### 7.2.2 TOFU & Out-of-Band with `did:key` (Trust On First Use)
With `did:key`, no external anchor exists. Security relies on key usage continuity.
*   **Key Change Alert:** Implementations MUST warn the user if the public key of a known contact (identified by a name) changes.
*   **Out-of-Band Verification:** For critical first contacts, verification via a second channel (e.g., scanning a QR code or verbally comparing a "Safety Number" hash) SHOULD be enforced.

#### 7.2.3 Cryptographic Channel Binding
This is the most important measure against subtle MitM attacks like **Unknown Key-Share (UKS)**. In a UKS attack, an attacker (Eve) forwards Alice's authentication signature to Bob but swaps the Ephemeral Keys (for encryption) with her own. Bob thinks he is speaking securely with Alice, but actually decrypts for Eve.

To prevent this, signing a random Nonce ("Challenge-Response") is NOT sufficient.

*   **Mandate (Transcript Signature):** Identity signatures (`proof`) in the `ConnectionResponse` (by Agent B) and `ConnectionAcknowledge` (by Agent A) MUST mandatorily be over the complete **Handshake Transcript**, as defined in Section 5.2.
*   **Definition:** The transcript to be signed must cryptographically bind:
    1.  Both parties' Nonces (Replay Protection).
    2.  Both parties' Ephemeral Keys (Session Integrity).
    3.  Both parties' DIDs (Identity Binding).
    `Signature = Sign(PrivKey_Identity, Hash(Nonce_A || Nonce_B || EphemeralKey_A || EphemeralKey_B || DID_A || DID_B))`
*   **Prohibition:** Implementations MUST NOT simply sign the incoming `challenge` (Nonce). A signature that does not include the Ephemeral Keys is considered insecure and MUST be rejected by the receiver.

### 7.3 Protection against Replay Attacks

An attacker could try to record a valid handshake message (e.g., a `ConnectionRequest`) and send it again later to force a session, trigger state changes, or overload the server with redundant cryptographic operations (DoS). OAEP enforces a multi-layered protection mechanism.

#### 7.3.1 Uniqueness of the Nonce
Every handshake message MUST contain a cryptographically random Nonce (Number used once).
*   **Entropy:** The Nonce MUST be generated with a cryptographically secure random number generator (CSPRNG) and SHOULD have a length of at least 128 bits (16 bytes) to mathematically exclude collisions.
*   **Prohibition of Reuse:** An agent MUST never use the same Nonce for two different handshake attempts.

#### 7.3.2 The Nonce Cache (Normative Requirements)
Receivers MUST maintain a state store (**Nonce Cache**) to detect messages already processed.

*   **Check:** Before a computationally expensive operation (like signature verification) is performed, the receiver MUST check if the received Nonce already exists in the cache.
    *   **Hit:** The message is a replay. It MUST be discarded immediately. An error `ERR_NONCE_REPLAY` SHOULD be logged, but potentially not sent back to the sender for security reasons (Traffic Analysis / Silent Drop).
    *   **Miss:** The Nonce is stored in the cache, and processing continues.
*   **Retention Policy:**
    The cache MUST retain entries at least as long as the time window for valid timestamps is open (see 7.3.3).
    *   **Formula:** `RetentionTime >= ValidTimeWindow + ClockSkewTolerance`.
    *   *Recommendation:* With a time window of 5 minutes, Nonces MUST be stored for at least **310 seconds** (5 min + 10 sec tolerance).
*   **Scope:**
    To avoid collisions between different contexts, the cache SHOULD be partitioned per Peer DID and direction, if the DID is already known. For initial `ConnectionRequests` (where the DID is not yet verified), a global cache or a cache based on IP/Transport address MUST be used to mitigate DoS attacks on the cache itself.

#### 7.3.3 Time Window Limitation
To prevent the Nonce Cache from growing infinitely, messages MUST be limited by a timestamp (`created` according to RFC 3339).

*   **Outdated Messages:** Receivers MUST discard messages whose timestamp is older than a defined delta (Normative Standard: **300 seconds**).
*   **Future Messages:** Receivers MUST discard messages whose timestamp is more than **10 seconds** in the future (Protection against "Pre-Mining" Nonces for later replays).
*   **Interaction with Cache:** Only messages within this time window are checked against the Nonce Cache. Messages outside the window are discarded based on the timestamp. This allows the cache to be safely cleared after `RetentionTime` expires ("Rolling Window").

### 7.4 Metadata Privacy

Even with perfect end-to-end encryption (E2EE), traffic data (metadata) can be deanonymized through network analysis. OAEP implements countermeasures but points out physical limits and necessary design decisions.

#### 7.4.1 Limits of "Blind Relays" (IP Exposure)
The term "Blind Relay" in the OAP context refers exclusively to **Content Blindness**. The relay cannot read the encrypted payload (content of OAMP containers).
*   **Warning (Transport Layer Leak):** At the transport layer (TCP/IP, HTTP), the relay inevitably sees the **IP address** of the sending and receiving agents to technically deliver packets. A compromised relay can thus see *who* (IP) communicates with *whom* (IP), when, and how much.
*   **Mitigation:** To achieve complete anonymity (Transport Blindness), agents MUST route the connection to the relay through anonymization networks (e.g., **Tor** or **I2P**) or trusted VPNs. Implementations SHOULD provide native SOCKS5 proxy support to facilitate this for the user.

#### 7.4.2 DID Rotation (Unlinkability)
If an agent uses the same DID for interactions with different parties, correlatable profiles arise.
*   **Pairwise DIDs:** Agents SHOULD generate a new, dedicated DID (`did:key` or private `did:web` paths) for every new, long-term relationship. This prevents collaborators (e.g., two different shops or relays) from merging their logs and creating a global relationship profile of a user ("Correlation Attack").

#### 7.4.3 Traffic Padding (Length Obfuscation)
Encrypted messages often reveal their content through their length (e.g., a simple "Yes" is shorter than transmitting a key).
*   **Mandate:** OAEP handshake messages and subsequent OAMP packets SHOULD be padded to standardized block sizes (e.g., to the next multiple of 256 bytes) to eliminate this side-channel information.

#### 7.4.4 Protection of Sensitive Data in Handshake
The initial `ConnectionRequest` is often sent only transport-encrypted (TLS) to the relay before end-to-end encryption is established.
*   **Minimal Disclosure:** Agents SHOULD refrain from sending clear-text based `AgentProfiles` or detailed `Capabilities` in the first step (`ConnectionRequest`), provided these allow inferences about identity.
*   **Deferred Transmission:** Sensitive data MUST, whenever possible, be transmitted only **after** successful establishment of session keys (i.e., within the encrypted OAMP tunnel from Phase 3 or 4).
*   **Encryption at Rest (Relay):** If data must mandatorily be sent in the first step (e.g., for routing decisions), it MUST be packaged so that it can only be decrypted by the target agent (via its Public Key from the DID Document), not by the relay.

### 7.5 Cryptographic Agility & Cipher Suites

OAEP is designed for a lifespan of decades. Algorithms considered secure today could be broken by mathematical breakthroughs or the availability of quantum computers (CRQC). To combine security with future-proofing, OAEP relies on **atomic Cipher Suites**.

#### 7.5.1 Atomic Suites instead of "Mix & Match"
Agents MUST NOT negotiate signature, hashing, and encryption methods individually. This would increase combinatorial complexity and open attack vectors for downgrade attacks.
*   **Concept:** A Cipher Suite defines a fixed, tested combination of all necessary cryptographic primitives.
*   **Identification:** Each suite is identified by a unique string (Suite ID).

#### 7.5.2 The Negotiation Mechanism
Agreement on a suite occurs in the first round-trip of the handshake:
1.  **Offer (Initiator):** In the `ConnectionRequest`, the initiator sends the `supportedSuites` field. This is an ordered list of Suite IDs, starting with the **preferred (most secure)** suite.
2.  **Select (Responder):** The responder checks the list from top to bottom.
    *   **Tie-Break Rule:** If multiple common suites with identical security levels (according to local policy) are found, the responder MUST deterministically choose the suite whose Suite ID is lexically (ASCII sort) lowest (e.g., `OAEP-v1-2026` before `OAEP-v1-2027`).
3.  **Confirm (Responder):** In the `ConnectionResponse`, it sends the selected ID back in the `negotiatedSuite` field.
4.  **Enforcement:** From this point on, all cryptographic operations (Signatures, Key Derivation, Encryption) MUST strictly follow the specifications of this suite.

#### 7.5.3 Mandatory Suite for v1.0 (`OAEP-v1-2026`)
To guarantee basic interoperability, all OAEP v1.0 compliant implementations MUST support the following suite:

**Suite ID:** `OAEP-v1-2026`

| Primitive | Algorithm / Specification | Purpose |
| :--- | :--- | :--- |
| **Signature** | **Ed25519** (EdDSA) | Authentication & Integrity |
| **Key Agreement** | **X25519** (ECDH) | Perfect Forward Secrecy (PFS) |
| **Encryption** | **ChaCha20-Poly1305** (IETF) | Message Encryption |
| **Hashing / KDF** | **BLAKE3** | Transcript Hash & Key Derivation |

*Note: BLAKE3 is preferred due to its performance and security properties in modern Rust environments. A fallback to SHA-256 is not provided in this Suite ID to maintain determinism.*

#### 7.5.4 Post-Quantum Readiness & Hybrid Suites
The protocol is explicitly designed to support **hybrid methods** to safely manage the transition to the Post-Quantum Era.
*   **Hybrid Suites:** A future Suite ID (e.g., `OAEP-v2-PQ-Hybrid`) can define that **both** X25519 (classical) **and** Kyber-768 (PQC) must be used for key exchange. The `keyExchange` field in JSON-LD allows structured objects for this.
*   **Security through Redundancy:** By using a hybrid approach, the connection remains secure as long as *one* of the two algorithms (classical ECC or new PQC) remains unbroken.
*   **Mandate:** If an agent supports a newer, more secure suite (e.g., PQC), it MUST rank this ahead of older suites (Legacy ECC) in its `supportedSuites` list. Responders MUST choose the most secure common suite.

### 7.6 Implementation Security

*   **Timing Attacks:**
    Cryptographic comparisons (e.g., verifying MACs or Hashes) MUST be performed in "Constant Time" to prevent attackers from inferring the key by measuring response time.
*   **Error Messages:**
    In case of error (e.g., invalid signature, unknown DID), agents MUST NOT disclose detailed information that could help an attacker (e.g., "User does not exist" vs. "User exists, but key incorrect"). Generic error codes SHOULD be used.
*   **Input Validation:**
    All incoming JSON-LD data must be strictly validated against the schema before processing to prevent injection attacks or buffer overflows.

---

**Section 8: Implementation Guidelines**

## 8. Implementation Guidelines

This chapter provides normative and informative guidance for developers implementing OAEP in software libraries or applications. The goal is to maximize interoperability and network robustness.

### 8.1 Error Handling

In a distributed, asynchronous system, operation failure is an expected state. OAEP defines a standardized format for error messages so sending agents can react programmatically and securely to problems.

#### 8.1.1 The `OAEPError` Object
If a handshake or processing fails and security policies (see 8.1.4) allow a response, the agent MUST return an `OAEPError` message.

```json
{
  "@context": "https://w3id.org/oaep/v1",
  "type": "OAEPError",
  "id": "urn:uuid:...", 
  "replyTo": "urn:uuid:original-request-id",
  "category": 2000,
  "code": "ERR_AUTH_SIG_INVALID",
  "message": "Signature verification failed against DID document.",
  "timestamp": "2026-06-01T12:00:00Z"
}
```

#### 8.1.2 Taxonomy: Codes vs. Categories
To ensure stability and extensibility, OAEP distinguishes between semantic String IDs and numerical categories.

1.  **Code (String ID):** The `code` field is the normative identifier (e.g., `"ERR_PROTO_VERSION"`). Implementations MUST base their logic ("Switch-Case") on this string.
2.  **Category (Numeric):** The `category` field serves for grouping and generic fallback behavior.

| Category | Range | Meaning | Generic Behavior |
| :--- | :--- | :--- | :--- |
| **Protocol** | 1000-1999 | Syntax, Parsing, Versioning | Correct request & retry (if possible). |
| **Auth/Sec** | 2000-2999 | Signatures, DIDs, Expiration | **Fatal.** Abort session. Re-authentication necessary. |
| **Network** | 3000-3999 | Rate Limits, Routing, Timeouts | Wait (Backoff) and Retry. |
| **App** | 4000-4999 | Logic error in Layer 1 (OACP etc.) | Application dependent. |

#### 8.1.3 Normative Error Codes (Excerpt)
Implementations SHOULD support at least the following codes:

*   `ERR_MALFORMED_JSON` (1001): JSON-LD invalid or schema violated.
*   `ERR_PROTO_VERSION` (1002): Incompatible protocol version.
*   `ERR_DID_RESOLUTION` (2001): DID could not be resolved.
*   `ERR_AUTH_SIG_INVALID` (2002): Cryptographic signature verification failed.
*   `ERR_NONCE_REPLAY` (2003): Message already processed.
*   `ERR_RATE_LIMIT` (3001): Too many requests (Backoff required).

#### 8.1.4 Security Policies (Response Matrix)
Not every error may be answered. To prevent *Information Leakage*, *Reflection Attacks*, and *DoS Amplification*, the following rules apply for sending `OAEPError`:

Three normative policies for error handling:
1.  **Reply & Continue:** (Syntax/App errors in active session).
    *   *Application:* For syntax errors (`1xxx`) or application errors (`4xxx`) within an already **authenticated** (encrypted) session.
    *   *Action:* Send `OAEPError`. Keep connection open.

2.  **Reply & Close:** (Auth errors in Handshake).
    *   *Application:* For authentication errors (`2xxx`) or protocol mismatch during the handshake.
    *   *Action:* Send `OAEPError` (to enable peer debugging). Immediately delete all session keys. Close transport connection.

3.  **Silent Drop:** (DoS suspicion, Replay, invalid timestamps) -> Send no response.
    *   *Application:*
        *   Upon suspicion of DoS (e.g., extremely high request rate).
        *   For Replay Attacks (`ERR_NONCE_REPLAY`).
        *   For invalid timestamps (Expired/Future).
        *   If parsing the header fails (Sender unclear).
    *   *Action:* **Send no response.** Minimize resource usage. Potentially block IP temporarily (Fail2Ban).
    *   *Reason:* Sending an error would confirm to the attacker that a service is running and could consume bandwidth for an Amplification Attack.

### 8.2 Versioning and Compatibility

The OAEP ecosystem will evolve. Implementations MUST be robust against version differences.

*   **Semantic Versioning:** OAEP uses SemVer (MAJOR.MINOR.PATCH).
    *   *Patch Updates (1.0.1):* Must not make changes to the data model.
    *   *Minor Updates (1.1.0):* May add new fields (additive changes). Older implementations MUST ignore unknown fields ("Forward Compatibility").
    *   *Major Updates (2.0.0):* Breaking changes. Require re-negotiation.
*   **Negotiation:**
    During the handshake, every agent sends its version (`oaepVersion: "1.0"`). Communication occurs on the highest common denominator (Major Version). If Agent A supports v1.2 and Agent B v1.0, Agent A MUST fall back to v1.0 behavior.

### 8.3 Performance & Resource Management

Since OAEP agents often operate on mobile end devices (battery and bandwidth limited) or in IoT environments, efficient resource management is not just an optimization but a prerequisite for stability.

#### 8.3.1 Local Context Rule (No Runtime Fetching)
JSON-LD uses URLs (e.g., `https://w3id.org/oaep/v1`) to define vocabulary.
*   **Risk:** Loading these resources at runtime would violate privacy (tracking by server operator on every handshake) and endanger protocol availability during internet outages.
*   **Mandate:** OAEP implementations **MUST** ship static, local copies of all supported JSON-LD contexts (Core OAEP, W3C DIDs, W3C VCs) with the software ("Ship with code").
*   **Prohibition:** The JSON-LD processor MUST strictly **block** external HTTP requests for known `@context` URIs and use local static copies instead (see 9.3).

#### 8.3.2 Caching of DID Documents
Resolving DIDs (especially `did:web` via DNS/HTTPS) is an expensive operation.
*   **Caching Mandate:** Implementations MUST apply a caching strategy for resolved DID Documents.
*   **TTL (Time To Live):**
    *   For `did:web`, cache duration SHOULD follow HTTP Headers (`Cache-Control`) of the source, but be at least 15 minutes to prevent "Resolution Spam".
    *   For `did:key`, the document is immutable. It MAY be cached indefinitely.
*   **Invalidation:** Before critical transactions (e.g., a large payment), the cache MAY be ignored to ensure no key revocation was missed.

#### 8.3.3 DoS Mitigation & "Silent Drop"
The handshake requires asymmetric cryptography (Signature verification, ECDH), which is computationally intensive. Attackers can use this for *Resource Exhaustion*.
*   **Behavior under Load:** If an agent detects resources (CPU, Memory, open Sockets) running low, it SHOULD switch to **"Defensive Mode"**.
*   **Silent Drop:** In Defensive Mode or with obviously malformed packets (wrong Magic Byte, invalid timestamps), the agent MUST **silently drop** packets instead of wasting computing power creating and sending `OAEPError` responses.
*   **Rate Limiting:** Server-side agents MUST implement limits on the number of handshake attempts per IP address or DID per time window.

**Normative Rate-Limiting Algorithm (Token Bucket):**
To prevent handshake flooding and PSI scraping, server endpoints MUST implement a **Token Bucket Filter**:
*   **Bucket Capacity ($C$):** Defines the burst (Recommendation: 50).
*   **Refill Rate ($R$):** Defines sustained load (Recommendation: 5/second).
*   Scope: Per IP (anonymous) or per DID (authenticated).
*   On empty bucket: `ERR_RATE_LIMIT` or Silent Drop.

#### 8.3.4 Connection Reuse (Keep-Alive)
Establishing a TLS connection (for transport) and the OAEP handshake create overhead.
*   **Persistent Connections:** If the underlying transport channel allows (e.g., HTTP/2, WebSockets, QUIC), the connection SHOULD be kept open for multiple consecutive OAMP messages.
*   **Timeouts:**
    *   For the synchronous part of the handshake (Request <-> Response), a timeout of **30 seconds** applies.
    *   For inactive sessions, an "Idle Timeout" (e.g., 10 minutes) SHOULD be implemented, after which ephemeral keys are deleted and the connection closed to free memory.

### 8.4 Reference Implementation

To accelerate development and ensure standard compliance, the OAP Foundation provides an official reference implementation.

*   **OAP Core (Rust):**
    The security-critical logic (Cryptography, DID Resolution, Handshake State Machine) is implemented in Rust.
    *   *Repository:* `github.com/oap-foundation/oap-core-rs`
    *   *Status:* This is the "Source of Truth" for protocol behavior.
*   **Bindings (SDKs):**
    Wrappers utilizing the Rust Core are provided for application developers:
    *   `oap-python` (for Backend/AI Services)
    *   `oap-dart` (for Flutter/Mobile Apps)
    *   `oap-js` (WASM-based for Web Clients)

Developers are STRONGLY encouraged to use these libraries instead of implementing cryptography themselves ("Don't roll your own crypto").

### 8.5 Testing & Conformance

An implementation may only call itself "OAEP Compliant" if it passes the official test suite.

*   **Test Vectors:**
    The RFC repository contains a folder `/test-vectors`. This includes JSON files with input data (e.g., raw keys, DIDs) and expected output data (e.g., correct signatures, validated handshake messages).
*   **Integration Tests:**
    Developers should test their agents against the **"OAP Echo Bot"**. This is a publicly available, always-up-to-date reference agent (`did:web:echo.oap.foundation`) that accepts any correct handshake and mirrors messages.

### 8.6 Migration from Legacy Systems

For developers wishing to connect existing Web2 systems (e.g., classic REST APIs):

*   **OAP Gateway Pattern:**
    It is recommended to operate a "Sidecar" agent that speaks OAEP and internally forwards requests to the legacy API.
*   **Authentication Bridge:**
    Existing OAuth2 systems can use OAEP by replacing the `id_token` flow with an OAEP handshake. The result of the handshake (the verified DID) is then internally mapped to a local user account.
    
### 8.7 Edge Cases & Resilience

Robust implementations are characterized by mastering not only the successful path ("Happy Path") but also acting deterministically and securely in error states.

#### 8.7.1 Incomplete Handshakes ("Hanging State")
A common attack pattern or network problem is the "half handshake": Initiator A sends a Request, Responder B answers, but A never sends the final Acknowledge. B now holds memory resources (Ephemeral Keys, State) for a connection that never materializes.

*   **Mandate (State Cleanup):** Implementations MUST set a strict timer for handshake completion (Recommendation: 30 seconds from receipt of first message).
*   **Action:** If the timer expires before `ACTIVE` status is reached, the agent MUST:
    1.  Discard the entire session context.
    2.  Securely delete all generated Ephemeral Keys from memory (overwrite/zeroize).
    3.  Return to `IDLE` status.
*   **Prohibition:** No "Ghost Session" may be kept open in hopes that the Acknowledge arrives hours later.

#### 8.7.2 Transport Loss vs. Session Status
Since OAEP v1.0 supports no *Session Resumption*, cryptographic session status is tightly coupled to the underlying transport connection (e.g., TCP Socket, WebSocket).

*   **Connection Drop:** If the transport layer signals a drop (e.g., TCP FIN/RST, WebSocket Close), the OAEP agent MUST immediately regard the cryptographic session as terminated.
*   **Key Destruction:** Symmetric session keys (`sk_a_to_b`, `sk_b_to_a`) MUST be immediately deleted.
*   **Reconnect:** Re-establishing connection mandatorily requires a new, full OAEP handshake with fresh keys. Implementers MUST NOT try to reuse old session keys on a new TCP connection (Violation of Forward Secrecy).
*   **Keepalive for Unstable Transports (BLE/NFC):**
    For transport media without native connection states, a Heartbeat mechanism MUST be used.
    *   **Message:** Type `OAEPHeartbeat` (Body empty).
    *   **Interval:** Every 30s (Default).
    *   **Ack:** Receiver answers with `OAEPHeartbeatAck`.
    *   **Timeout:** After 3 unanswered heartbeats, keys MUST be deleted.

#### 8.7.3 `did:key` without Service Endpoint (In-Band Transport)
`did:key` documents often contain no `service` entry, as they are intended for ad-hoc scenarios (e.g., Bluetooth LE, WebSockets, or scanning a QR code).

*   **Implicit Routing:** If an agent initiates a handshake with a `did:key` possessing no Service Endpoint, it MUST NOT abort resolution with `ERR_DID_RESOLUTION`.
*   **Mandate:** In this case, the agent MUST assume that the transport channel already exists "In-Band" (i.e., the response is sent back over the same socket the request came from).
*   **Security Note:** This does not absolve from the obligation of signature verification. In-Band messages must also be cryptographically verified.

#### 8.7.4 Race Conditions (Simultaneous Handshakes)
Scenario: Agent A sends `ConnectionRequest` to B. Simultaneously, B sends `ConnectionRequest` to A.

*   **Resolution:** OAEP treats this as two completely separate, independent attempts.
*   **Behavior:** Both agents should try to continue their respective handshake as Responder or Initiator. Two parallel encrypted tunnels are created (in success case).
*   **App-Layer Decision:** It is up to application logic (Layer 1) to decide which tunnel to use (e.g., "use tunnel with newer timestamp") and close the other (`OAEPError` or TCP Close).

#### 8.7.5 Panic Mode (State Exhaustion)
If a server is under massive load and has no memory for new Handshake States (`AWAIT_ACK`):
*   **Policy:** The agent SHOULD avoid the **"LIFO Drop" (Last In, First Out) principle**. Instead, it SHOULD either:
    1.  Discard the oldest not-yet-completed handshake (LRU Eviction) to make space.
    2.  Or immediately silently drop new requests (Silent Drop) until memory recovers.
*   **No Crash:** Memory exhaustion from too many open handshakes MUST NEVER lead to a crash of the entire agent process.

### 8.8 Protocol Lifecycle and Deprecation
Since cryptographic algorithms age, OAEP v1.0 defines a mechanism for the orderly retirement (Sunset) of Cipher Suites.
*   **Sunset Announcement:** Responders MAY send a `warnings` field in the `ConnectionResponse` Header (e.g., "Suite deprecated on 2029-01-01").
*   **Hard Cutoff:** After the cutoff date, usage of the suite MUST be rejected with `ERR_UNSUPPORTED_SUITE`.
*   **Long-lived Devices:** IoT devices MUST be updateable or shipped with conservative, hybrid suites (see 7.5.4) aiming for a lifespan of >10 years.

### 8.9 Compatibility with W3C Standards
OAEP v1.0 is normatively bound to **W3C DID Core v1.0** and **Verifiable Credentials v1.1**. Newer W3C formats MUST be transparently mapped ("downgraded") to these versions at the interface.
*   **Forward Compatibility:** Should future W3C standard versions (e.g., DID v2.0) introduce breaking changes, OAEP v1.0 remains on v1.0/v1.1 definitions. Support for new W3C standards requires an upgrade to OAEP v2.0.
*   **Mapping:** Implementations internally using newer W3C formats MUST transparently map these to the v1.0/v1.1 specification at the OAEP interface (in the handshake) to not jeopardize protocol integrity.

---

**Section 9: Appendix & Examples**

## 9. Appendix and Examples

This section is informative, not normative. It provides examples of JSON-LD payloads and cryptographic test vectors to assist developers with implementation and debugging.

### 9.1 Full Handshake Flow (Example)

The following scenario describes a successful handshake ("Happy Path") between two agents. It demonstrates negotiation of encryption parameters and **Channel Binding via Transcript Signatures** to prevent Man-in-the-Middle attacks.

*   **Initiator (Alice):** `did:key:z6MkAlice...` (Personal AI on a smartphone)
*   **Responder (Bob):** `did:web:shop.com` (An Online Shop)

#### Step 1: ConnectionRequest (Alice -> Bob)
Alice wants to establish a connection. She generates a Nonce (`Nonce_A`), her ephemeral key (`EphemeralKey_A`), and lists Cipher Suites she supports.

```json
{
  "@context": ["https://w3id.org/oaep/v1"],
  "type": "ConnectionRequest",
  "id": "urn:uuid:a1b2c3d4-e5f6-7890-1234-567890abcdef",
  "from": "did:key:z6MkAliceXyZ123...",
  "to": "did:web:shop.com",
  "created": "2026-11-23T14:30:00Z",
  "body": {
    "nonce": "nonce_alice_random_string_987",
    "keyExchange": {
      "supportedSuites": ["OAEP-v1-2026", "OAEP-v2-PQ-Hybrid"],
      "mechanism": "X25519",
      "publicKey": "MultibaseEncodedEphemeralKeyAlice..."
    },
    // Optional: Embedded AgentProfile (not yet encrypted!)
    "profile": { ... }
  }
}
```

#### Step 2: ConnectionResponse (Bob -> Alice)
Bob receives the request. He chooses Suite `OAEP-v1-2026`, generates his values (`Nonce_B` and `EphemeralKey_B`), and creates the **Handshake Transcript** (according to Section 5.2.1).
**Important:** Bob signs the hash of this transcript to irrevocably bind his identity (`did:web:shop.com`) to the negotiated keys.

```json
{
  "@context": ["https://w3id.org/oaep/v1"],
  "type": "ConnectionResponse",
  "id": "urn:uuid:b2c3d4e5-f6a7-8901-2345-678901bcdefa",
  "replyTo": "urn:uuid:a1b2c3d4-e5f6-7890-1234-567890abcdef",
  "from": "did:web:shop.com",
  "to": "did:key:z6MkAliceXyZ123...",
  "created": "2026-11-23T14:30:01Z",
  "body": {
    "nonce": "nonce_bob_random_string_456",
    "keyExchange": {
      "negotiatedSuite": "OAEP-v1-2026",
      "mechanism": "X25519",
      "publicKey": "MultibaseEncodedEphemeralKeyBob..."
    }
  },
  "proof": {
    "type": "Ed25519Signature2020",
    "created": "2026-11-23T14:30:01Z",
    "verificationMethod": "did:web:shop.com#key-1",
    "proofPurpose": "authentication",
    // NOTE: This field represents the hash of the entire
    // Handshake Transcript (JCS normalized), not just the Nonce.
    // Hash(Header + Alice_Params + Bob_Params)
    "transcriptHash": "SHA256_HASH_OF_FULL_TRANSCRIPT_XYZ...",
    "jws": "eyJhbGciOiJFZ...SignatureOverTranscriptHash..."
  }
}
```

#### Step 3: ConnectionAcknowledge (Alice -> Bob)
Alice checks Bob's signature against the locally reconstructed transcript. It is valid. Now Alice signs **the same transcript** with her private key to prove her own identity and close the channel on both sides.

```json
{
  "@context": ["https://w3id.org/oaep/v1"],
  "type": "ConnectionAcknowledge",
  "id": "urn:uuid:c3d4e5f6-a7b8-9012-3456-789012cdefab",
  "replyTo": "urn:uuid:b2c3d4e5-f6a7-8901-2345-678901bcdefa",
  "from": "did:key:z6MkAliceXyZ123...",
  "to": "did:web:shop.com",
  "created": "2026-11-23T14:30:02Z",
  "proof": {
    "type": "Ed25519Signature2020",
    "created": "2026-11-23T14:30:02Z",
    "verificationMethod": "did:key:z6MkAliceXyZ123...#z6MkAliceXyZ123...",
    "proofPurpose": "authentication",
    // Here too: Signature over the same transcript as Bob
    "transcriptHash": "SHA256_HASH_OF_FULL_TRANSCRIPT_XYZ...",
    "jws": "eyJhbGciOiJFZ...SignatureOverTranscriptHash..."
  }
}
```
*After this step, both parties possess the Shared Secret (via ECDH of their ephemeral keys) and the session is established. Status changes to `ACTIVE`.*

### 9.2 Cryptographic Test Vectors

Implementers MUST test their libraries against these vectors to ensure compatibility.

#### 9.2.1 DID Derivation (did:key)
*   **Algorithm:** Ed25519
*   **Public Key (Hex):** `4cc5d946841753173d639b7367616b492927976176332766324e6c382b6c7938`
*   **Expected DID:** `did:key:z6Mkk7yqnYD6h4nwVeM8jQjC9K9E5g8jFwi5p5J555555555` *(Note: Example value, must be computed for real)*

#### 9.2.2 Shared Secret Derivation (X25519)
Simulates ECDH exchange for Session Keys.

*   **Alice Private Ephemeral (Hex):** `77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a`
*   **Bob Public Ephemeral (Hex):** `de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f`
*   **Expected Shared Secret (Hex):** `4a5d9d5ba4c49464a8395187327c76910d643c8e47087798341e975971573327`

### 9.3 OAEP JSON-LD Context Definition
The following Context is **normative**. Implementations MUST host this content locally.

```json
{
  "@context": {
    "@version": 1.1,
    "id": "@id",
    "type": "@type",
    "oaep": "https://w3id.org/oaep/v1#",
    "xsd": "http://www.w3.org/2001/XMLSchema#",
    
    "ConnectionRequest": "oaep:ConnectionRequest",
    "ConnectionResponse": "oaep:ConnectionResponse",
    "ConnectionAcknowledge": "oaep:ConnectionAcknowledge",
    "OAEPError": "oaep:OAEPError",
    "OAEPHeartbeat": "oaep:OAEPHeartbeat",
    "OAEPHeartbeatAck": "oaep:OAEPHeartbeatAck",

    "from": { "@id": "oaep:from", "@type": "@id" },
    "to": { "@id": "oaep:to", "@type": "@id" },
    "replyTo": { "@id": "oaep:replyTo", "@type": "@id" },
    "created": { "@id": "oaep:created", "@type": "xsd:dateTime" },
    "body": "oaep:body",
    "nonce": "oaep:nonce",
    "keyExchange": "oaep:keyExchange",
    "mechanism": "oaep:mechanism",
    "publicKey": "oaep:publicKey",
    "transcriptHash": "oaep:transcriptHash",
    "capabilities": "oaep:capabilities",
    "protocol": { "@id": "oaep:protocol", "@type": "@id" },
    "version": "oaep:version",
    
    "code": "oaep:code",
    "category": "oaep:category",
    "message": "oaep:message"
  }
}
```

### 9.4 List of Reserved Error Codes

OAEP uses a dual error system.
1.  **`code` (String):** The normative, unique identifier (e.g., `"ERR_AUTH_SIG_INVALID"`). Implementations MUST base their program logic on this string.
2.  **`category` (Integer):** A grouping for generic behavior (e.g., `2002`).

Implementations MUST support the following standard codes. The range `1000` to `4999` is reserved for the Core Protocol.

#### 9.4.1 Category 1xxx: Syntax & Protocol Errors
*Behavior: The Request is technically invalid. Correction by sender required.*

| Code ID | Category | Description |
| :--- | :--- | :--- |
| `ERR_MALFORMED_JSON` | 1001 | Received JSON is syntactically incorrect or violates schema. |
| `ERR_PROTO_VERSION` | 1002 | Requested OAEP version not supported by receiver. |
| `ERR_MISSING_FIELD` | 1003 | Mandatory field (e.g., `nonce`, `proof`) is missing. |
| `ERR_ENCODING_INVALID` | 1004 | A field has wrong format (e.g., invalid Base64 or Hex). |

#### 9.4.2 Category 2xxx: Identity & Security Errors
*Behavior: **Fatal.** Identity or integrity could not be verified. Connection MUST be closed immediately and all keys discarded.*

| Code ID | Category | Description |
| :--- | :--- | :--- |
| `ERR_DID_RESOLUTION` | 2001 | Sender's DID could not be resolved (e.g., DNS error for `did:web`). |
| `ERR_AUTH_SIG_INVALID` | 2002 | Cryptographic signature over transcript is mathematically invalid. |
| `ERR_UNKNOWN_KEY` | 2003 | Key used for signing (`verificationMethod`) not found in DID Document. |
| `ERR_CERT_REVOKED` | 2004 | Credential or key used is on a revocation list (StatusList2021). |
| `ERR_CERT_EXPIRED` | 2005 | `expirationDate` of Credential or DID has passed. |
| `ERR_UNSUPPORTED_SUITE`| 2006 | No common Cipher Suite could be negotiated. |
| `ERR_SECURITY_KEY_MISMATCH` | 2007 | Public key does not match locally pinned key (TOFU). |

#### 9.4.3 Category 3xxx: Network & State Errors
*Behavior: Temporary error or protection measure. Retry (with Backoff) possible or message discarded.*

| Code ID | Category | Description |
| :--- | :--- | :--- |
| `ERR_RATE_LIMIT` | 3001 | Too many requests. Sender MUST apply exponential backoff. |
| `ERR_NONCE_REPLAY` | 3002 | Nonce already used. Message discarded (Replay Attack Protection). |
| `ERR_MSG_EXPIRED` | 3003 | Timestamp too far in the past (outside tolerance window). |
| `ERR_MSG_FUTURE` | 3004 | Timestamp in the future (Clock Drift too large). |
| `ERR_STATE_MISMATCH` | 3005 | Message type does not match current state (e.g., received ACK though no Request sent). |

#### 9.4.4 Category 4xxx: Policy & Application Errors (Logic Errors)
*Behavior: Message was technically correct but rejected for logical or legal reasons.*

| Code ID | Category | Description |
| :--- | :--- | :--- |
| `ERR_POLICY_REJECTED` | 4001 | Agent refuses communication (e.g., Blocklist, Geoblocking, "Verified Users Only"). |
| `ERR_NO_COMMON_PROTO` | 4002 | No match in *Capability Negotiation* (no common language in Layer 1). |
| `ERR_APP_GENERIC` | 4999 | Unspecified error in processing application (Layer 1). |

#### 9.4.5 Custom Errors
Developers building their own extensions MAY define codes in the range **9000-9999**.
*   **Naming Convention:** Custom codes MUST start with a unique namespace (Vendor Prefix) to avoid collisions.
*   *Example:* `COM_SHOPIFY_OUT_OF_STOCK` (Category 9001).