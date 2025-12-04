# RFC: Open Agent Exchange Protocol (OAEP)
**Version:** 1.0 (PROPOSED STANDARD)
**Status:** CODE FREEZE
**Date:** 2025-11-25

**Section 1: Introduction**

## 1. Einleitung

Das Internet, ursprünglich als dezentrales Netzwerk konzipiert, hat sich in den letzten zwei Jahrzehnten zu einer Topologie zentralisierter Plattformen und "Walled Gardens" entwickelt. In dieser Architektur sind Identität, Daten und Interaktionsfähigkeit untrennbar mit spezifischen Anbietern (Identity Providers, IdPs) verbunden.

Mit dem Aufkommen autonomer KI-Agenten ("Personal AI") stößt dieses zentralisierte Modell an seine Grenzen. Ein KI-Agent, der im Auftrag eines Nutzers handeln soll, benötigt eine Identität, die mathematisch verifizierbar, aber administrativ unabhängig ist.

Das **Open Agent Exchange Protocol (OAEP)** legt dieses Fundament. Es ist das Protokoll für **Schicht 0** des OAP-Frameworks. Es definiert, wie digitale Entitäten ihre Identität beweisen, Vertrauen etablieren und eine sichere Kommunikationsbasis aushandeln.

### 1.1 Motivation

Die Notwendigkeit für OAEP ergibt sich aus drei fundamentalen Defiziten bestehender Standards (wie OAuth 2.0, OIDC oder X.509) im Kontext einer dezentralen Agenten-Ökonomie:

1.  **Abhängigkeit von zentralen Vertrauensankern (Root of Trust):**
    Klassische PKI- und föderierte Identitätssysteme (Federated Identity) basieren auf hierarchischen Vertrauensketten (Certificate Authorities oder IdP-Server). Fällt der zentrale Anker aus oder entzieht er das Vertrauen (De-Platforming), verliert der Agent seine Handlungsfähigkeit. OAEP ersetzt diese Hierarchie durch ein "Web of Trust" und dezentrale Identifikatoren (DIDs), bei denen die Validierung der Identität direkt durch Kryptografie und nicht durch administrative Bestätigung erfolgt.

2.  **Mangelnde Offline- und P2P-Fähigkeit:**
    Moderne KI-Agenten operieren zunehmend "Local-First" (auf dem Endgerät) oder in direkten Peer-to-Peer-Netzwerken. Protokolle, die für jede Interaktion einen "Call Home" zu einem Authentifizierungsserver benötigen, erzeugen Latenz, Sicherheitsrisiken und Metadaten-Spuren. OAEP ermöglicht eine gegenseitige Authentifizierung (Mutual Authentication) auch in vollständig isolierten Umgebungen (z.B. über Bluetooth LE oder lokale Netzwerke), solange die kryptografischen Schlüssel vorhanden sind.

3.  **Fehlende Semantik für Agenten-Fähigkeiten:**
    In einer Welt heterogener KI-Agenten ist die Frage "Wer bist du?" untrennbar mit der Frage "Was kannst du?" verbunden. Bestehende Protokolle trennen Identität strikt von Capability-Discovery. OAEP integriert diese Schritte in einen effizienten Handshake-Prozess. Ein Agent weist sich nicht nur aus, sondern signalisiert kryptografisch signiert, welche Protokolle (z.B. Commerce, Governance) er unterstützt und welche Versionen er spricht.

### 1.2 Scope (Geltungsbereich)

OAEP ist als **Fundament-Protokoll** konzipiert. Sein Aufgabenbereich ist strikt abgegrenzt, um Modularität und Sicherheit zu gewährleisten.

**In Scope (Bestandteil von OAEP):**
*   **Identitäts-Management:** Die Erstellung, Verwaltung und Auflösung von Decentralized Identifiers (DIDs).
*   **Verifiable Credentials (VCs):** Der Transport und die Validierung von Eigenschaftsnachweisen (z.B. "Ist ein verifizierter Händler", "Ist volljährig") innerhalb des Verbindungsaufbaus.
*   **Handshake & Authentifizierung:** Der kryptografische Prozess (Challenge-Response), um sicherzustellen, dass das Gegenüber den privaten Schlüssel zur behaupteten Identität besitzt.
*   **Capability Negotiation:** Die Aushandlung der unterstützten Anwendungsprotokolle (Schicht 1) und Verschlüsselungsparameter.
*   **Session Establishment:** Die Ableitung von temporären Sitzungsschlüsseln (Ephemeral Keys) für die nachfolgende Kommunikation.

**Out of Scope (Nicht Bestandteil von OAEP v1.0):**
*   **Nachrichtentransport:** OAEP definiert nicht, wie Datenpakete über das Netzwerk geroutet oder gespeichert werden. Dies ist Aufgabe des *Open Agent Message Protocol (OAMP)*.
*   **Inhaltliche Payload:** Die Struktur von Handelsangeboten, Social-Media-Posts oder Zahlungen wird in den jeweiligen Anwendungsprotokollen (OACP, SFP, OAPP) definiert. OAEP liefert lediglich den sicheren Tunnel für diese Daten.
*   **Konsens-Mechanismen:** OAEP ist keine Blockchain. Es nutzt Distributed Ledgers (wo nötig) nur als Verzeichnisdienst (Registry) für öffentliche Schlüssel, nicht zur Transaktionsabwicklung.
*   **Session Resumption (Wiederaufnahme):** OAEP v1.0 definiert den initialen, vollständigen Handshake. Mechanismen zur beschleunigten Wiederaufnahme von Sitzungen ohne erneute PKI-Operationen (z.B. 0-RTT oder Fast Reconnect nach Netzwerkwechsel) sind Aufgabe der Transportschicht (OAMP) oder werden in zukünftigen Protokollerweiterungen spezifiziert.

### 1.3 Design Philosophy

Die Architektur von OAEP folgt vier unverhandelbaren Design-Prinzipien, die die Werte der digitalen Souveränität technisch kodifizieren:

1.  **Self-Sovereignty (Selbstverwaltung):**
    Die Kontrolle über Identität und Schlüsselmaterial verbleibt ausschließlich beim Nutzer (Principal) bzw. dessen Agenten. Es gibt keine "Master-Keys" oder "Backdoors" für Plattformbetreiber. Ein Widerruf der Identität ist nur durch den Inhaber selbst möglich.

2.  **Privacy by Design & Minimal Disclosure:**
    Standardmäßig gibt ein Agent während des Handshakes nur die absolut notwendigen Informationen preis. Die Nutzung von *Zero-Knowledge-Proofs (ZKPs)* wird explizit unterstützt, um Eigenschaften zu beweisen (z.B. "Solvenz vorhanden"), ohne die zugrundeliegenden Daten (z.B. Kontostand) offenlegen zu müssen.

3.  **Transport Agnosticism:**
    OAEP operiert auf der Anwendungsschicht (Application Layer). Es setzt keine spezifische Transportschicht voraus. Ein OAEP-Handshake muss über HTTPS genauso funktionieren wie über WebSockets, BLE (Bluetooth Low Energy), NFC oder asynchrone Message Queues.

4.  **Cryptographic Agility (Zukunftssicherheit):**
    Angesichts der Bedrohung durch Quantencomputer (Post-Quantum-Era) legt sich OAEP nicht statisch auf einzelne Algorithmen fest. Das Protokoll enthält Mechanismen zur Versionierung und Aushandlung von kryptografischen Verfahren (Cipher Suites), sodass das gesamte Ökosystem nahtlos auf sicherere Algorithmen (z.B. Post-Quantum-Kryptografie) migriert werden kann, ohne die Architektur zu brechen.

---

**Section 2: Terminology & Definitions**

## 2. Begriffsbestimmungen und Terminologie

Um eine eindeutige Interpretation dieses Protokolls und interoperable Implementierungen zu gewährleisten, werden in diesem Abschnitt die zentralen Begriffe definiert. Soweit möglich, referenziert OAEP etablierte Begriffe aus den W3C-Spezifikationen für *Decentralized Identifiers (DID) v1.0* und *Verifiable Credentials (VC) v1.1*.

Die Schlüsselwörter "MUSS" ("MUST"), "DARF NICHT" ("MUST NOT"), "SOLLTE" ("SHOULD") und "KANN" ("MAY") in diesem Dokument sind entsprechend RFC 2119 zu interpretieren.

### 2.1 Rollen und Akteure

In einer OAEP-Interaktion nehmen Entitäten spezifische Rollen ein. Eine Entität kann je nach Kontext mehrere Rollen gleichzeitig innehaben.

*   **Principal (Prinzipal/Inhaber):**
    Die rechtliche oder natürliche Entität, die die ultimative Kontrolle über eine Identität ausübt. Dies kann ein menschlicher Nutzer, ein Unternehmen oder eine Organisation sein. Der Principal ist der rechtmäßige Besitzer des privaten Schlüsselmaterials.

*   **Agent (Software-Agent):**
    Eine Software-Instanz, die autonom oder semi-autonom im Auftrag eines Principals handelt. Im Kontext von OAEP ist der Agent der technische Endpunkt, der das Protokoll ausführt, kryptografische Operationen durchführt und Entscheidungen basierend auf den Vorgaben des Principals trifft (z.B. eine "Personal AI" auf einem Smartphone).

*   **Issuer (Aussteller):**
    Eine vertrauenswürdige Entität, die Behauptungen (Claims) über einen Principal verifiziert und diese in Form von *Verifiable Credentials* kryptografisch signiert bestätigt (z.B. eine Bank, die Bonität bestätigt, oder der OAP Verein, der die Echtheit eines Shops bestätigt).

*   **Verifier (Prüfer):**
    Die Rolle eines Agenten, der einen Identitätsnachweis oder ein Credential von einem anderen Agenten empfängt, dessen kryptografische Signatur prüft und die Gültigkeit (z.B. Widerrufsstatus) validiert.

*   **Relay (Vermittler):**
    Ein Infrastruktur-Knoten, der den Transport von OAEP-Handshake-Nachrichten ermöglicht, wenn keine direkte P2P-Verbindung möglich ist (z.B. aufgrund von NAT/Firewalls). Ein Relay im OAP-Kontext ist "blind"; es leitet verschlüsselte Pakete weiter, ohne Zugriff auf Identitäten oder Inhalte zu haben.

### 2.2 Identität und Adressierung

OAEP nutzt das DID-Format als primären Mechanismus zur Identifikation.

*   **DID (Decentralized Identifier):**
    Ein global eindeutiger, dauerhafter Identifikator, der keine zentrale Registrierungsstelle benötigt.
    *   *Format:* `did:<method>:<unique-idstring>`
    *   *Beispiel:* `did:key:z6MkhaXgBZDvotDkL5257m5NrJFGM64Da4i72...`

*   **DID Document (DID-Dokument):**
    Ein JSON-LD-Dokument, das mit einer DID verknüpft ist. Es enthält die öffentlichen kryptografischen Schlüssel (Verification Methods) und Service-Endpunkte (URLs), die notwendig sind, um mit dem Agenten zu interagieren. Im OAP-Ökosystem ist das DID Document die "Source of Truth" für die Erreichbarkeit eines Agenten.

*   **DID Method (DID-Methode):**
    Das spezifische Regelwerk, wie eine DID erstellt, aufgelöst und aktualisiert wird. OAEP schreibt die Unterstützung spezifischer Methoden vor (siehe Section 3.3), primär `did:key` (für ephemere/lokale Identitäten) und `did:web` (für domain-gebundene, institutionelle Identitäten).

### 2.3 Vertrauens-Artefakte (Credentials)

Identität allein schafft noch kein Vertrauen. OAEP nutzt signierte Datenstrukturen, um Eigenschaften beweisbar zu machen.

*   **Verifiable Credential (VC):**
    Ein manipulationssicherer digitaler Nachweis. Ein VC enthält Aussagen über ein Subjekt (den Principal), Metadaten (Aussteller, Gültigkeitsdauer) und eine kryptografische Signatur des Ausstellers.
    *   *OAP-Kontext:* Das wichtigste VC in OAEP ist das **AgentProfile**, welches Basisdaten wie Anzeigename und Avatar mit der DID verknüpft.

*   **Verifiable Presentation (VP):**
    Ein Datenpaket, das ein Agent an einen Verifier sendet. Es kann ein oder mehrere VCs enthalten. Crucial ist hierbei, dass der Agent ("Holder") die Präsentation selbst signiert, um zu beweisen, dass die VCs tatsächlich ihm gehören (Proof of Possession).

*   **Zero-Knowledge Proof (ZKP):**
    Ein kryptografisches Verfahren, das es einem Agenten erlaubt, eine Eigenschaft eines VCs zu beweisen, ohne die Daten selbst offenzulegen.
    *   *Beispiel:* Beweis "Alter > 18", ohne das Geburtsdatum zu übermitteln.

### 2.4 Kryptografische Infrastruktur

Die Sicherheit von OAEP basiert auf asymmetrischer Kryptografie und lokaler Schlüsselverwaltung.

*   **Wallet (Keystore/Tresor):**
    Die Software- oder Hardware-Komponente, die private Schlüssel speichert. Im OAP-Standard MUSS die Wallet so konzipiert sein, dass private Schlüssel niemals unverschlüsselt den Speicherbereich des Geräts verlassen. Bevorzugt werden Hardware-gestützte Umgebungen (Secure Enclave, TEE).

*   **Key Rotation (Schlüssel-Rotation):**
    Der Prozess des Austauschs von kryptografischen Schlüsseln zu einer bestehenden Identität. OAEP unterstützt Rotation, um die Sicherheit bei langlebigen Identitäten (z.B. Unternehmen) zu gewährleisten, ohne dass sich der Identifikator (die DID) ändert (sofern die DID-Methode dies unterstützt).

*   **Handshake (Verbindungsaufbau):**
    Die in diesem RFC definierte Sequenz von Nachrichten, bei der zwei Agenten ihre Identitäten austauschen, gegenseitig authentifizieren und einen gemeinsamen Sitzungsschlüssel aushandeln.

*   **Session Keys (Sitzungsschlüssel):**
    Temporäre, symmetrische Schlüssel, die während des Handshakes generiert werden (z.B. via Diffie-Hellman Key Exchange). Sie werden genutzt, um den nachfolgenden Datentransport (via OAMP) effizient zu verschlüsseln. Sie bieten *Perfect Forward Secrecy* (PFS).

### 2.5 Protokoll-Semantik

*   **Capability (Fähigkeit):**
    Eine definierte Funktion oder ein unterstütztes Protokoll höherer Ordnung (Schicht 1), das ein Agent beherrscht. Capabilities werden im Handshake durch standardisierte URIs signalisiert (z.B. `https://oap.dev/protocols/commerce/v1`).

*   **Manifest (Manifest):**
    Eine öffentliche, signierte Liste von Capabilities und Metadaten, die ein Agent vor dem eigentlichen Handshake bereitstellen kann, um Discovery zu ermöglichen.

---

**Section 3: Data Model**

## 3. Datenmodell (Data Model)

OAEP erzwingt strikte Semantik mittels **JSON-LD**.

**Kryptografische Integrität & Kanonisierung (OAEP Signature Profile):**
1.  **Struktur:** Das zu signierende Objekt MUSS ein valides JSON-LD-Dokument in **kompaktierter Form** sein.
2.  **Ausschluss:** Das `proof`-Attribut wird vor der Verarbeitung entfernt.
3.  **Kanonisierung:** Das Objekt MUSS gemäß **RFC 8785 (JSON Canonicalization Scheme - JCS)** normalisiert werden.

### 3.1 Das Agent Profile (Agenten-Profil)

Das zentrale Datenobjekt im OAEP-Handshake ist das **AgentProfile**. Es dient als digitale Visitenkarte und Repräsentation des Agenten gegenüber Dritten.

Um Fälschungen (Spoofing) zu verhindern, DARF das AgentProfile NICHT als einfaches JSON-Objekt übertragen werden. Es MUSS zwingend als **W3C Verifiable Credential (VC)** strukturiert sein. Dies garantiert durch die kryptografische Signatur im `proof`-Feld, dass die Daten vom rechtmäßigen Inhaber der Identität stammen (im Falle eines Self-Signed Credentials) oder von einer vertrauenswürdigen Stelle validiert wurden.

#### 3.1.1 Struktur des AgentProfile
Ein valides AgentProfile-Credential MUSS folgende Eigenschaften enthalten:

*   **@context:** Verweis auf die verwendeten JSON-LD Kontexte (W3C v1 und OAEP v1).
*   **type:** Muss `["VerifiableCredential", "AgentProfile"]` enthalten.
*   **issuer:** Die DID des Ausstellers (meist identisch mit dem Subject bei Self-Sovereign Profiles).
*   **issuanceDate:** Zeitstempel der Erstellung im strikten **RFC 3339** Format (z.B. `2026-03-15T10:00:00Z`).
*   **credentialSubject:** Der eigentliche Inhalt des Profils.
    *   `id`: Die DID des Agenten.
    *   `name`: (Optional) Anzeigename des Agenten.
    *   `description`: (Optional) Kurzbeschreibung.
    *   `avatar`: (Optional) URI zu einem Profilbild oder Hash eines Bildes.
*   **proof:** Die kryptografische Signatur.

#### 3.1.2 Beispiel: Self-Signed AgentProfile (JSON-LD)

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
    "name": "Lenas Personal AI",
    "description": "Bevollmächtigter Einkaufs- und Planungsagent.",
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

### 3.2 Capability Manifesto (Fähigkeiten-Manifest)

Da OAEP modular aufgebaut ist, müssen Agenten vor dem Beginn einer Interaktion aushandeln, welche Anwendungsprotokolle (Schicht 1) sie unterstützen. Diese Aushandlung erfolgt über das **Capability Manifesto**.

Das Manifesto ist eine Liste von unterstützten Protokoll-URIs und Versionen. Es SOLLTE als Teil des `credentialSubject` im AgentProfile eingebettet werden, um Round-Trips zu sparen, KANN aber auch als separates Credential nachgeladen werden.

#### 3.2.1 Datenstruktur
Das Feld `capabilities` ist ein Array von Objekten mit folgenden Feldern:
*   `protocol`: Die eindeutige URI des Standards (z.B. OACP).
*   `version`: Semver-kompatible Version (z.B. "1.0.0").
*   `role`: (Optional) Die Rolle des Agenten in diesem Protokoll (z.B. "Merchant" oder "Buyer").

#### 3.2.2 Beispiel-Auszug (innerhalb credentialSubject)

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

### 3.3 Unterstützte DID-Methoden

Um Fragmentierung zu vermeiden, schreibt OAEP v1.0 die Unterstützung ("MUST implement") von zwei spezifischen DID-Methoden vor. Ein OAEP-konformer Agent MUSS in der Lage sein, diese Identifikatoren aufzulösen und zu verifizieren.

#### 3.3.1 did:key (Für P2P & Ephemeres)
*   **Zweck:** Ad-hoc Interaktionen, private Chats.
*   **Mechanismus:** Der öffentliche Schlüssel ist direkt im DID-String kodiert. Es ist keine Auflösung über einen Server oder eine Blockchain notwendig ("self-certifying").
*   **Schlüssel-Spezifikation:** OAEP v1.0 schreibt **Ed25519** (Multicodec `0xed`) für Signaturen vor.
*   **Verschlüsselung:** Für die Verschlüsselung (Key Agreement) MÜSSEN im Handshake separate, ephemere **X25519**-Schlüssel generiert werden (Perfect Forward Secrecy).
*   **Vorteil:** Funktioniert offline, extrem schnell, maximale Privatsphäre (Einweg-Identitäten möglich).
*   **Nachteil:** Keine Schlüssel-Rotation möglich (bei Kompromittierung muss die Identität aufgegeben werden).

#### 3.3.2 did:web (Für Institutionen & Vertrauen)
*   **Zweck:** Unternehmen, Shops, Behörden, öffentliche Personen.
*   **Mechanismus:** Die DID ist an eine DNS-Domain gebunden (z.B. `did:web:think.systems`). Das DID-Dokument wird unter einer bekannten URL (`/.well-known/did.json`) gehostet.
*   **Vorteil:** Nutzt das bestehende Vertrauen in das DNS-System (SSL-Zertifikate). Nutzer können intuitiv prüfen: "Spreche ich wirklich mit zalando.de?". Ermöglicht Schlüssel-Rotation.
*   **Nachteil:** Abhängig von DNS und Webserver-Verfügbarkeit.

#### 3.3.3 Zukünftige Methoden (Optional / Draft)
OAEP ist so designed, dass weitere Methoden hinzugefügt werden können (z.B. `did:dht` oder `did:ion` für dezentrale Persistenz ohne DNS). In Version 1.0 sind diese jedoch optional, um die Komplexität der Client-Implementierung gering zu halten.

### 3.4 Service Endpoints (Erreichbarkeit)

Jedes aufgelöste DID Document eines Agenten MUSS mindestens einen Service Endpoint vom Typ `OAPEndpoint` enthalten. Dieser definiert die technische Adresse für den Nachrichtentransport (Layer 0).

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
Dies ermöglicht das Routing von Nachrichten, selbst wenn der Agent (z.B. ein Smartphone) hinter einer Firewall sitzt oder offline ist (Store-and-Forward via Relay).

---

**Section 4: The Discovery Process**

## 4. Der Discovery-Prozess (Auffindbarkeit)

In einem dezentralen Ökosystem existiert kein zentrales Verzeichnis (Directory Service), das alle Teilnehmer und ihre Adressen auflistet. OAEP definiert daher Mechanismen, wie Agenten ihre Kommunikationspartner entdecken und die notwendigen technischen Informationen für den Verbindungsaufbau abrufen können.

Der Discovery-Prozess ist in drei Szenarien unterteilt:
1.  **Explizite Einladung:** Direkter Austausch von Identifikatoren (Out-of-Band).
2.  **Implizite Discovery:** Das Finden von Kontakten basierend auf bekannten Attributen (z.B. Telefonnummern) unter strikter Wahrung der Privatsphäre.
3.  **Auflösung (Resolution):** Der technische Schritt von der abstrakten ID (DID) zu den konkreten Verbindungsparametern.

### 4.1 Out-of-Band Discovery (Explizite Einladung)

Dieses Verfahren wird genutzt, wenn eine Interaktion durch einen externen Kanal (physisches Treffen, E-Mail, Webseite) initiiert wird. Um die Interoperabilität zwischen verschiedenen OAP-kompatiblen Wallets und Agenten zu gewährleisten, definiert OAEP ein standardisiertes URI-Schema.

#### 4.1.1 Das `oap` URI-Schema
Agenten MÜSSEN URIs verarbeiten können, die dem folgenden Schema entsprechen:

`oap:connect?did=<did>&label=<optional_name>`

*   **oap:** Das Protokoll-Präfix.
*   **connect:** Die Aktion (hier: Verbindungsaufbau anfordern).
*   **did:** Der vollständige Decentralized Identifier des Ziel-Agenten.
*   **label:** (Optional) Ein URL-encodierter, menschenlesbarer Name (z.B. "Th!nk%20Store"), der dem Nutzer vor dem Handshake angezeigt wird.

#### 4.1.2 QR-Codes
Für physische Interaktionen (z.B. an einer Ladenkasse oder beim Austausch von Kontakten zwischen zwei Smartphones) MUSS der URI in einem QR-Code (Quick Response Code) kodiert werden.
*   **Fehlerkorrektur:** Level M oder höher SOLLTE verwendet werden.
*   **Format:** Alphanumerischer Modus.

### 4.2 Privacy-Preserving Contact Discovery (PSI)

Eines der größten Datenschutzprobleme klassischer Messenger ist das Hochladen des gesamten Adressbuchs im Klartext auf zentrale Server ("Contact Upload"). OAEP lehnt dieses Vorgehen ab. Um dennoch Nutzer zu finden, deren Telefonnummer oder E-Mail-Adresse einem Agenten bekannt ist, verwendet OAEP das Verfahren der **Private Set Intersection (PSI)**.

Dieser Mechanismus ermöglicht es einem Agenten (Client) und einem Discovery-Server zu ermitteln, welche Kontakte sie gemeinsam haben (Schnittmenge), ohne dass der Server die Eingabedaten des Clients erfährt und ohne dass der Client die gesamte Datenbank des Servers herunterladen muss.

OAEP standardisiert PSI basierend auf **Ristretto255** und OPRF.

#### 4.2.1 Das Protokoll (OPRF-basiertes PSI)

OAEP standardisiert ein PSI-Verfahren basierend auf einer *Oblivious Pseudo-Random Function (OPRF)*. Um Interoperabilität zu gewährleisten und kryptografische Angriffe durch Untergruppen (Subgroups) zu verhindern, MUSS die **Ristretto255**-Gruppe für alle OPRF-Operationen verwendet werden.

Als Pseudo-Random Function (PRF) zur Finalisierung der Ausgabe wird **HMAC-SHA256** festgelegt.

**Ablauf:**

1.  **Vorbereitung (Client):** Client blindet Inputs ($B = P_x \cdot r$).

2.  **Anfrage (Client -> Server):**
    *   Der Agent sendet die verblindeten Elemente ($B$).
    *   **Normative Batch-Größe:** Die maximale Anzahl an Elementen pro Anfrage (`MAX_BATCH_SIZE`) ist fixiert auf **1000 Elemente**. Clients MÜSSEN größere Mengen in sequentielle Requests aufteilen.

3.  **Auswertung (Server):**
    *   **DoS-Schutz:** Der Server MUSS Requests, die `MAX_BATCH_SIZE` überschreiten, mit `ERR_RATE_LIMIT` ablehnen.
    *   Der Server MUSS ein Rate-Limiting basierend auf dem **Token Bucket Algorithmus** implementieren (siehe Abschnitt 8.3.3).

4.  **Unblinding (Client):**
    *   Der Agent entfernt seinen zufälligen Faktor $r$ durch Multiplikation mit dem Inversen ($r^{-1}$): $U = E \cdot r^{-1} = (P_x \cdot r \cdot k) \cdot r^{-1} = P_x \cdot k$.
    *   Das Ergebnis $U$ ist nun das OPRF-Ergebnis, das nur vom Input $x$ und dem Server-Schlüssel $k$ abhängt.

5.  **Vergleich (Lokal):**
    *   Um die finale Schnittmenge zu bilden, berechnet der Client den Hash des entblindeten Elements: $H_{final} = \text{HMAC-SHA256}(key=\text{"OAEP-PSI-v1"}, data=U)$.
    *   Dieser Wert wird mit der Liste von Hash-Werten verglichen, die der Server für alle registrierten Nutzer bereitstellt (z.B. als Bloom-Filter oder Golomb-Compressed Set, um Bandbreite zu sparen).

6.  **Match:** Bei einer Übereinstimmung hat der Agent einen OAP-Nutzer gefunden und kann die zugehörige DID auflösen.

### 4.3 DID Resolution (Auflösung)

Sobald einem Agenten eine DID bekannt ist (durch 4.1 oder 4.2), muss er diese in ein **DID Document** auflösen, um den Handshake zu beginnen. Der Resolver ist eine Komponente im OAP-SDK, die je nach DID-Methode unterschiedliche Strategien verfolgt.

#### 4.3.1 Auflösung von `did:key`
Bei dieser Methode ist für den **Auflösungsschritt** kein Netzwerkzugriff erforderlich (Offline-Resolution).
1.  Der Resolver extrahiert den Multicodec-Wert und expandiert ihn zum DID Document.
2.  **In-Band Transport Regel:** Da `did:key`-Dokumente oft keinen `service`-Eintrag enthalten, MUSS der Agent in diesem Fall annehmen, dass der Transportkanal bereits "In-Band" existiert (z.B. Antwort über denselben WebSocket/TCP-Socket, über den die Anfrage kam). Ein Abbruch mit `ERR_DID_RESOLUTION` ist in diesem Fall VERBOTEN.

#### 4.3.2 Auflösung von `did:web`
Hierbei fungiert das Domain Name System (DNS) als Vertrauensanker.
1.  Der Resolver parst die DID: `did:web:example.com:user:alice` wird zur URL `https://example.com/user/alice/.well-known/did.json`.
2.  Der Agent führt einen HTTPS GET Request durch.
3.  **Sicherheitsprüfung:** Die Verbindung MUSS über TLS (HTTPS) gesichert sein. Das Zertifikat der Domain MUSS valide sein.
4.  Das zurückgegebene JSON-Dokument wird geparst. Der Agent extrahiert:
    *   `verificationMethod`: Die öffentlichen Schlüssel des Gegenübers.
    *   `service`: Die URL des OAMP-Relays (Inbox), an die die erste Handshake-Nachricht ("Hello") gesendet werden muss.

#### 4.3.3 Caching-Richtlinien
Um die Privatsphäre zu schützen und Netzwerklast zu reduzieren, SOLLTEN aufgelöste DID Documents lokal gecached werden. Die Gültigkeitsdauer des Caches richtet sich nach den HTTP-Cache-Headern (bei `did:web`) oder ist unbegrenzt (bei `did:key`, da unveränderlich). Vor kritischen Transaktionen (z.B. Zahlungen via OAPP) MUSS jedoch eine erneute Live-Auflösung erfolgen, um sicherzustellen, dass Schlüssel nicht rotiert oder widerrufen wurden.

---

**Section 5: The Handshake Protocol**

## 5. Das Handshake-Protokoll (Verbindungsaufbau)

Nachdem ein Agent die DID seines Gegenübers aufgelöst hat (siehe Section 4), initiiert er das Handshake-Protokoll. Ziel dieses Prozesses ist die Etablierung einer **gegenseitig authentifizierten, verschlüsselten Sitzung**.

Der OAEP-Handshake ist zustandsbehaftet (stateful). Er stellt sicher, dass:
1.  Beide Parteien die Kontrolle über die privaten Schlüssel ihrer jeweiligen DIDs besitzen (**Authentication**).
2.  Beide Parteien sich auf eine gemeinsame Menge an Anwendungsprotokollen einigen (**Negotiation**).
3.  Ein Satz frischer, symmetrischer Schlüssel für die nachfolgende Kommunikation generiert wird (**Session Establishment**).

### 5.1 State Machine (Zustandsautomat)

Der OAEP-Handshake ist ein zustandsbehafteter Prozess. Um Protokoll-Konfusionen und Angriffe (z.B. State Exhaustion) zu verhindern, MÜSSEN Implementierungen den Status einer Verbindung strikt anhand der folgenden Zustandsmaschine verwalten.

Der Lebenszyklus einer Sitzung wird durch fünf Hauptzustände definiert:

1.  **`IDLE`**: Der Ausgangszustand. Kein Kontext vorhanden.
2.  **`AWAIT_RESPONSE`** (Nur Initiator): `ConnectionRequest` wurde gesendet; Warten auf Antwort.
3.  **`AWAIT_ACK`** (Nur Responder): `ConnectionResponse` wurde gesendet; Warten auf Finalisierung.
4.  **`ACTIVE`**: Der Handshake war erfolgreich. Sitzungsschlüssel sind abgeleitet. OAMP-Nachrichten können ausgetauscht werden.
5.  **`FAILED`**: Ein Fehler ist aufgetreten. Temporärer Zustand zur Fehlerbehandlung/Cleanup.

#### 5.1.1 Übergangsmatrix (Transition Matrix)

Die folgende Tabelle definiert die **einzig zulässigen Übergänge**. Jede Nachricht, die in einem Zustand empfangen wird, für den kein Übergang definiert ist, MUSS ignoriert oder als Fehler behandelt werden.

| Rolle | Aktueller Status | Ereignis / Eingehende Nachricht | Aktion / Überprüfung | Neuer Status |
| :--- | :--- | :--- | :--- | :--- |
| **Initiator** | `IDLE` | *Start Handshake* | Sende `ConnectionRequest` (Speichere `EphemeralKey_A` & `Nonce_A`). Starte Timer. | `AWAIT_RESPONSE` |
| **Responder** | `IDLE` | Empfang `ConnectionRequest` | Validiere Schema & Zeitstempel. Generiere `EphemeralKey_B` & `Nonce_B`. Signiere Transkript. Sende `ConnectionResponse`. Starte Timer. | `AWAIT_ACK` |
| **Initiator** | `AWAIT_RESPONSE` | Empfang `ConnectionResponse` | 1. Prüfe Signatur über Transkript.<br>2. Verifiziere `negotiatedSuite`.<br>3. Leite Session Keys ab.<br>4. Sende `ConnectionAcknowledge`. | `ACTIVE` |
| **Responder** | `AWAIT_ACK` | Empfang `ConnectionAcknowledge` | 1. Prüfe Signatur über Transkript.<br>2. Leite Session Keys ab. | `ACTIVE` |
| **Beide** | `ACTIVE` | Empfang `OAMP Message` | Entschlüsseln und Verarbeiten der Nutzdaten. | `ACTIVE` |
| **Beide** | *Alle* | Empfang `OAEPError` | Loggen des Fehlers. Löschen aller Ephemeral Keys. | `FAILED` -> `IDLE` |
| **Beide** | *Alle außer IDLE* | **Timeout** (Default: 30s) | Löschen aller Ephemeral Keys. | `FAILED` -> `IDLE` |

#### 5.1.2 Fehlerbehandlung & Timeouts

Um Ressourcenerschöpfung (DoS) zu verhindern, gelten folgende normative Regeln für Zustandsübergänge im Fehlerfall:

1.  **Unexpected Message:** Trifft eine Nachricht ein, die im aktuellen Zustand nicht erwartet wird (z.B. `ConnectionAcknowledge` im Status `IDLE`), MUSS der Agent diese Nachricht **stillschweigend verwerfen (Silent Drop)**. Er darf KEINEN `OAEPError` senden, um "Reflection Attacks" zu verhindern.
2.  **Invalid Signature:** Schlägt die kryptografische Prüfung in `AWAIT_RESPONSE` oder `AWAIT_ACK` fehl, MUSS der Agent mit einem `OAEPError` (Code: `ERR_AUTH_SIG_INVALID`) antworten und sofort in den Status `FAILED` wechseln.
3.  **Timeout:** Läuft der Timer ab, bevor der nächste erwartete Zustand erreicht ist, MUSS der Handshake abgebrochen werden. Alle temporären Schlüssel (`EphemeralKey`) und Nonces MÜSSEN sofort sicher aus dem Speicher gelöscht werden. Es erfolgt kein Retry auf Protokollebene (dies obliegt der Applikation).

### 5.2 Der Protokoll-Ablauf (Sequence)

Der Standard-Handshake besteht aus drei Nachrichten (3-Way-Handshake), analog zu TCP, jedoch auf der Anwendungsschicht.

Um **Man-in-the-Middle-Angriffe** und **Unknown Key-Share Attacks** mathematisch auszuschließen, DÜRFEN Signaturen NICHT über einzelne Werte (wie nur die Nonce) gebildet werden. Stattdessen MUSS jede Signatur über ein deterministisches **Handshake-Transkript** erfolgen, das alle sicherheitskritischen Parameter beider Parteien bindet.

#### 5.2.1 Definition des Handshake-Transkripts

Das Transkript ist ein JSON-Objekt, das den ausgehandelten Zustand der Sitzung repräsentiert. Vor dem Hashing oder Signieren MUSS dieses Objekt gemäß **RFC 8785 (JCS)** normalisiert werden.

Das Transkript-Objekt `T` hat folgende Struktur:

```json
{
  "header": {
    "suite": "OAEP-v1-2026",       // Die ausgehandelte Cipher Suite
    "created": "2026-..."          // Zeitstempel des Requests
  },
  "initiator": {
    "did": "did:key:alice...",     // DID von Agent A
    "nonce": "...",                // Nonce von Agent A
    "ephemeralKey": "..."          // Public Key für ECDH von A
  },
  "responder": {
    "did": "did:web:bob...",       // DID von Agent B
    "nonce": "...",                // Nonce von Agent B
    "ephemeralKey": "..."          // Public Key für ECDH von B
  }
}
```

Der **Transkript-Hash** $H_T$ wird berechnet als:
$$H_T = \text{HashFunction}_{\text{Suite}}(\text{JCS}(T))$$

#### 5.2.2 Der Ablauf

**Phase 1: Connection Request (SYN)**
Der Initiator (Agent A) sendet den `ConnectionRequest`.
*   **Aktion:** Generierung von `Nonce_A` und `EphemeralKey_A`.
*   **Inhalt:** DID A, Zeitstempel, `Nonce_A`, `EphemeralKey_A`, Liste der `supportedSuites`.
*   *Hinweis:* Noch keine Signatur, da die Parameter von B noch unbekannt sind.

**Phase 2: Connection Response (SYN-ACK)**
Der Empfänger (Agent B) wählt eine Suite, generiert `Nonce_B` und `EphemeralKey_B`.
*   **Transkript-Bildung:** Agent B konstruiert lokal das Transkript-Objekt `T` aus den Werten von A und seinen eigenen Werten.
*   **Signatur (Authentication & Binding):** Agent B berechnet $H_T$ und signiert diesen Hash mit seinem *langfristigen* privaten Identitätsschlüssel:
    $$\text{Sig}_B = \text{Sign}(\text{PrivKey}_B, H_T)$$
*   **Inhalt:** DID B, `Nonce_B`, `EphemeralKey_B`, `negotiatedSuite`, und die `Sig}_B` (im Feld `proof`).

**Phase 3: Connection Acknowledge (ACK)**
Der Initiator (Agent A) empfängt die Antwort.
*   **Validierung:** Agent A konstruiert ebenfalls lokal das Transkript `T` und berechnet $H_T$. Er verifiziert `Sig_B` gegen diesen Hash. Schlägt dies fehl, bricht der Handshake ab.
*   **Signatur (Mutual Authentication):** Um den Kanal zu bestätigen, signiert Agent A nun denselben Hash $H_T$ mit seinem *langfristigen* privaten Schlüssel:
    $$\text{Sig}_A = \text{Sign}(\text{PrivKey}_A, H_T)$$
*   **Inhalt:** Die `Sig_A` (im Feld `proof`) und das finale `CapabilityManifest`.

**Ergebnis:**
Sobald B die Nachricht empfängt und `Sig_A` gegen das Transkript prüft, ist die Sitzung etabliert. Beide Parteien haben bewiesen, dass sie (1) ihre DIDs kontrollieren und (2) dieselben Ephemeral Keys für die Verschlüsselung sehen.

*Wichtig: Signaturen erfolgen zwingend über den Hash des JCS-normalisierten Transkripts aller Parameter.*

### 5.3 Nachrichtenformate (JSON-LD)

Alle Handshake-Nachrichten MÜSSEN dem folgenden Schema folgen. Alle Zeitstempel MÜSSEN dem Format **RFC 3339** entsprechen.

#### 5.3.1 ConnectionRequest (Beispiel)

Der Initiator schlägt eine Liste von Cipher Suites vor (`supportedSuites`), die er beherrscht.

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
    // Optional: Eingebettetes AgentProfile VC (noch unverschlüsselt!)
    "profile": { ... } 
  }
}
```

#### 5.3.2 ConnectionResponse (Beispiel)

Der Responder wählt eine Suite (`negotiatedSuite`) und signiert das Transkript. Das Feld im `proof` heißt nun explizit `transcriptHash`, um klarzustellen, dass nicht nur eine Nonce signiert wurde.

```json
{
  "@context": ["https://w3id.org/oaep/v1"],
  "type": "ConnectionResponse",
  "replyTo": "urn:uuid:a1b2c3d4-...", // ID des Requests
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
    // WARNUNG: Dieses Feld repräsentiert den Hash des gesamten 
    // Handshake-Transkripts (siehe 5.2.1), nicht nur eine Nonce.
    "transcriptHash": "SHA256_HASH_OF_JCS_NORMALIZED_TRANSCRIPT", 
    "jws": "eyJhbGciOiJFZ..."
  }
}
```

#### 5.3.3 ConnectionAcknowledge (Beispiel)

Der Initiator bestätigt die Sitzung. Auch hier wird der `transcriptHash` signiert.

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
  // Ab hier können verschlüsselte Capabilities folgen
  "body": { 
    "capabilities": [...] 
  }
}
```

### 5.4 Capability Negotiation (Aushandlung)

Im Rahmen der `ConnectionRequest` (oder spätestens im `ConnectionAcknowledge`) tauschen die Agenten ihre unterstützten Protokolle aus (siehe Section 3.2).

**Logik der Schnittmenge:**
1.  Agent A sendet Liste `[OACP v1.0, OAPP v2.0, SFP v1.0]`.
2.  Agent B unterstützt `[OACP v1.0, OAPP v1.0]`.
3.  **Ergebnis:** Die Session wird für **OACP v1.0** aktiviert. Für OAPP wird (falls möglich) auf den kleinsten gemeinsamen Nenner (v1.0) zurückgefallen. SFP wird deaktiviert, da B es nicht unterstützt.

Wenn die Schnittmenge der essenziellen Protokolle leer ist, MUSS der Handshake mit einem Fehler `ERR_NO_COMMON_PROTOCOL` abgebrochen werden.

### 5.5 Session Establishment (Schlüsselableitung)

OAEP implementiert **Perfect Forward Secrecy (PFS)**. Das bedeutet, dass selbst wenn der langfristige Identitätsschlüssel (aus der DID) in Zukunft kompromittiert wird, aufgezeichnete vergangene Sitzungen nicht entschlüsselt werden können.

Nach erfolgreichem Abschluss von Phase 2 und 3 verfügen beide Parteien über die notwendigen Geheimnisse, um den symmetrischen Nachrichtenkanal (OAMP) zu initialisieren.

#### 5.5.1 The Key Schedule (HKDF)

Input Key Material via ECDH der ephemeren Schlüssel. Salt ist der Transkript-Hash.

Zur Ableitung der Sitzungsschlüssel MUSS die **HKDF** (HMAC-based Extract-and-Expand Key Derivation Function) gemäß **RFC 5869** verwendet werden. Der zugrundeliegende Hash-Algorithmus wird durch die Cipher Suite bestimmt (für `OAEP-v1-2026` ist dies `BLAKE3` oder `SHA-256`).

Die Eingabeparameter für HKDF sind normativ wie folgt definiert:

1.  **Input Key Material (IKM):**
    Das Ergebnis des Diffie-Hellman-Austauschs (ECDH) zwischen den ephemeren Schlüsseln.
    $$IKM = \text{ECDH}(\text{PrivKey}_{\text{Ephemeral\_Local}}, \text{PubKey}_{\text{Ephemeral\_Remote}})$$

2.  **Salt:**
    Um die Sitzungsschlüssel kryptografisch an die Identitäten und den Handshake-Verlauf zu binden, MUSS der **Transkript-Hash** ($H_T$, siehe 5.2.1) als Salt verwendet werden.
    $$\text{Salt} = H_T$$

3.  **Info (Context Information):**
    Ein fester String zur Domain-Separation, der die Protokollversion enthält.
    $$\text{Info} = \text{"OAEP-v1-Session-Keys"}$$

#### 5.5.2 Ableitung der Symmetrischen Schlüssel

Der Output der HKDF-Expand-Funktion (Länge: 64 Bytes) wird in zwei 32-Byte-Schlüssel aufgeteilt:

```text
Output_Keying_Material = HKDF-Expand(PRK, Info, L=64)

Split:
1. Client_Write_Key (Bytes 0-31): Schlüssel für Nachrichten vom Initiator zum Responder.
2. Server_Write_Key (Bytes 32-63): Schlüssel für Nachrichten vom Responder zum Initiator.
```

*   **Initiator (Alice):** Nutzt `Client_Write_Key` zum Verschlüsseln und `Server_Write_Key` zum Entschlüsseln.
*   **Responder (Bob):** Nutzt `Server_Write_Key` zum Verschlüsseln und `Client_Write_Key` zum Entschlüsseln.

**Sicherheits-Vorschrift:** Unmittelbar nach der Ableitung dieser Schlüssel MÜSSEN die privaten Ephemeral Keys (`EphemeralKey_A`, `EphemeralKey_B`) und das ECDH-Resultat (`IKM`) sicher aus dem Arbeitsspeicher gelöscht (überschrieben/zeroized) werden.

#### 5.5.3 AEAD Nonce Management (ChaCha20-Poly1305)

Für die symmetrische Verschlüsselung der Nutzdaten (Payload) wird **ChaCha20-Poly1305** verwendet. Dieser Algorithmus benötigt für jede Nachricht eine einzigartige **Nonce** (96 Bit / 12 Bytes).

**Warnung:** Die Wiederverwendung einer Nonce mit demselben Schlüssel ("Nonce Reuse") führt zum Totalverlust der Vertraulichkeit.

OAEP schreibt folgendes Nonce-Schema vor:

*   **Implizite Sequenznummern:**
    Jeder Agent führt zwei interne 64-Bit-Zähler (Unsigned Integer):
    1.  `send_counter`: Initialisiert mit `0`. Wird nach jedem Senden inkrementiert.
    2.  `recv_counter`: Initialisiert mit `0`. Wird nach jedem erfolgreichen Entschlüsseln inkrementiert.

*   **Konstruktion der Nonce (12 Bytes):**
    Die 96-Bit Nonce wird konstruiert durch das **Auffüllen (Padding)** des 64-Bit Zählers mit Nullen (Big Endian oder Little Endian gemäß Suite-Spezifikation, Standard: Little Endian für ChaCha20).
    `Nonce = [0x00, 0x00, 0x00, 0x00] || [64-bit Counter]`

*   **Regeln:**
    1.  Nonces werden **nicht** über das Netzwerk übertragen.
    2.  **Sliding Window (Pflicht):** Aufgrund der asynchronen Natur von OAMP (UDP-ähnlich oder Relay-basiert) MÜSSEN Empfänger ein Sliding Window (empfohlene Fenstergröße $\ge 64$) für den `recv_counter` implementieren. Nachrichten, die innerhalb des Fensters eintreffen, aber "out-of-order" sind, MÜSSEN akzeptiert werden. Nachrichten, die links aus dem Fenster fallen (zu alt), MÜSSEN als Replay verworfen werden.
    3.  Bei Counter-Überlauf MUSS ein Re-Keying erfolgen.

### 5.6 Security Considerations für den Handshake

Der Handshake ist der kritischste Moment der Kommunikation. Da noch kein verschlüsselter Kanal existiert, ist er anfällig für Replay- und Timing-Angriffe. Implementierungen MÜSSEN folgende Sicherheitsmechanismen erzwingen.

#### 5.6.1 Replay Protection (Schutz vor Wiederholung)

Ein Angreifer könnte versuchen, eine valide `ConnectionRequest` abzufangen und später erneut zu senden, um eine Sitzung zu erzwingen oder den Server zu überlasten.

*   **Nonce-Cache:** Jeder Empfänger MUSS einen Cache (z.B. Redis, In-Memory Set) aller gesehenen Nonces pflegen.
*   **Prüfung:** Tritt eine Nonce in einer eingehenden Nachricht auf, die bereits im Cache existiert, MUSS die Nachricht sofort verworfen werden.
*   **Lebensdauer:** Der Cache MUSS Nonces mindestens so lange speichern, wie das Zeitfenster für gültige Zeitstempel (siehe 5.6.2) geöffnet ist (d.h. > 300 Sekunden).

#### 5.6.2 Zeitfenster & Clock Drift (Uhren-Synchronisation)

Alle Handshake-Nachrichten MÜSSEN einen `created`-Zeitstempel im Format **RFC 3339** enthalten. Da Uhren in verteilten Systemen nie perfekt synchron laufen, definiert OAEP ein Toleranzfenster ("Window of Acceptance").

Der Empfänger vergleicht den Zeitstempel $T_{msg}$ der Nachricht mit seiner lokalen Systemzeit $T_{now}$.

1.  **Veraltete Nachrichten (Past Tolerance):**
    Ist $T_{msg} < T_{now} - 300\text{s}$ (älter als 5 Minuten), MUSS die Nachricht verworfen werden (`ERR_MSG_EXPIRED`). Dies begrenzt die Notwendigkeit, Nonces ewig zu speichern.
2.  **Nachrichten aus der Zukunft (Future Tolerance):**
    Ist $T_{msg} > T_{now} + 10\text{s}$ (mehr als 10 Sekunden in der Zukunft), MUSS die Nachricht verworfen werden (`ERR_MSG_FUTURE`).
    *   *Begründung:* Dies verhindert Angriffe, bei denen ein Angreifer Nachrichten mit zukünftigen Zeitstempeln generiert, um sie später zu nutzen, wenn der Nonce-Cache bereinigt wurde. Die 10 Sekunden Toleranz dienen dem Ausgleich von leichtem Clock Drift.

**Sonderfall: IoT-Geräte ohne RTC (Real Time Clock)**
Für Geräte, die keine verlässliche Systemzeit haben (z.B. einfache Sensoren nach einem Neustart):
*   Diese Geräte DÜRFEN die Zeitprüfung im Handshake aussetzen ("Relaxed Mode").
*   Stattdessen MÜSSEN sie sich strikt auf die **kryptografische Challenge-Response** verlassen. Das Gerät sendet eine eigene Zufalls-Nonce und akzeptiert die Verbindung nur, wenn diese frisch signiert zurückkommt.
*   Sobald eine vertrauenswürdige Verbindung steht, SOLLTE das Gerät seine Zeit über das Netzwerk synchronisieren (z.B. via OAMP Time Sync).

#### 5.6.3 TOFU (Trust On First Use) bei `did:key`

Bei der Verwendung von `did:key` existiert kein externer Vertrauensanker (wie DNS bei `did:web`).

*   **Erste Verbindung:** Der Initiator muss darauf vertrauen, dass der im QR-Code oder Link enthaltene Public Key tatsächlich dem gewünschten Partner gehört.
*   **Persistenz:** Nach dem ersten erfolgreichen Handshake MUSS der Agent die Verknüpfung "Name <-> DID/Key" lokal speichern ("Pinning").
*   **Warnung:** Ändert sich der Schlüssel für einen bekannten Kontakt (z.B. neue DID bei Gerätewechsel), MUSS die Software den Nutzer explizit warnen und eine erneute manuelle Verifizierung (z.B. QR-Scan) fordern. Automatisches "Re-Trusting" ist VERBOTEN.

*   **Technisches Pinning-Format:** Um Client-Interoperabilität zu gewährleisten, MÜSSEN gepinnte Identitäten in folgendem JSON-Schema gespeichert werden:
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
*   Eine Abweichung vom `pinnedKey` MUSS als fataler Sicherheitsfehler (`ERR_SECURITY_KEY_MISMATCH`) behandelt werden.

#### 5.6.4 DDoS Prevention (Überlastschutz)

Der Handshake erfordert teure kryptografische Operationen (Signaturprüfung, ECDH). Angreifer könnten dies für *Resource Exhaustion Attacks* nutzen.

*   **Silent Drop Policy:** Bei Verdacht auf einen Angriff (z.B. hohe Frequenz von Requests von einer IP) oder bei offensichtlich ungültigen Nachrichten (falsches Format, veralteter Timestamp) SOLLTEN Agenten die Nachricht **stillschweigend verwerfen**, anstatt Rechenleistung für das Erstellen einer `OAEPError`-Antwort zu verschwenden.
*   **Proof of Work (Optional):** Service-Endpunkte KÖNNEN im `ConnectionRequest` einen kryptografischen Arbeitsnachweis (z.B. Hashcash) fordern, bevor sie eine Signatur prüfen.

---

**Section 6: Trust & Reputation**

## 6. Vertrauensmodell und Reputation (Trust & Reputation)

In einem dezentralen Netzwerk wie dem OAP-Ökosystem ist die Existenz einer Identität (DID) keine Garantie für deren Vertrauenswürdigkeit. Jeder Akteur kann beliebig viele DIDs generieren. OAEP trennt daher strikt zwischen **Authentifizierung** (Beweis der Identitäts-Kontrolle, geregelt in Section 5) und **Verifikation** (Beweis der Eigenschaften und Vertrauenswürdigkeit).

Dieses Kapitel definiert die Algorithmen und Datenstrukturen, mit denen Agenten den Vertrauensstatus eines Gegenübers ermitteln. OAEP setzt dabei nicht auf eine einzelne zentrale "Root CA" (Certificate Authority), sondern auf ein föderiertes **Web of Trust** basierend auf W3C Verifiable Credentials.

### 6.1 Verification Logic (Verifikations-Logik)

Ein OAEP-Agent MUSS bei jedem Handshake und vor jeder kritischen Transaktion (z.B. Zahlung, Datenfreigabe) eine mehrstufige Prüfung durchführen. Der Status der Verbindung ("Verified" vs. "Unverified") ergibt sich aus dem Ergebnis dieser Kette.

#### Stufe 1: Kryptografische Integrität (Proof of Possession)
*   **Prüfung:** Entspricht die Signatur im Handshake dem öffentlichen Schlüssel im DID Document?
*   **Aussage:** "Der Absender kontrolliert diesen Identifier."
*   **Fehlerfall:** Bei Fehlschlag MUSS die Verbindung sofort getrennt werden.

#### Stufe 2: Identitäts-Bindung (Controller Validation)
*   **Prüfung:**
    *   Bei `did:web`: Entspricht die DID der Domain, von der das DID Document geladen wurde? Ist das TLS-Zertifikat der Domain gültig?
    *   Bei `did:key`: Ist der öffentliche Schlüssel korrekt im DID-String kodiert?
*   **Aussage:**
    *   `did:web`: "Dieser Agent handelt im Auftrag des Besitzers der Domain `shop.com`."
    *   `did:key`: "Dieser Agent ist konsistent mit seiner mathematischen Definition."

#### Stufe 3: Credential Validation (Ketten-Prüfung)
Wenn ein Agent im Handshake ein `AgentProfile` als Verifiable Credential (VC) vorlegt, das von einer dritten Partei (Issuer) signiert wurde:
*   **Prüfung:**
    1.  Ist die Signatur des Issuers unter dem VC gültig?
    2.  Ist der Issuer selbst vertrauenswürdig? (Prüfung gegen eine lokale "Trusted Issuer List" oder ein Governance-Framework).
*   **Aussage:** "Eine vertrauenswürdige Stelle (z.B. OAP Foundation) bestätigt, dass dieser Agent zur Firma XY gehört."

### 6.2 Revocation (Widerruf & Status-Prüfung)

Vertrauen ist dynamisch. Schlüssel können gestohlen werden, Unternehmen können insolvent gehen, Zertifikate können ablaufen. Da OAEP keine zentralen Server abfragt ("Ist Zertifikat X noch gültig?"), wird ein datenschutzfreundlicher Mechanismus für den Widerruf benötigt.

OAEP standardisiert hierfür die Nutzung von **Bitstring Status Lists (StatusList2021)**.

#### 6.2.1 Funktionsweise
1.  Ein Issuer veröffentlicht eine Status-Liste (z.B. als Datei auf einem Webserver oder IPFS). Diese Datei ist eine stark komprimierte Bit-Map (0/1).
2.  Jedes ausgestellte Credential enthält einen Verweis auf diese Liste und einen Index (z.B. "Bit #452").
3.  Um den Status zu prüfen, lädt der Verifier (der Agent) die Liste.
4.  Ist Bit #452 auf `0` gesetzt, ist das Credential gültig. Ist es auf `1` gesetzt, wurde es widerrufen.

#### 6.2.2 Vorteile & Anforderungen
*   **Privacy:** Der Server, der die Liste hostet, sieht nur, dass die *Liste* abgerufen wurde, nicht *welches* spezifische Credential geprüft wird.
*   **Caching:** Agenten SOLLTEN Status-Listen für einen definierten Zeitraum (z.B. 1 Stunde) cachen, um Netzwerklast zu reduzieren.
*   **Pflicht:** Agenten MÜSSEN den Revocation-Status prüfen, bevor sie eine Transaktion mit hohem Risiko (z.B. > 50€) autorisieren.

### 6.3 Trust Levels (Vertrauensstufen)

Um dem Nutzer (oder der steuernden KI) die Komplexität der Verifikation verständlich zu machen, definiert OAEP vier standardisierte Vertrauensstufen. Das SDK MUSS diese Stufen an die UI (Benutzeroberfläche) durchreichen.

| Level | Bezeichnung | Symbolik (UI) | Technische Bedingung | Anwendungsfall |
| :--- | :--- | :--- | :--- | :--- |
| **0** | **Unknown** | ⚪️ Grau / ? | Valide DID, aber keine bekannten Credentials oder Domain-Bindung. | Anonymer Chat, P2P-Erstkontakt. |
| **1** | **Self-Attested** | 🟡 Gelb | `did:key` mit Profil-Daten, die nur vom Ersteller selbst signiert wurden. Vertrauen basiert auf "Trust on First Use" (TOFU) oder manuellem Kontakt-Austausch (QR-Code). | Persönliche Kontakte, Freunde. |
| **2** | **Domain Validated** | 🟢 Grün (Schloss) | `did:web`. Die Identität ist kryptografisch an eine DNS-Domain gebunden. | Online-Shops, Organisationen, Cloud-Dienste. |
| **3** | **Verified Entity** | ✅ Blauer Haken / Schild | Ein Verifiable Credential von einem **Root Trust Anchor** (z.B. OAP Foundation, eIDAS-Provider) liegt vor und wurde geprüft. | Bankgeschäfte, Behörden, Verifizierte Händler. |

### 6.4 Reputation (Reputations-Netzwerk)

Über die harte Verifikation hinaus unterstützt OAEP den Austausch von weichen Reputations-Daten ("Review Scores").

*   **Signed Reviews:** Ein Agent kann eine Bewertung über einen anderen Agenten (z.B. nach einem Kauf) als signiertes Objekt (VC) erstellen.
*   **Distributed Reputation:** Da es keinen zentralen Server gibt, der alle Bewertungen speichert, MÜSSEN Agenten ihre Reputations-Nachweise selbst sammeln und im Handshake (als Teil des Profils) oder auf Anfrage vorlegen.
*   **Validierung:** Der Empfänger prüft:
    1.  Sind die Signaturen der Bewertungen echt?
    2.  Stammen die Bewertungen von DIDs, mit denen tatsächlich eine OACP-Transaktion stattgefunden hat? (Verknüpfung von Kaufbeleg und Bewertung, um Fake-Reviews zu erschweren).

### 6.5 Security Considerations

*   **Trust Anchor Management:** Das SDK muss mit einer Liste von Standard-Trust-Anchors (z.B. OAP Foundation Public Keys) ausgeliefert werden, muss dem Nutzer aber erlauben, diese Liste zu bearbeiten (Souveränität).
*   **Phishing-Prävention:** Bei `did:web` MUSS die UI die Domain prominent anzeigen. Das SDK SOLLTE "Look-alike" Domains (Homograph Attacks) erkennen und warnen.
*   **Metadaten-Schutz:** Beim Abruf von Status-Listen SOLLTE der Agent Proxies oder Anonymisierungsnetzwerke (z.B. Tor) nutzen können, um zu verhindern, dass der Listen-Host Bewegungsprofile erstellt.

---

**Section 7: Security Considerations**

## 7. Sicherheitsbetrachtungen (Security Considerations)

Die Sicherheit des gesamten OAP-Ökosystems hängt von der korrekten Implementierung des OAEP ab. Da OAEP in einer "Zero-Trust"-Umgebung operiert, in der das Netzwerk, Relays und potenziell auch Gegenstellen kompromittiert sein können, müssen Implementierer die folgenden Sicherheitsrichtlinien strikt einhalten.

### 7.1 Schlüsselmanagement und Speicherung

Die Sicherheit einer Dezentralen Identität (DID) ist untrennbar mit der Sicherheit des privaten Schlüssels verbunden.

*   **Secure Storage (Sichere Speicherung):**
    Private Schlüssel (sowohl langfristige Identitätsschlüssel als auch kurzlebige Sitzungsschlüssel) DÜRFEN NIEMALS im Klartext im Dateisystem, in Datenbanken oder im Code gespeichert werden.
    *   Auf Mobilgeräten MÜSSEN Hardware-gestützte Speicher (iOS Secure Enclave, Android Keystore/StrongBox) verwendet werden.
    *   Auf Servern SOLLTEN HSMs (Hardware Security Modules) oder vergleichbare KMS (Key Management Systems) mit Enclave-Technologie zum Einsatz kommen.
*   **Kein Export:**
    Implementierungen SOLLTEN verhindern, dass private Schlüssel extrahiert werden können. Alle kryptografischen Operationen (Signieren, Entschlüsseln) SOLLTEN innerhalb der gesicherten Hardware-Umgebung stattfinden.
*   **Entropie:**
    Die Generierung von Schlüsseln und Nonces MUSS einen kryptografisch sicheren Zufallszahlengenerator (CSPRNG) verwenden.

### 7.2 Schutz vor Man-in-the-Middle (MitM) Angriffen

Da OAEP keine zentrale Public-Key-Infrastruktur (PKI) verwendet, ist der Schutz vor MitM-Angriffen während des ersten Handshakes kritisch. Ein Angreifer könnte versuchen, sich in die Kommunikation zu schalten, Nachrichten weiterzuleiten oder Schlüssel auszutauschen. Die Sicherheit beruht auf drei Säulen:

#### 7.2.1 Kanalbindung bei `did:web` (Transport Layer Binding)
Bei der Verwendung von `did:web` dient das DNS-System als Vertrauensanker.
*   **Vorschrift:** Bei der Auflösung des DID-Dokuments und beim Senden des `ConnectionRequest` MUSS die HTTPS-Verbindung (TLS) erfolgreich validiert werden.
*   **Abbruch-Bedingung:** Der Handshake MUSS sofort abgebrochen werden, wenn das TLS-Zertifikat der Domain ungültig, abgelaufen, widerrufen oder selbstsigniert (ohne vertrauenswürdige Root-CA) ist. Dies verankert die Sicherheit der DID in der Sicherheit der Domain-Inhaberschaft.

#### 7.2.2 TOFU & Out-of-Band bei `did:key` (Trust On First Use)
Bei `did:key` existiert kein externer Anker. Die Sicherheit basiert auf der Kontinuität der Schlüsselverwendung.
*   **Key Change Alert:** Implementierungen MÜSSEN den Nutzer warnen, wenn sich der öffentliche Schlüssel einer bekannten Kontaktperson (identifiziert durch einen Namen) ändert.
*   **Out-of-Band Verifizierung:** Für kritische Erstkontakte SOLLTE ein Vergleich über einen zweiten Kanal (z.B. Scannen eines QR-Codes oder verbaler Abgleich eines "Safety Number"-Hashes) erzwungen werden.

#### 7.2.3 Kryptografische Kanalbindung (Channel Binding)
Dies ist die wichtigste Maßnahme gegen subtile MitM-Angriffe wie **Unknown Key-Share (UKS)**. Bei einem UKS-Angriff leitet ein Angreifer (Eve) die Authentifizierungs-Signatur von Alice an Bob weiter, tauscht aber die Ephemeral Keys (für die Verschlüsselung) gegen ihre eigenen aus. Bob glaubt, er spreche sicher mit Alice, entschlüsselt aber tatsächlich für Eve.

Um dies zu verhindern, reicht das Signieren einer zufälligen Nonce ("Challenge-Response") NICHT aus.

*   **Vorschrift (Transkript-Signatur):** Die Identitäts-Signaturen (`proof`) in der `ConnectionResponse` (durch Agent B) und im `ConnectionAcknowledge` (durch Agent A) MÜSSEN zwingend über das vollständige **Handshake-Transkript** erfolgen, wie in Abschnitt 5.2 definiert.
*   **Definition:** Das zu signierende Transkript muss kryptografisch binden:
    1.  Die Nonces beider Parteien (Replay-Schutz).
    2.  Die Ephemeral Keys beider Parteien (Session-Integrität).
    3.  Die DIDs beider Parteien (Identitäts-Bindung).
    `Signatur = Sign(PrivKey_Identity, Hash(Nonce_A || Nonce_B || EphemeralKey_A || EphemeralKey_B || DID_A || DID_B))`
*   **Verbot:** Implementierungen DÜRFEN NICHT lediglich die eingehende `challenge` (Nonce) signieren. Eine Signatur, die nicht die Ephemeral Keys einschließt, gilt als unsicher und MUSS vom Empfänger abgelehnt werden.

### 7.3 Schutz vor Replay-Angriffen

Ein Angreifer könnte versuchen, eine valide Handshake-Nachricht (z.B. eine `ConnectionRequest`) aufzuzeichnen und später erneut zu senden, um eine Sitzung zu erzwingen, Zustandsänderungen auszulösen oder den Server durch redundante kryptografische Operationen zu überlasten (DoS). OAEP erzwingt einen mehrstufigen Schutzmechanismus.

#### 7.3.1 Einmaligkeit der Nonce
Jede Handshake-Nachricht MUSS eine kryptografisch zufällige Nonce (Number used once) enthalten.
*   **Entropie:** Die Nonce MUSS mit einem kryptografisch sicheren Zufallszahlengenerator (CSPRNG) erzeugt werden und SOLLTE eine Länge von mindestens 128 Bit (16 Bytes) aufweisen, um Kollisionen mathematisch auszuschließen.
*   **Verbot der Wiederverwendung:** Ein Agent DARF niemals dieselbe Nonce für zwei verschiedene Handshake-Versuche verwenden.

#### 7.3.2 Der Nonce-Cache (Normative Anforderungen)
Empfänger MÜSSEN einen Zustandsspeicher (**Nonce-Cache**) pflegen, um bereits verarbeitete Nachrichten zu erkennen.

*   **Prüfung:** Bevor eine rechenintensive Operation (wie Signaturprüfung) durchgeführt wird, MUSS der Empfänger prüfen, ob die empfangene Nonce bereits im Cache existiert.
    *   **Treffer (Hit):** Die Nachricht ist ein Replay. Sie MUSS sofort verworfen werden. Es SOLLTE ein Fehler `ERR_NONCE_REPLAY` geloggt, aber aus Sicherheitsgründen (Traffic Analysis) eventuell nicht an den Absender zurückgesendet werden (Silent Drop).
    *   **Kein Treffer (Miss):** Die Nonce wird im Cache gespeichert und die Verarbeitung fortgesetzt.
*   **Speicherdauer (Retention Policy):**
    Der Cache MUSS Einträge mindestens so lange vorhalten, wie das Zeitfenster für gültige Zeitstempel geöffnet ist (siehe 7.3.3).
    *   **Formel:** `RetentionTime >= ValidTimeWindow + ClockSkewTolerance`.
    *   *Empfehlung:* Bei einem Zeitfenster von 5 Minuten MÜSSEN Nonces für mindestens **310 Sekunden** (5 Min + 10 Sek Toleranz) gespeichert werden.
*   **Scope (Geltungsbereich):**
    Um Kollisionen zwischen verschiedenen Kontexten zu vermeiden, SOLLTE der Cache pro Peer-DID und Richtung partitioniert sein, sofern die DID bereits bekannt ist. Für initiale `ConnectionRequests` (wo die DID noch nicht verifiziert ist) MUSS ein globaler Cache oder ein Cache basierend auf der IP/Transport-Adresse verwendet werden, um DoS-Attacken auf den Cache selbst zu mitigieren.

#### 7.3.3 Zeitfenster-Begrenzung (Time Window)
Um zu verhindern, dass der Nonce-Cache unendlich wächst, MÜSSEN Nachrichten durch einen Zeitstempel (`created` gemäß RFC 3339) begrenzt werden.

*   **Veraltete Nachrichten:** Empfänger MÜSSEN Nachrichten verwerfen, deren Zeitstempel älter ist als ein definiertes Delta (Normativer Standard: **300 Sekunden**).
*   **Zukünftige Nachrichten:** Empfänger MÜSSEN Nachrichten verwerfen, deren Zeitstempel mehr als **10 Sekunden** in der Zukunft liegt (Schutz vor "Pre-Mining" von Nonces für spätere Replays).
*   **Interaktion mit Cache:** Nur Nachrichten innerhalb dieses Zeitfensters werden gegen den Nonce-Cache geprüft. Nachrichten außerhalb des Fensters werden aufgrund des Zeitstempels verworfen. Dies erlaubt es, den Cache nach Ablauf der `RetentionTime` sicher zu bereinigen ("Rolling Window").

### 7.4 Metadaten-Privatsphäre (Metadata Privacy)

Auch bei perfekter Inhaltsverschlüsselung (E2EE) können Verkehrsdaten (Metadaten) durch Netzwerkanalysen deanonymisiert werden. OAEP implementiert Gegenmaßnahmen, weist jedoch auf physikalische Grenzen und notwendige Design-Entscheidungen hin.

#### 7.4.1 Grenzen von "Blind Relays" (IP-Exposition)
Der Begriff "Blind Relay" bezieht sich im OAP-Kontext ausschließlich auf die **Inhalts-Blindheit**. Das Relay kann den verschlüsselten Payload (den Inhalt der OAMP-Container) nicht lesen.
*   **Warnung (Transport Layer Leak):** Auf der Transportschicht (TCP/IP, HTTP) sieht das Relay zwangsläufig die **IP-Adresse** des sendenden und empfangenden Agenten, um Pakete technisch zuzustellen. Ein kompromittiertes Relay kann somit sehen, *wer* (IP) mit *wem* (IP) wann und wie viel kommuniziert.
*   **Mitigation:** Um vollständige Anonymität (Transport-Blindheit) zu erreichen, MÜSSEN Agenten die Verbindung zum Relay über Anonymisierungsnetzwerke (z.B. **Tor** oder **I2P**) oder vertrauenswürdige VPNs routen. Implementierungen SOLLTEN nativen SOCKS5-Proxy-Support bieten, um dies dem Nutzer zu erleichtern.

#### 7.4.2 DID Rotation (Unlinkability)
Wenn ein Agent dieselbe DID für Interaktionen mit verschiedenen Parteien nutzt, entstehen korrelierbare Profile.
*   **Pairwise DIDs:** Agenten SOLLTEN für jede neue, langfristige Beziehung eine neue, dedizierte DID (`did:key` oder private `did:web`-Pfade) generieren. Dies verhindert, dass Kollaborateure (z.B. zwei verschiedene Shops oder Relays) ihre Logs zusammenführen und ein globales Beziehungsprofil eines Nutzers erstellen ("Correlation Attack").

#### 7.4.3 Traffic Padding (Längen-Verschleierung)
Verschlüsselte Nachrichten verraten durch ihre Länge oft ihren Inhalt (z.B. ist ein einfaches "Ja" kürzer als die Übertragung eines Schlüssels).
*   **Vorschrift:** OAEP-Handshake-Nachrichten und nachfolgende OAMP-Pakete SOLLTEN auf standardisierte Blockgrößen aufgefüllt (padded) werden (z.B. auf das nächste Vielfache von 256 Bytes), um diese Seitenkanalinformationen zu eliminieren.

#### 7.4.4 Schutz sensibler Daten im Handshake
Der initiale `ConnectionRequest` wird oft nur transportverschlüsselt (TLS) zum Relay gesendet, bevor die Ende-zu-Ende-Verschlüsselung steht.
*   **Minimal Disclosure:** Agenten SOLLTEN im ersten Schritt (`ConnectionRequest`) auf das Mitsenden von klarnamen-basierten `AgentProfiles` oder detaillierten `Capabilities` verzichten, sofern diese Rückschlüsse auf die Identität zulassen.
*   **Deferred Transmission:** Sensible Daten MÜSSEN, wann immer möglich, erst **nach** erfolgreicher Etablierung der Sitzungsschlüssel (also innerhalb des verschlüsselten OAMP-Tunnels ab Phase 3 oder 4) übertragen werden.
*   **Encryption at Rest (Relay):** Falls Daten zwingend im ersten Schritt gesendet werden müssen (z.B. zur Routing-Entscheidung), MÜSSEN diese so verpackt sein, dass sie nur vom Ziel-Agenten (durch dessen Public Key aus dem DID Document), nicht aber vom Relay entschlüsselt werden können.

### 7.5 Kryptografische Agilität & Cipher Suites

OAEP ist für eine Lebensdauer von Jahrzehnten ausgelegt. Algorithmen, die heute als sicher gelten, könnten durch mathematische Durchbrüche oder die Verfügbarkeit von Quantencomputern (CRQC) gebrochen werden. Um Sicherheit mit Zukunftssicherheit zu vereinen, setzt OAEP auf **atomare Cipher Suites**.

#### 7.5.1 Atomare Suites statt "Mix & Match"
Agenten DÜRFEN NICHT Signatur-, Hashing- und Verschlüsselungsverfahren einzeln aushandeln. Dies würde die kombinatorische Komplexität erhöhen und Angriffsvektoren für Downgrade-Attacken öffnen.
*   **Konzept:** Eine Cipher Suite definiert eine feste, getestete Kombination aller notwendigen kryptografischen Primitive.
*   **Identifikation:** Jede Suite wird durch einen eindeutigen String (Suite-ID) identifiziert.

#### 7.5.2 Der Aushandlungs-Mechanismus (Negotiation)
Die Einigung auf eine Suite erfolgt im ersten Round-Trip des Handshakes:
1.  **Offer (Initiator):** Im `ConnectionRequest` sendet der Initiator das Feld `supportedSuites`. Dies ist eine geordnete Liste von Suite-IDs, beginnend mit der **bevorzugten (sichersten)** Suite.

1.  **Offer (Initiator):** Liste `supportedSuites`.
2.  **Select (Responder):** Der Responder prüft die Liste von oben nach unten.
    *   **Tie-Break Regel:** Finden sich mehrere gemeinsame Suites mit identischer Sicherheitsstufe (gemäß lokaler Policy), MUSS der Responder deterministisch jene Suite wählen, deren Suite-ID lexikalisch (ASCII-Sortierung) am niedrigsten ist (z.B. `OAEP-v1-2026` vor `OAEP-v1-2027`).
3.  **Confirm (Responder):** Im `ConnectionResponse` sendet er die gewählte ID im Feld `negotiatedSuite` zurück.
4.  **Enforcement:** Ab diesem Zeitpunkt MÜSSEN alle kryptografischen Operationen (Signaturen, Key Derivation, Encryption) strikt den Vorgaben dieser Suite folgen.

#### 7.5.3 Mandatory Suite für v1.0 (`OAEP-v1-2026`)
Um Basis-Interoperabilität zu garantieren, MÜSSEN alle OAEP-v1.0-konformen Implementierungen folgende Suite unterstützen:

**Suite-ID:** `OAEP-v1-2026`

| Primitiv | Algorithmus / Spezifikation | Zweck |
| :--- | :--- | :--- |
| **Signatur** | **Ed25519** (EdDSA) | Authentifizierung & Integrität |
| **Key Agreement** | **X25519** (ECDH) | Perfect Forward Secrecy (PFS) |
| **Encryption** | **ChaCha20-Poly1305** (IETF) | Nachrichten-Verschlüsselung |
| **Hashing / KDF** | **BLAKE3** | Transkript-Hash & Schlüsselableitung |

*Hinweis: BLAKE3 wird aufgrund seiner Performance und Sicherheitseigenschaften in modernen Rust-Umgebungen bevorzugt. Ein Fallback auf SHA-256 ist in dieser Suite-ID nicht vorgesehen, um Determinismus zu wahren.*

#### 7.5.4 Post-Quantum-Readiness & Hybride Suites
Das Protokoll ist explizit darauf ausgelegt, **hybride Verfahren** zu unterstützen, um den Übergang in die Post-Quantum-Ära sicher zu gestalten.
*   **Hybride Suites:** Eine zukünftige Suite-ID (z.B. `OAEP-v2-PQ-Hybrid`) kann definieren, dass für den Schlüsselaustausch **sowohl** X25519 (klassisch) **als auch** Kyber-768 (PQC) verwendet werden müssen. Das `keyExchange`-Feld im JSON-LD erlaubt hierfür strukturierte Objekte.
*   **Sicherheit durch Redundanz:** Durch die hybride Ansatzweise bleibt die Verbindung sicher, solange *einer* der beiden Algorithmen (der klassische ECC oder der neue PQC) ungebrochen ist.
*   **Vorschrift:** Wenn ein Agent eine neuere, sicherere Suite (z.B. PQC) unterstützt, MUSS er diese in seiner `supportedSuites`-Liste vor den älteren Suites (Legacy ECC) reihen. Responder MÜSSEN die sicherste gemeinsame Suite wählen.

### 7.6 Implementierungssicherheit

*   **Timing Attacks:**
    Kryptografische Vergleiche (z.B. Überprüfung von MACs oder Hashes) MÜSSEN in konstanter Zeit ("Constant Time") erfolgen, um zu verhindern, dass Angreifer durch Messung der Antwortzeit Rückschlüsse auf den Schlüssel ziehen.
*   **Fehlermeldungen:**
    Im Fehlerfall (z.B. ungültige Signatur, unbekannte DID) DÜRFEN Agenten keine detaillierten Informationen preisgeben, die einem Angreifer helfen könnten (z.B. "Benutzer existiert nicht" vs. "Benutzer existiert, aber Schlüssel falsch"). Es SOLLTEN generische Fehlercodes verwendet werden.
*   **Input Validation:**
    Alle eingehenden JSON-LD-Daten müssen streng gegen das Schema validiert werden, bevor sie verarbeitet werden, um Injection-Angriffe oder Buffer Overflows zu verhindern.
    
---

**Section 8: Implementation Guidelines**

## 8. Richtlinien für Implementierer (Implementation Guidelines)

Dieses Kapitel bietet normative und informative Hinweise für Entwickler, die OAEP in Softwarebibliotheken oder Applikationen implementieren. Das Ziel ist die Maximierung der Interoperabilität und Robustheit des Netzwerks.

### 8.1 Fehlerbehandlung (Error Handling)

In einem verteilten, asynchronen System ist das Scheitern von Operationen ein erwarteter Zustand. OAEP definiert ein standardisiertes Format für Fehlermeldungen, damit sendende Agenten programmatisch und sicher auf Probleme reagieren können.

#### 8.1.1 Das `OAEPError` Objekt
Wenn ein Handshake oder eine Verarbeitung fehlschlägt und die Sicherheitsrichtlinien (siehe 8.1.4) eine Antwort erlauben, MUSS der Agent eine `OAEPError`-Nachricht zurücksenden.

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

#### 8.1.2 Taxonomie: Codes vs. Kategorien
Um Stabilität und Erweiterbarkeit zu gewährleisten, unterscheidet OAEP zwischen semantischen String-IDs und numerischen Kategorien.

1.  **Code (String-ID):** Das Feld `code` ist der normative Identifikator (z.B. `"ERR_PROTO_VERSION"`). Implementierungen MÜSSEN ihre Logik ("Switch-Case") auf diesen String stützen.
2.  **Kategorie (Numerisch):** Das Feld `category` dient der Gruppierung und dem generischen Fallback-Verhalten.

| Kategorie | Bereich | Bedeutung | Generisches Verhalten |
| :--- | :--- | :--- | :--- |
| **Protocol** | 1000-1999 | Syntax, Parsing, Versionierung | Request korrigieren & wiederholen (wenn möglich). |
| **Auth/Sec** | 2000-2999 | Signaturen, DIDs, Ablaufdatum | **Fatal.** Abbruch der Sitzung. Neu-Authentifizierung nötig. |
| **Network** | 3000-3999 | Rate Limits, Routing, Timeouts | Warten (Backoff) und Retry. |
| **App** | 4000-4999 | Logikfehler in Layer 1 (OACP etc.) | Anwendungsabhängig. |

#### 8.1.3 Normative Fehlercodes (Auszug)
Implementierungen SOLLTEN mindestens folgende Codes unterstützen:

*   `ERR_MALFORMED_JSON` (1001): JSON-LD ungültig oder Schema verletzt.
*   `ERR_PROTO_VERSION` (1002): Inkompatible Protokollversion.
*   `ERR_DID_RESOLUTION` (2001): DID konnte nicht aufgelöst werden.
*   `ERR_AUTH_SIG_INVALID` (2002): Kryptografische Signaturprüfung fehlgeschlagen.
*   `ERR_NONCE_REPLAY` (2003): Nachricht wurde bereits verarbeitet.
*   `ERR_RATE_LIMIT` (3001): Zu viele Anfragen (Backoff erforderlich).

#### 8.1.4 Sicherheits-Policies (Response Matrix)
Nicht jeder Fehler darf beantwortet werden. Um *Information Leakage*, *Reflection Attacks* und *DoS-Amplification* zu verhindern, gelten folgende Regeln für das Senden von `OAEPError`:

Drei normative Policies für den Umgang mit Fehlern:
1.  **Reply & Continue:** (Syntax/App Fehler in aktiver Session).
    *   *Anwendung:* Bei Syntax-Fehlern (`1xxx`) oder Anwendungsfehlern (`4xxx`) innerhalb einer bereits **authentifizierten** (verschlüsselten) Sitzung.
    *   *Aktion:* Sende `OAEPError`. Halte Verbindung offen.

2.  **Reply & Close:** (Auth-Fehler im Handshake).
    *   *Anwendung:* Bei Authentifizierungsfehlern (`2xxx`) oder Protokoll-Mismatch während des Handshakes.
    *   *Aktion:* Sende `OAEPError` (um dem Peer Debugging zu ermöglichen). Lösche sofort alle Sitzungsschlüssel. Schließe die Transportverbindung.

3.  **Silent Drop:** (DoS-Verdacht, Replay, ungültige Timestamps) -> Keine Antwort senden.
    *   *Anwendung:*
        *   Bei Verdacht auf DoS (z.B. extrem hohe Anfragerate).
        *   Bei Replay-Attacken (`ERR_NONCE_REPLAY`).
        *   Bei ungültigen Zeitstempeln (Expired/Future).
        *   Wenn das Parsen des Headers fehlschlägt (Absender unklar).
    *   *Aktion:* **Keine Antwort senden.** Ressourcennutzung minimieren. Eventuell IP temporär blockieren (Fail2Ban).
    *   *Grund:* Das Senden eines Fehlers würde dem Angreifer bestätigen, dass ein Dienst läuft, und könnte Bandbreite für eine Amplification-Attacke missbrauchen.

### 8.2 Versionierung und Kompatibilität

Das OAEP-Ökosystem wird sich weiterentwickeln. Implementierungen MÜSSEN robust gegenüber Versionsunterschieden sein.

*   **Semantic Versioning:** OAEP nutzt SemVer (MAJOR.MINOR.PATCH).
    *   *Patch-Updates (1.0.1):* Dürfen keine Änderungen am Datenmodell vornehmen.
    *   *Minor-Updates (1.1.0):* Dürfen neue Felder hinzufügen (additive Änderungen). Ältere Implementierungen MÜSSEN unbekannte Felder ignorieren ("Forward Compatibility").
    *   *Major-Updates (2.0.0):* Brechende Änderungen. Erfordern Neu-Aushandlung.
*   **Negotiation:**
    Während des Handshakes sendet jeder Agent seine Version (`oaepVersion: "1.0"`). Die Kommunikation findet auf dem höchsten gemeinsamen Nenner (Major Version) statt. Unterstützt Agent A v1.2 und Agent B v1.0, MUSS Agent A auf das v1.0-Verhalten zurückfallen.

### 8.3 Performance & Ressourcen-Management

Da OAEP-Agenten häufig auf mobilen Endgeräten (Batterie- und Bandbreiten-limitiert) oder in IoT-Umgebungen operieren, ist ein effizientes Ressourcenmanagement nicht nur eine Optimierung, sondern eine Voraussetzung für die Stabilität.

#### 8.3.1 Local Context Rule (Kein Runtime-Fetching)
JSON-LD nutzt URLs (z.B. `https://w3id.org/oaep/v1`), um das Vokabular zu definieren.
*   **Risiko:** Ein Nachladen dieser Ressourcen zur Laufzeit würde die Privatsphäre verletzen (Tracking durch den Server-Betreiber bei jedem Handshake) und die Verfügbarkeit des Protokolls bei Internetausfall gefährden.
*   **Vorschrift:** OAEP-Implementierungen **MÜSSEN** statische, lokale Kopien aller unterstützten JSON-LD-Kontexte (Core OAEP, W3C DIDs, W3C VCs) mit der Software ausliefern ("Ship with code").
*   **Verbot:** Der JSON-LD-Prozessor MUSS externe HTTP-Requests für bekannte `@context`-URIs strikt **blockieren** und stattdessen die lokalen statischen Kopien nutzen (siehe 9.3).

#### 8.3.2 Caching von DID Documents
Die Auflösung von DIDs (insbesondere `did:web` via DNS/HTTPS) ist eine teure Operation.
*   **Caching-Pflicht:** Implementierungen MÜSSEN eine Caching-Strategie für aufgelöste DID Documents anwenden.
*   **TTL (Time To Live):**
    *   Für `did:web` SOLLTE die Cache-Dauer den HTTP-Headern (`Cache-Control`) der Quelle folgen, jedoch mindestens 15 Minuten betragen, um "Resolution-Spam" zu verhindern.
    *   Für `did:key` IST das Dokument unveränderlich. Es KANN unbegrenzt gecached werden.
*   **Invalidierung:** Vor kritischen Transaktionen (z.B. einer hohen Zahlung) KANN der Cache ignoriert werden, um sicherzustellen, dass kein Schlüssel-Widerruf (Revocation) verpasst wurde.

#### 8.3.3 DoS-Mitigation & "Silent Drop"
Der Handshake erfordert asymmetrische Kryptografie (Signaturprüfung, ECDH), was rechenintensiv ist. Angreifer können dies für *Resource Exhaustion* nutzen.
*   **Verhalten unter Last:** Wenn ein Agent feststellt, dass seine Ressourcen (CPU, Memory, offene Sockets) knapp werden, SOLLTE er in den **"Defensive Mode"** wechseln.
*   **Silent Drop:** Im Defensive Mode oder bei offensichtlich malgeformten Paketen (falscher Magic Byte, ungültige Zeitstempel) MUSS der Agent Pakete **stillschweigend verwerfen**, anstatt Rechenleistung für das Erstellen und Senden von `OAEPError`-Antworten zu verschwenden.
*   **Rate Limiting:** Server-seitige Agenten MÜSSEN Limits für die Anzahl der Handshake-Versuche pro IP-Adresse oder DID pro Zeitfenster implementieren.

**Normativer Rate-Limiting Algorithmus (Token Bucket):**
Um Handshake-Flooding und PSI-Scraping zu verhindern, MÜSSEN Server-Endpunkte einen **Token Bucket Filter** implementieren:
*   **Bucket-Kapazität ($C$):** Definiert den Burst (Empfehlung: 50).
*   **Refill-Rate ($R$):** Definiert die Dauerlast (Empfehlung: 5/Sekunde).
*   Scope: Pro IP (anonym) oder pro DID (authentifiziert).
*   Bei leerem Bucket: `ERR_RATE_LIMIT` oder Silent Drop.

#### 8.3.4 Verbindungs-Wiederverwendung (Keep-Alive)
Der Aufbau einer TLS-Verbindung (für den Transport) und der OAEP-Handshake erzeugen Overhead.
*   **Persistente Verbindungen:** Wenn der zugrundeliegende Transportkanal es erlaubt (z.B. HTTP/2, WebSockets, QUIC), SOLLTE die Verbindung für mehrere aufeinanderfolgende OAMP-Nachrichten offengehalten werden.
*   **Timeouts:**
    *   Für den synchronen Teil des Handshakes (Request <-> Response) gilt ein Timeout von **30 Sekunden**.
    *   Für inaktive Sessions SOLLTE ein "Idle Timeout" (z.B. 10 Minuten) implementiert werden, nach dem die Ephemeral Keys gelöscht und die Verbindung geschlossen wird, um Speicher freizugeben.

### 8.4 Referenzimplementierung (Reference Implementation)

Um die Entwicklung zu beschleunigen und Standardkonformität zu sichern, stellt die OAP Foundation eine offizielle Referenzimplementierung bereit.

*   **OAP Core (Rust):**
    Die sicherheitskritische Logik (Kryptografie, DID Resolution, Handshake State Machine) ist in Rust implementiert.
    *   *Repository:* `github.com/oap-foundation/oap-core-rs`
    *   *Status:* Dies ist die "Source of Truth" für das Verhalten des Protokolls.
*   **Bindings (SDKs):**
    Für Anwendungsentwickler werden Wrapper bereitgestellt, die den Rust-Core nutzen:
    *   `oap-python` (für Backend/AI Services)
    *   `oap-dart` (für Flutter/Mobile Apps)
    *   `oap-js` (WASM-basiert für Web-Clients)

Entwickler werden DRINGEND ermutigt, diese Bibliotheken zu nutzen, anstatt die Kryptografie selbst zu implementieren ("Don't roll your own crypto").

### 8.5 Testen & Konformität (Conformance Testing)

Eine Implementierung darf sich nur dann "OAEP Compliant" nennen, wenn sie die offizielle Test-Suite besteht.

*   **Test-Vektoren:**
    Das RFC-Repository enthält einen Ordner `/test-vectors`. Dieser beinhaltet JSON-Dateien mit Eingabedaten (z.B. rohe Schlüssel, DIDs) und den erwarteten Ausgabedaten (z.B. korrekte Signaturen, validierte Handshake-Nachrichten).
*   **Integrationstests:**
    Entwickler sollten ihre Agenten gegen den **"OAP Echo Bot"** testen. Dies ist ein öffentlich verfügbarer, immer aktueller Referenz-Agent (`did:web:echo.oap.foundation`), der jeden korrekten Handshake akzeptiert und Nachrichten spiegelt.

### 8.6 Migration von Legacy-Systemen

Für Entwickler, die bestehende Web2-Systeme (z.B. klassische REST-APIs) anbinden wollen:

*   **OAP Gateway Pattern:**
    Es wird empfohlen, einen "Sidecar"-Agenten zu betreiben, der OAEP spricht und intern Anfragen an die Legacy-API weiterleitet.
*   **Authentication Bridge:**
    Bestehende OAuth2-Systeme können OAEP nutzen, indem der `id_token` Flow durch einen OAEP-Handshake ersetzt wird. Das Ergebnis des Handshakes (die verifizierte DID) wird dann intern auf einen lokalen User-Account gemappt.
    
### 8.7 Edge Cases & Resilience (Grenzfälle und Resilienz)

Robuste Implementierungen zeichnen sich dadurch aus, dass sie nicht nur den erfolgreichen Pfad ("Happy Path") beherrschen, sondern auch in Fehlerzuständen deterministisch und sicher agieren.

#### 8.7.1 Unvollständige Handshakes ("Hanging State")
Ein häufiges Angriffsmuster oder Netzwerkproblem ist der "halbe Handshake": Initiator A sendet einen Request, Responder B antwortet, aber A sendet nie das finale Acknowledge. B hält nun Speicherressourcen (Ephemeral Keys, State) für eine Verbindung, die nie zustande kommt.

*   **Vorschrift (State Cleanup):** Implementierungen MÜSSEN einen strikten Timer für den Abschluss des Handshakes setzen (Empfehlung: 30 Sekunden ab Empfang der ersten Nachricht).
*   **Aktion:** Läuft der Timer ab, bevor der Status `ACTIVE` erreicht ist, MUSS der Agent:
    1.  Den gesamten Kontext der Sitzung verwerfen.
    2.  Alle generierten Ephemeral Keys sicher aus dem Speicher löschen (überschreiben/zeroize).
    3.  In den Status `IDLE` zurückkehren.
*   **Verbot:** Es darf KEINE "Geister-Session" offen gehalten werden, in der Hoffnung, dass das Acknowledge Stunden später eintrifft.

#### 8.7.2 Transport-Verlust vs. Session-Status
Da OAEP v1.0 keine *Session Resumption* (Wiederaufnahme) unterstützt, ist der kryptografische Sitzungsstatus eng an die darunterliegende Transportverbindung (z.B. TCP Socket, WebSocket) gekoppelt.

*   **Verbindungsabbruch:** Wenn die Transportschicht einen Abbruch signalisiert (z.B. TCP FIN/RST, WebSocket Close), MUSS der OAEP-Agent die kryptografische Sitzung sofort als beendet betrachten.
*   **Key Destruction:** Die symmetrischen Sitzungsschlüssel (`sk_a_to_b`, `sk_b_to_a`) MÜSSEN sofort gelöscht werden.
*   **Reconnect:** Ein erneuter Verbindungsaufbau erfordert zwingend einen neuen, vollständigen OAEP-Handshake mit frischen Schlüsseln. Implementierer DÜRFEN NICHT versuchen, alte Sitzungsschlüssel auf einer neuen TCP-Verbindung wiederzuverwenden (Verletzung der Forward Secrecy).
*   **Keepalive für instabile Transporte (BLE/NFC):**
    Bei Transportmedien ohne native Verbindungszustände MUSS ein Heartbeat-Mechanismus genutzt werden.
    *   **Message:** Typ `OAEPHeartbeat` (Body leer).
    *   **Interval:** Alle 30s (Default).
    *   **Ack:** Empfänger antwortet mit `OAEPHeartbeatAck`.
    *   **Timeout:** Nach 3 unbeantworteten Heartbeats MÜSSEN die Schlüssel gelöscht werden.

#### 8.7.3 `did:key` ohne Service Endpoint (In-Band Transport)
`did:key`-Dokumente enthalten oft keinen `service`-Eintrag, da sie für Ad-hoc-Szenarien gedacht sind (z.B. Bluetooth LE, WebSockets oder Scannen eines QR-Codes).

*   **Implizites Routing:** Wenn ein Agent einen Handshake mit einer `did:key` initiiert, die keinen Service-Endpunkt besitzt, DARF er die Auflösung nicht mit `ERR_DID_RESOLUTION` abbrechen.
*   **Vorschrift:** In diesem Fall MUSS der Agent annehmen, dass der Transportkanal bereits "In-Band" existiert (d.h. die Antwort wird über denselben Socket zurückgesendet, über den die Anfrage kam).
*   **Sicherheitshinweis:** Dies entbindet nicht von der Pflicht zur Signaturprüfung. Auch In-Band-Nachrichten müssen kryptografisch verifiziert werden.

#### 8.7.4 Race Conditions (Gleichzeitige Handshakes)
Szenario: Agent A sendet `ConnectionRequest` an B. Gleichzeitig sendet B einen `ConnectionRequest` an A.

*   **Resolution:** OAEP behandelt dies als zwei völlig separate, unabhängige Versuche.
*   **Verhalten:** Beide Agenten sollten versuchen, ihren jeweiligen Handshake als Responder bzw. Initiator fortzuführen. Es entstehen (im Erfolgsfall) zwei parallele verschlüsselte Tunnel.
*   **App-Layer Entscheidung:** Es obliegt der Anwendungslogik (Layer 1), zu entscheiden, welcher der beiden Tunnel genutzt wird (z.B. "nutze den Tunnel mit dem neueren Zeitstempel") und den anderen zu schließen (`OAEPError` oder TCP Close).

#### 8.7.5 Panic Mode (State Exhaustion)
Wenn ein Server unter massiver Last steht und keinen Speicher mehr für neue Handshake-States (`AWAIT_ACK`) hat:
*   **Policy:** Der Agent SOLLTE das Prinzip **"LIFO Drop" (Last In, First Out) vermeiden**. Stattdessen SOLLTE er entweder:
    1.  Den ältesten noch nicht abgeschlossenen Handshake verwerfen (LRU Eviction), um Platz zu schaffen.
    2.  Oder neue Anfragen sofort stillschweigend verwerfen (Silent Drop), bis sich der Speicher erholt hat.
*   **Kein Crash:** Eine Speichererschöpfung durch zu viele offene Handshakes DARF NIEMALS zum Absturz des gesamten Agenten-Prozesses führen.

### 8.8 Protokoll-Lebenszyklus und Deprecation
Da kryptografische Algorithmen altern, definiert OAEP v1.0 einen Mechanismus für den geordneten Rückzug (Sunset) von Cipher Suites.
*   **Sunset-Ankündigung:** Responder KÖNNEN im `ConnectionResponse` Header ein Feld `warnings` mitsenden (z.B. "Suite deprecated on 2029-01-01").
*   **Hard Cutoff:** Nach dem Stichtag MUSS die Nutzung der Suite mit `ERR_UNSUPPORTED_SUITE` abgelehnt werden.
*   **Langlebige Geräte:** IoT-Geräte MÜSSEN updatefähig sein oder mit konservativen, hybriden Suites (siehe 7.5.4) ausgeliefert werden, die eine Lebensdauer von >10 Jahren anstreben.

### 8.9 Kompatibilität zu W3C Standards
OAEP v1.0 ist normativ an **W3C DID Core v1.0** und **Verifiable Credentials v1.1** gebunden. Neuere W3C-Formate MÜSSEN an der Schnittstelle transparent auf diese Versionen gemappt ("gedowngradet") werden.
*   **Forward Compatibility:** Sollten zukünftige Versionen der W3C-Standards (z.B. DID v2.0) Breaking Changes einführen, verbleibt OAEP v1.0 auf den v1.0/v1.1 Definitionen. Eine Unterstützung neuer W3C-Standards erfordert ein Upgrade auf OAEP v2.0.
*   **Mapping:** Implementierungen, die intern neuere W3C-Formate nutzen, MÜSSEN diese an der OAEP-Schnittstelle (im Handshake) transparent auf die v1.0/v1.1-Spezifikation mappen ("Downgrade"), um die Protokoll-Integrität nicht zu gefährden.

---

**Section 9: Appendix & Examples**

## 9. Anhang und Beispiele (Appendix & Examples)

Dieser Abschnitt ist informativ, nicht normativ. Er stellt Beispiele für JSON-LD-Payloads und kryptografische Testvektoren bereit, um Entwicklern bei der Implementierung und beim Debugging zu helfen.

### 9.1 Vollständiger Handshake-Ablauf (Beispiel)

Das folgende Szenario beschreibt einen erfolgreichen Handshake ("Happy Path") zwischen zwei Agenten. Es demonstriert die Aushandlung der Verschlüsselungsparameter und die **Kanalbindung durch Transkript-Signaturen** zur Verhinderung von Man-in-the-Middle-Angriffen.

*   **Initiator (Alice):** `did:key:z6MkAlice...` (Personal AI auf einem Smartphone)
*   **Responder (Bob):** `did:web:shop.com` (Ein Online-Shop)

#### Schritt 1: ConnectionRequest (Alice -> Bob)
Alice möchte eine Verbindung aufbauen. Sie generiert eine Nonce (`Nonce_A`), ihren ephemeren Schlüssel (`EphemeralKey_A`) und listet die von ihr unterstützten Cipher Suites auf.

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
    // Optional: Eingebettetes AgentProfile (noch unverschlüsselt!)
    "profile": { ... }
  }
}
```

#### Schritt 2: ConnectionResponse (Bob -> Alice)
Bob empfängt die Anfrage. Er wählt die Suite `OAEP-v1-2026`, generiert seine Werte (`Nonce_B` und `EphemeralKey_B`) und erstellt das **Handshake-Transkript** (gemäß Abschnitt 5.2.1).
**Wichtig:** Bob signiert den Hash dieses Transkripts, um seine Identität (`did:web:shop.com`) unwiderruflich an die ausgehandelten Schlüssel zu binden.

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
    // HINWEIS: Dieses Feld repräsentiert den Hash des gesamten
    // Handshake-Transkripts (JCS normalisiert), nicht nur die Nonce.
    // Hash(Header + Alice_Params + Bob_Params)
    "transcriptHash": "SHA256_HASH_OF_FULL_TRANSCRIPT_XYZ...",
    "jws": "eyJhbGciOiJFZ...SignaturÜberDenTranscriptHash..."
  }
}
```

#### Schritt 3: ConnectionAcknowledge (Alice -> Bob)
Alice prüft Bobs Signatur gegen das lokal rekonstruierte Transkript. Sie ist gültig. Nun signiert Alice **dasselbe Transkript** mit ihrem privaten Schlüssel, um ihre eigene Identität zu beweisen und den Kanal beidseitig zu schließen.

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
    // Auch hier: Signatur über dasselbe Transkript wie bei Bob
    "transcriptHash": "SHA256_HASH_OF_FULL_TRANSCRIPT_XYZ...",
    "jws": "eyJhbGciOiJFZ...SignaturÜberDenTranscriptHash..."
  }
}
```
*Nach diesem Schritt verfügen beide Parteien über das Shared Secret (via ECDH ihrer ephemeren Keys) und die Session ist etabliert. Der Status wechselt auf `ACTIVE`.*

### 9.2 Kryptografische Test-Vektoren

Implementierer MÜSSEN ihre Bibliotheken gegen diese Vektoren testen, um Kompatibilität sicherzustellen.

#### 9.2.1 DID Ableitung (did:key)
*   **Algorithmus:** Ed25519
*   **Public Key (Hex):** `4cc5d946841753173d639b7367616b492927976176332766324e6c382b6c7938`
*   **Erwartete DID:** `did:key:z6Mkk7yqnYD6h4nwVeM8jQjC9K9E5g8jFwi5p5J555555555` *(Hinweis: Beispielwert, muss real berechnet werden)*

#### 9.2.2 Shared Secret Ableitung (X25519)
Simuliert den ECDH-Austausch für Session Keys.

*   **Alice Private Ephemeral (Hex):** `77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a`
*   **Bob Public Ephemeral (Hex):** `de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f`
*   **Erwartetes Shared Secret (Hex):** `4a5d9d5ba4c49464a8395187327c76910d643c8e47087798341e975971573327`

### 9.3 OAEP JSON-LD Kontext Definition
Der folgende Context ist **normativ**. Implementierungen MÜSSEN diesen Inhalt lokal vorhalten.

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

### 9.4 Liste der reservierten Fehlercodes

OAEP verwendet ein duales Fehlersystem.
1.  **`code` (String):** Der normative, eindeutige Identifikator (z.B. `"ERR_AUTH_SIG_INVALID"`). Implementierungen MÜSSEN ihre Programmlogik auf diesen String stützen.
2.  **`category` (Integer):** Eine Gruppierung für generisches Verhalten (z.B. `2002`).

Implementierungen MÜSSEN die folgenden Standard-Codes unterstützen. Der Bereich `1000` bis `4999` ist für das Core-Protokoll reserviert.

#### 9.4.1 Kategorie 1xxx: Syntax & Protokoll (Protocol Errors)
*Verhalten: Der Request ist technisch ungültig. Korrektur durch Sender erforderlich.*

| Code-ID | Kategorie | Beschreibung |
| :--- | :--- | :--- |
| `ERR_MALFORMED_JSON` | 1001 | Das empfangene JSON ist syntaktisch inkorrekt oder verletzt das Schema. |
| `ERR_PROTO_VERSION` | 1002 | Die angeforderte OAEP-Version wird vom Empfänger nicht unterstützt. |
| `ERR_MISSING_FIELD` | 1003 | Ein zwingend erforderliches Feld (z.B. `nonce`, `proof`) fehlt. |
| `ERR_ENCODING_INVALID` | 1004 | Ein Feld hat das falsche Format (z.B. kein valides Base64 oder Hex). |

#### 9.4.2 Kategorie 2xxx: Identität & Sicherheit (Security Errors)
*Verhalten: **Fatal.** Die Identität oder Integrität konnte nicht verifiziert werden. Die Verbindung MUSS sofort geschlossen und alle Schlüssel müssen verworfen werden.*

| Code-ID | Kategorie | Beschreibung |
| :--- | :--- | :--- |
| `ERR_DID_RESOLUTION` | 2001 | Die DID des Senders konnte nicht aufgelöst werden (z.B. DNS-Fehler bei `did:web`). |
| `ERR_AUTH_SIG_INVALID` | 2002 | Die kryptografische Signatur über das Transkript ist mathematisch ungültig. |
| `ERR_UNKNOWN_KEY` | 2003 | Der zum Signieren verwendete Schlüssel (`verificationMethod`) ist nicht im DID Document enthalten. |
| `ERR_CERT_REVOKED` | 2004 | Das verwendete Credential oder der Schlüssel steht auf einer Revocation-Liste (StatusList2021). |
| `ERR_CERT_EXPIRED` | 2005 | Das `expirationDate` des Credentials oder der DID ist überschritten. |
| `ERR_UNSUPPORTED_SUITE`| 2006 | Keine gemeinsame Cipher Suite konnte ausgehandelt werden. |
| `ERR_SECURITY_KEY_MISMATCH` | 2007 | Der öffentliche Schlüssel stimmt nicht mit dem lokal gepinnten Schlüssel (TOFU) überein. |

#### 9.4.3 Kategorie 3xxx: Netzwerk & Zustand (State Errors)
*Verhalten: Temporärer Fehler oder Schutzmaßnahme. Retry (mit Backoff) möglich oder Nachricht wird verworfen.*

| Code-ID | Kategorie | Beschreibung |
| :--- | :--- | :--- |
| `ERR_RATE_LIMIT` | 3001 | Zu viele Anfragen. Sender MUSS exponentielles Backoff anwenden. |
| `ERR_NONCE_REPLAY` | 3002 | Die Nonce wurde bereits verwendet. Nachricht wird verworfen (Replay Attack Protection). |
| `ERR_MSG_EXPIRED` | 3003 | Der Zeitstempel liegt zu weit in der Vergangenheit (außerhalb des Toleranzfensters). |
| `ERR_MSG_FUTURE` | 3004 | Der Zeitstempel liegt in der Zukunft (Clock Drift zu groß). |
| `ERR_STATE_MISMATCH` | 3005 | Nachrichtentyp passt nicht zum aktuellen Status (z.B. ACK empfangen, obwohl kein Request gesendet). |

#### 9.4.4 Kategorie 4xxx: Policy & Application (Logic Errors)
*Verhalten: Die Nachricht war technisch korrekt, wurde aber aus logischen oder rechtlichen Gründen abgelehnt.*

| Code-ID | Kategorie | Beschreibung |
| :--- | :--- | :--- |
| `ERR_POLICY_REJECTED` | 4001 | Der Agent lehnt die Kommunikation ab (z.B. Blockliste, Geoblocking, "Nur verifizierte User"). |
| `ERR_NO_COMMON_PROTO` | 4002 | Keine Übereinstimmung bei der *Capability Negotiation* (keine gemeinsame Sprache in Layer 1). |
| `ERR_APP_GENERIC` | 4999 | Ein unspezifischer Fehler in der verarbeitenden Applikation (Layer 1). |

#### 9.4.5 Benutzerdefinierte Fehler (Custom Errors)
Entwickler, die eigene Erweiterungen bauen, DÜRFEN Codes im Bereich **9000-9999** definieren.
*   **Namenskonvention:** Eigene Codes MÜSSEN mit einem eindeutigen Namensraum (Vendor Prefix) beginnen, um Kollisionen zu vermeiden.
*   *Beispiel:* `COM_SHOPIFY_OUT_OF_STOCK` (Kategorie 9001).