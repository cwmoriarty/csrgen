# CSRGen

**CSRGen** is a self-contained, Web 1.0 style PKI application that generates matching Certificate Signing Requests (CSRs) and cryptographic key pairs matching the parameters (cipher types, key sizes, elliptic curves, subjects, and SAN extensions) of an existing certificate.

👉 **Live Web App:** [https://cwmoriarty.github.io/csrgen/](https://cwmoriarty.github.io/csrgen/)

---

## Features

1. **Self-Contained Standalone Application (`index.html`)**:
   - Zero runtime dependencies—all cryptography, styling, and application logic are inlined into a single portable `index.html` file.
   - Runs offline in any modern web browser or on air-gapped systems.
   - Keys are generated locally in memory via the W3C Web Cryptography API (`crypto.subtle`) and never leave your machine.

2. **Multiple Certificate Input Methods**:
   - **Live HTTPS URL inspection**: Connects via TLS with Server Name Indication (SNI) to extract the active leaf certificate and full chain (e.g. `https://example.com` or `internal-app:8443`).
   - **File Upload & Drag-and-Drop**: Accepts `.crt`, `.pem`, `.cer`, and binary `.der` certificates.
   - **Paste PEM**: Direct copy-paste of standard PEM certificate blocks.
   - **Quick Sample Presets**: 1-click presets for RSA, ECDSA, and Ed25519 certificates.

3. **Cryptographic Algorithm Support**:
   - **RSA**: 2048-bit, 3072-bit, 4096-bit.
   - **ECDSA**: NIST P-256 (`prime256v1` / `secp256r1`), P-384 (`secp384r1`), P-521 (`secp521r1`).
   - **Edwards-Curve**: Ed25519 (RFC 8410 / native WebCrypto).
   - **Post-Quantum Cryptography (PQC)**: NIST FIPS 204 ML-DSA (`ML-DSA-44`, `ML-DSA-65`, `ML-DSA-87`) with OpenSSL 4.1.

4. **Subject DN & SAN Integrity**:
   - Formats Subject DN (`CN`, `O`, `OU`, `C`, `ST`, `L`, `Street`, `Email`) using strict single-valued RDN Sets to guarantee clean, standard OpenSSL formatting.
   - Auto-extracts all DNS names, IP addresses, and URIs into the CSR's Subject Alternative Name (SAN) extension (`2.5.29.17`).
   - Includes a 1-click **Sync CN to SAN** helper.

5. **Export & Automation Tools**:
   - **OpenSSL Config (`request.cnf`)**: Generate and download an exact OpenSSL configuration file reproducing all parameters for offline CLI use.
   - **PKCS#12 (`.p12` / `.pfx`) Bundles**: Package private keys and certificates into password-protected bundles for Windows Server / IIS, Azure Key Vault, and Java Tomcat.
   - **Let's Encrypt / Certbot & ACME Commands**: Generates ready-to-run `certbot certonly --csr request.csr` commands for automated renewal.
   - **Self-Verification**: Decodes the generated CSR and executes cryptographic self-signature verification (`req.verify()`) with side-by-side comparison.

---

## Quick Start

### 🌐 Live Hosted Web App (Zero Install)
Click and run CSRGen directly in your browser:  
👉 **[https://cwmoriarty.github.io/csrgen/](https://cwmoriarty.github.io/csrgen/)** (or [cwmoriarty.com/csrgen](https://cwmoriarty.com/csrgen/))

### Standalone (Offline / Air-Gapped)
Open [`index.html`](index.html) directly in any web browser. File uploads, PEM pasting, key generation, and CSR downloads work 100% offline.

### Companion Server (Live HTTPS Inspection)
```bash
npm start
```
Navigate to **http://localhost:3000** in your browser.
