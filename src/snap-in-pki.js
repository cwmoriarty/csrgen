import * as pkijs from "pkijs";
import * as asn1js from "asn1js";
import forge from "node-forge";

// Common OID mapping
export const OID_MAP = {
  // Subject attributes
  "2.5.4.3": { short: "CN", name: "Common Name" },
  "2.5.4.6": { short: "C", name: "Country" },
  "2.5.4.7": { short: "L", name: "Locality / City" },
  "2.5.4.8": { short: "ST", name: "State / Province" },
  "2.5.4.9": { short: "STREET", name: "Street Address" },
  "2.5.4.10": { short: "O", name: "Organization" },
  "2.5.4.11": { short: "OU", name: "Organizational Unit" },
  "2.5.4.12": { short: "TITLE", name: "Title" },
  "2.5.4.17": { short: "POSTALCODE", name: "Postal Code" },
  "2.5.4.5": { short: "SERIALNUMBER", name: "Serial Number" },
  "1.2.840.113549.1.9.1": { short: "EMAIL", name: "Email Address" },
  "0.9.2342.19200300.100.1.25": { short: "DC", name: "Domain Component" },

  // Key algorithms
  "1.2.840.113549.1.1.1": { name: "RSA" },
  "1.2.840.10045.2.1": { name: "ECDSA" },
  "1.3.101.112": { name: "ED25519", hash: "Ed25519" },

  // Post-Quantum ML-DSA (NIST FIPS 204)
  "2.16.840.1.101.3.4.3.17": { name: "ML-DSA-44", hash: "Pure" },
  "2.16.840.1.101.3.4.3.18": { name: "ML-DSA-65", hash: "Pure" },
  "2.16.840.1.101.3.4.3.19": { name: "ML-DSA-87", hash: "Pure" },

  // EC Curves
  "1.2.840.10045.3.1.7": { name: "P-256", alias: "prime256v1 / secp256r1" },
  "1.3.132.0.34": { name: "P-384", alias: "secp384r1" },
  "1.3.132.0.35": { name: "P-521", alias: "secp521r1" },

  // Signature algorithms
  "1.2.840.113549.1.1.5": { name: "SHA-1 with RSA", hash: "SHA-1" },
  "1.2.840.113549.1.1.11": { name: "SHA-256 with RSA", hash: "SHA-256" },
  "1.2.840.113549.1.1.12": { name: "SHA-384 with RSA", hash: "SHA-384" },
  "1.2.840.113549.1.1.13": { name: "SHA-512 with RSA", hash: "SHA-512" },
  "1.2.840.10045.4.1": { name: "SHA-1 with ECDSA", hash: "SHA-1" },
  "1.2.840.10045.4.3.2": { name: "SHA-256 with ECDSA", hash: "SHA-256" },
  "1.2.840.10045.4.3.3": { name: "SHA-384 with ECDSA", hash: "SHA-384" },
  "1.2.840.10045.4.3.4": { name: "SHA-512 with ECDSA", hash: "SHA-512" },

  // EKUs
  "1.3.6.1.5.5.7.3.1": { id: "serverAuth", name: "TLS Web Server Authentication" },
  "1.3.6.1.5.5.7.3.2": { id: "clientAuth", name: "TLS Web Client Authentication" },
  "1.3.6.1.5.5.7.3.3": { id: "codeSigning", name: "Code Signing" },
  "1.3.6.1.5.5.7.3.4": { id: "emailProtection", name: "E-mail Protection (S/MIME)" },
  "1.3.6.1.5.5.7.3.8": { id: "timeStamping", name: "Time Stamping" },
  "1.3.6.1.5.5.7.3.9": { id: "ocspSigning", name: "OCSP Signing" }
};

export function initCrypto() {
  const cryptoObj = typeof window !== "undefined" ? window.crypto : (typeof globalThis !== "undefined" ? globalThis.crypto : null);
  if (!cryptoObj || !cryptoObj.subtle) {
    throw new Error("WebCrypto Subtle API is not available in this environment.");
  }
  pkijs.setEngine("crypto", new pkijs.CryptoEngine({
    name: "crypto",
    crypto: cryptoObj,
    subtle: cryptoObj.subtle
  }));
}

// Format array buffer to PEM
export function toPem(derBuffer, header) {
  const bytes = new Uint8Array(derBuffer);
  let binary = "";
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  const base64 = btoa(binary);
  const formatted = base64.match(/.{1,64}/g)?.join("\n") || "";
  return `-----BEGIN ${header}-----\n${formatted}\n-----END ${header}-----\n`;
}

// Convert PEM or binary to ArrayBuffer
export function pemToArrayBuffer(input) {
  if (input instanceof ArrayBuffer) return input;
  if (ArrayBuffer.isView(input)) {
    return input.buffer.slice(input.byteOffset, input.byteOffset + input.byteLength);
  }
  if (typeof input !== "string") {
    throw new Error("Invalid input type: expected string or ArrayBuffer");
  }

  const trimmed = input.trim();
  const base64 = trimmed
    .replace(/-----BEGIN [^-]+-----/g, "")
    .replace(/-----END [^-]+-----/g, "")
    .replace(/\s+/g, "");

  const binaryString = atob(base64);
  const len = binaryString.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes.buffer;
}

// Helper: format IP bytes
export function ipBytesToString(u8) {
  if (u8.length === 4) {
    return Array.from(u8).join(".");
  } else if (u8.length === 16) {
    const parts = [];
    for (let i = 0; i < 16; i += 2) {
      parts.push(((u8[i] << 8) | u8[i + 1]).toString(16));
    }
    return parts.join(":");
  }
  return "";
}

// Helper: parse IP string to Uint8Array
export function ipStringToBytes(ip) {
  const str = ip.trim();
  if (str.includes(".")) {
    const parts = str.split(".").map(x => parseInt(x, 10));
    if (parts.length === 4 && parts.every(n => !isNaN(n) && n >= 0 && n <= 255)) {
      return new Uint8Array(parts);
    }
  }
  if (str.includes(":")) {
    const parts = str.toLowerCase().split("::");
    let head = parts[0] ? parts[0].split(":") : [];
    let tail = parts[1] ? parts[1].split(":") : [];
    if (parts.length > 2) return null;
    let missing = 8 - (head.length + tail.length);
    let full = parts.length === 2 ? [...head, ...Array(missing).fill("0"), ...tail] : head;
    if (full.length !== 8) return null;
    const buf = new Uint8Array(16);
    for (let i = 0; i < 8; i++) {
      const val = parseInt(full[i] || "0", 16);
      buf[i * 2] = (val >> 8) & 0xff;
      buf[i * 2 + 1] = val & 0xff;
    }
    return buf;
  }
  return null;
}

// Parse Certificate and extract matching parameters
export function parseCertificate(input) {
  initCrypto();
  const ab = pemToArrayBuffer(input);
  const asn1 = asn1js.fromBER(ab);
  if (asn1.offset === -1) {
    throw new Error("Unable to parse ASN.1 data. Ensure the certificate is valid PEM or DER.");
  }
  const cert = new pkijs.Certificate({ schema: asn1.result });

  // 1. Subject extraction
  const subjectList = [];
  const subjectMap = {};
  if (cert.subject && cert.subject.typesAndValues) {
    for (const tv of cert.subject.typesAndValues) {
      const oid = tv.type;
      const info = OID_MAP[oid] || { short: oid, name: oid };
      let val = "";
      if (tv.value && tv.value.valueBlock && typeof tv.value.valueBlock.value === "string") {
        val = tv.value.valueBlock.value;
      }
      subjectList.push({
        oid,
        short: info.short,
        name: info.name,
        value: val
      });
      if (info.short && !subjectMap[info.short]) {
        subjectMap[info.short] = val;
      }
    }
  }

  // 2. Public Key & Cipher parameters
  const spkiAlg = cert.subjectPublicKeyInfo.algorithm.algorithmId;
  let keyType = "UNKNOWN";
  let keySize = null;
  let ecCurve = null;
  let ecCurveAlias = null;

  if (spkiAlg === "1.2.840.113549.1.1.1") {
    keyType = "RSA";
    try {
      const rsaAsn1 = asn1js.fromBER(cert.subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHexView);
      const rsaPubKey = new pkijs.RSAPublicKey({ schema: rsaAsn1.result });
      const view = new Uint8Array(rsaPubKey.modulus.valueBlock.valueHexView);
      let start = 0;
      while (start < view.length && view[start] === 0) start++;
      keySize = (view.length - start) * 8;
    } catch (e) {
      console.warn("Could not parse RSA public key bits", e);
    }
  } else if (spkiAlg === "1.2.840.10045.2.1") {
    keyType = "ECDSA";
    const params = cert.subjectPublicKeyInfo.algorithm.algorithmParams;
    if (params && params.valueBlock) {
      const curveOid = params.valueBlock.toString();
      const curveInfo = OID_MAP[curveOid];
      if (curveInfo) {
        ecCurve = curveInfo.name;
        ecCurveAlias = curveInfo.alias;
      } else {
        ecCurve = curveOid;
      }
    }
  } else if (spkiAlg === "1.3.101.112") {
    keyType = "ED25519";
    ecCurve = "Ed25519";
  } else if (spkiAlg === "2.16.840.1.101.3.4.3.17") {
    keyType = "ML-DSA-44";
  } else if (spkiAlg === "2.16.840.1.101.3.4.3.18") {
    keyType = "ML-DSA-65";
  } else if (spkiAlg === "2.16.840.1.101.3.4.3.19") {
    keyType = "ML-DSA-87";
  }

  // 3. Signature & Hash algorithm
  const sigAlgOid = cert.signatureAlgorithm.algorithmId;
  const sigInfo = OID_MAP[sigAlgOid] || { name: sigAlgOid, hash: "SHA-256" };
  const signatureHash = sigInfo.hash || "SHA-256";

  // 4. Extensions: SAN, KeyUsage, EKU, BasicConstraints
  const sanList = [];
  const keyUsageFlags = {
    digitalSignature: false,
    nonRepudiation: false,
    keyEncipherment: false,
    dataEncipherment: false,
    keyAgreement: false,
    keyCertSign: false,
    cRLSign: false
  };
  let hasKeyUsage = false;
  const ekuList = [];
  let basicConstraints = null;

  if (cert.extensions) {
    for (const ext of cert.extensions) {
      // SAN (2.5.29.17)
      if (ext.extnID === "2.5.29.17") {
        try {
          const sanAsn1 = asn1js.fromBER(ext.extnValue.valueBlock.valueHexView);
          const generalNames = new pkijs.GeneralNames({ schema: sanAsn1.result });
          for (const item of generalNames.names) {
            if (item.type === 2) {
              sanList.push({ type: "dns", value: item.value });
            } else if (item.type === 7) {
              const u8 = new Uint8Array(item.value.valueBlock.valueHexView);
              const ipStr = ipBytesToString(u8);
              if (ipStr) sanList.push({ type: "ip", value: ipStr });
            } else if (item.type === 1) {
              sanList.push({ type: "email", value: item.value });
            } else if (item.type === 6) {
              sanList.push({ type: "uri", value: item.value });
            }
          }
        } catch (e) {
          console.warn("Error parsing SAN extension", e);
        }
      }

      // Key Usage (2.5.29.15)
      if (ext.extnID === "2.5.29.15") {
        try {
          hasKeyUsage = true;
          const kuAsn1 = asn1js.fromBER(ext.extnValue.valueBlock.valueHexView);
          const u8 = new Uint8Array(kuAsn1.result.valueBlock.valueHexView);
          if (u8.length > 0) {
            keyUsageFlags.digitalSignature = (u8[0] & 0x80) !== 0;
            keyUsageFlags.nonRepudiation = (u8[0] & 0x40) !== 0;
            keyUsageFlags.keyEncipherment = (u8[0] & 0x20) !== 0;
            keyUsageFlags.dataEncipherment = (u8[0] & 0x10) !== 0;
            keyUsageFlags.keyAgreement = (u8[0] & 0x08) !== 0;
            keyUsageFlags.keyCertSign = (u8[0] & 0x04) !== 0;
            keyUsageFlags.cRLSign = (u8[0] & 0x02) !== 0;
          }
        } catch (e) {
          console.warn("Error parsing Key Usage extension", e);
        }
      }

      // Extended Key Usage (2.5.29.37)
      if (ext.extnID === "2.5.29.37") {
        try {
          const ekuAsn1 = asn1js.fromBER(ext.extnValue.valueBlock.valueHexView);
          const eku = new pkijs.ExtKeyUsage({ schema: ekuAsn1.result });
          for (const purpose of eku.keyPurposes) {
            const info = OID_MAP[purpose] || { id: purpose, name: purpose };
            ekuList.push({ oid: purpose, id: info.id || purpose, name: info.name });
          }
        } catch (e) {
          console.warn("Error parsing EKU extension", e);
        }
      }

      // Basic Constraints (2.5.29.19)
      if (ext.extnID === "2.5.29.19") {
        try {
          const bcAsn1 = asn1js.fromBER(ext.extnValue.valueBlock.valueHexView);
          const bc = new pkijs.BasicConstraints({ schema: bcAsn1.result });
          basicConstraints = {
            cA: bc.cA,
            pathLen: bc.pathLenConstraint
          };
        } catch (e) {
          console.warn("Error parsing Basic Constraints", e);
        }
      }
    }
  }

  // 5. Validity Dates & Serial Number
  const notBefore = cert.notBefore ? cert.notBefore.value : null;
  const notAfter = cert.notAfter ? cert.notAfter.value : null;
  const now = new Date();
  const isExpired = notAfter ? now > notAfter : false;
  const daysRemaining = notAfter ? Math.round((notAfter - now) / (1000 * 60 * 60 * 24)) : null;

  let serialHex = "";
  if (cert.serialNumber && cert.serialNumber.valueBlock && cert.serialNumber.valueBlock.valueHexView) {
    const bytes = new Uint8Array(cert.serialNumber.valueBlock.valueHexView);
    serialHex = Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join(":");
  }

  // Issuer summary
  let issuerCN = "";
  let issuerO = "";
  if (cert.issuer && cert.issuer.typesAndValues) {
    for (const tv of cert.issuer.typesAndValues) {
      if (tv.type === "2.5.4.3") issuerCN = tv.value.valueBlock.value;
      if (tv.type === "2.5.4.10") issuerO = tv.value.valueBlock.value;
    }
  }

  return {
    rawCert: cert,
    subjectList,
    subjectMap,
    keyType,
    keySize,
    ecCurve,
    ecCurveAlias,
    signatureAlgorithm: sigInfo.name,
    signatureHash,
    sanList,
    hasKeyUsage,
    keyUsageFlags,
    ekuList,
    basicConstraints,
    notBefore,
    notAfter,
    isExpired,
    daysRemaining,
    serialHex,
    issuerSummary: issuerO ? `${issuerO} (${issuerCN || "CA"})` : (issuerCN || "Unknown Issuer")
  };
}

// Build standard RDN Sequence of Sets
function createStandardRDN(attributes) {
  const seq = new asn1js.Sequence({
    value: attributes.map(attr => new asn1js.Set({
      value: [attr.toSchema()]
    }))
  });
  return new pkijs.RelativeDistinguishedNames({ schema: asn1js.fromBER(seq.toBER(false)).result });
}

// Generate CSR & Private Key matching the input parameters
export async function generateSnapInCSR(options) {
  initCrypto();
  const cryptoObj = typeof window !== "undefined" ? window.crypto : globalThis.crypto;

  const {
    keyType, // "RSA", "ECDSA", "ED25519"
    keySize, // 2048, 3072, 4096
    ecCurve, // "P-256", "P-384", "P-521", "Ed25519"
    hashAlgorithm = "SHA-256",
    subjectAttributes = [],
    sanList = [],
    includeSAN = true,
    includeKeyUsage = false,
    keyUsages = [],
    includeEKU = false,
    ekus = [],
    includeBasicConstraints = false
  } = options;

  // Assemble Subject DN
  const rdnAttrs = [];
  for (const item of subjectAttributes) {
    if (!item.value || !item.value.trim()) continue;
    const val = item.value.trim();
    let asnVal;
    if (item.oid === "2.5.4.6") {
      asnVal = new asn1js.PrintableString({ value: val.toUpperCase() });
    } else {
      asnVal = new asn1js.Utf8String({ value: val });
    }
    rdnAttrs.push(new pkijs.AttributeTypeAndValue({
      type: item.oid,
      value: asnVal
    }));
  }

  if (rdnAttrs.length === 0) {
    throw new Error("Subject DN must contain at least a Common Name (CN).");
  }

  // Assemble Requested Extensions
  const extensions = [];

  // SAN Extension
  if (includeSAN && sanList.length > 0) {
    const generalNames = [];
    for (const item of sanList) {
      const val = item.value.trim();
      if (!val) continue;
      if (item.type === "dns") {
        generalNames.push(new pkijs.GeneralName({ type: 2, value: val }));
      } else if (item.type === "ip") {
        const ipBytes = ipStringToBytes(val);
        if (ipBytes) {
          generalNames.push(new pkijs.GeneralName({
            type: 7,
            value: new asn1js.OctetString({ valueHex: ipBytes.buffer })
          }));
        }
      } else if (item.type === "email") {
        generalNames.push(new pkijs.GeneralName({ type: 1, value: val }));
      } else if (item.type === "uri") {
        generalNames.push(new pkijs.GeneralName({ type: 6, value: val }));
      }
    }

    if (generalNames.length > 0) {
      const altNames = new pkijs.GeneralNames({ names: generalNames });
      extensions.push(new pkijs.Extension({
        extnID: "2.5.29.17",
        critical: false,
        extnValue: altNames.toSchema().toBER(false)
      }));
    }
  }

  // Key Usage Extension
  if (includeKeyUsage && keyUsages.length > 0) {
    const bitMap = {
      digitalSignature: 0,
      nonRepudiation: 1,
      keyEncipherment: 2,
      dataEncipherment: 3,
      keyAgreement: 4,
      keyCertSign: 5,
      cRLSign: 6,
      encipherOnly: 7,
      decipherOnly: 8
    };

    const bits = keyUsages.map(name => bitMap[name]).filter(b => b !== undefined);
    if (bits.length > 0) {
      let maxBit = Math.max(...bits);
      let numBytes = Math.ceil((maxBit + 1) / 8);
      const bytes = new Uint8Array(numBytes);
      for (const bit of bits) {
        const byteIndex = Math.floor(bit / 8);
        const bitIndex = 7 - (bit % 8);
        bytes[byteIndex] |= (1 << bitIndex);
      }
      const unusedBits = (numBytes * 8) - (maxBit + 1);

      const bitString = new asn1js.BitString({
        unusedBits: unusedBits,
        valueHex: bytes.buffer
      });

      extensions.push(new pkijs.Extension({
        extnID: "2.5.29.15",
        critical: false,
        extnValue: bitString.toBER(false)
      }));
    }
  }

  // Extended Key Usage Extension
  if (includeEKU && ekus.length > 0) {
    const eku = new pkijs.ExtKeyUsage({ keyPurposes: ekus });
    extensions.push(new pkijs.Extension({
      extnID: "2.5.29.37",
      critical: false,
      extnValue: eku.toSchema().toBER(false)
    }));
  }

  // Basic Constraints Extension
  if (includeBasicConstraints) {
    const bc = new pkijs.BasicConstraints({ cA: false });
    extensions.push(new pkijs.Extension({
      extnID: "2.5.29.19",
      critical: false,
      extnValue: bc.toSchema().toBER(false)
    }));
  }

  // --- Handling Ed25519 Curve ---
  if (keyType === "ED25519" || keyType === "Ed25519") {
    const keyPair = await cryptoObj.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
    const spki = await cryptoObj.subtle.exportKey("spki", keyPair.publicKey);

    const pkcs10 = new pkijs.CertificationRequest();
    pkcs10.version = 0;
    pkcs10.subjectPublicKeyInfo = new pkijs.PublicKeyInfo({ schema: asn1js.fromBER(spki).result });
    pkcs10.subject = createStandardRDN(rdnAttrs);

    if (extensions.length > 0) {
      pkcs10.attributes = [
        new pkijs.Attribute({
          type: "1.2.840.113549.1.9.14",
          values: [new pkijs.Extensions({ extensions }).toSchema()]
        })
      ];
    }

    const algId = new pkijs.AlgorithmIdentifier({ algorithmId: "1.3.101.112" });
    pkcs10.signatureAlgorithm = algId;
    pkcs10.signature = algId;

    const tbsBytes = new Uint8Array(pkcs10.encodeTBS().toBER(false));
    pkcs10.tbsView = tbsBytes;

    const sig = await cryptoObj.subtle.sign({ name: "Ed25519" }, keyPair.privateKey, tbsBytes);
    pkcs10.signatureValue = new asn1js.BitString({ valueHex: sig });

    const csrDer = pkcs10.toSchema().toBER(false);
    const csrPem = toPem(csrDer, "CERTIFICATE REQUEST");
    const privDer = await cryptoObj.subtle.exportKey("pkcs8", keyPair.privateKey);
    const privateKeyPem = toPem(privDer, "PRIVATE KEY");

    return {
      csrPem,
      privateKeyPem,
      keyType: "ED25519",
      keySize: 256,
      ecCurve: "Ed25519",
      hashAlgorithm: "Ed25519",
      extensionsCount: extensions.length
    };
  }

  // --- Handling RSA & ECDSA ---
  let keyGenParams;
  if (keyType === "RSA") {
    keyGenParams = {
      name: "RSASSA-PKCS1-v1_5",
      modulusLength: parseInt(keySize, 10) || 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: hashAlgorithm
    };
  } else if (keyType === "ECDSA") {
    keyGenParams = {
      name: "ECDSA",
      namedCurve: ecCurve || "P-256"
    };
  } else {
    throw new Error(`Unsupported key algorithm: ${keyType}`);
  }

  const keyPair = await cryptoObj.subtle.generateKey(keyGenParams, true, ["sign", "verify"]);

  const pkcs10 = new pkijs.CertificationRequest();
  pkcs10.version = 0;
  pkcs10.subject = createStandardRDN(rdnAttrs);

  if (extensions.length > 0) {
    pkcs10.attributes = [
      new pkijs.Attribute({
        type: "1.2.840.113549.1.9.14",
        values: [new pkijs.Extensions({ extensions }).toSchema()]
      })
    ];
  }

  await pkcs10.subjectPublicKeyInfo.importKey(keyPair.publicKey);
  await pkcs10.sign(keyPair.privateKey, hashAlgorithm);

  const csrDer = pkcs10.toSchema().toBER(false);
  const csrPem = toPem(csrDer, "CERTIFICATE REQUEST");
  const privDer = await cryptoObj.subtle.exportKey("pkcs8", keyPair.privateKey);
  const privateKeyPem = toPem(privDer, "PRIVATE KEY");

  return {
    csrPem,
    privateKeyPem,
    keyType,
    keySize: keyType === "RSA" ? keySize : null,
    ecCurve: keyType === "ECDSA" ? ecCurve : null,
    hashAlgorithm,
    extensionsCount: extensions.length
  };
}

// Parse and decode a CSR
export async function parseCSR(input) {
  initCrypto();
  const cryptoObj = typeof window !== "undefined" ? window.crypto : globalThis.crypto;
  const ab = pemToArrayBuffer(input);
  const asn1 = asn1js.fromBER(ab);
  if (asn1.offset === -1) {
    throw new Error("Unable to parse CSR ASN.1 structure.");
  }
  const req = new pkijs.CertificationRequest({ schema: asn1.result });
  let signatureValid = false;

  // Subject
  const subjectList = [];
  const subjectMap = {};
  if (req.subject && req.subject.typesAndValues) {
    for (const tv of req.subject.typesAndValues) {
      const oid = tv.type;
      const info = OID_MAP[oid] || { short: oid, name: oid };
      let val = "";
      if (tv.value && tv.value.valueBlock && typeof tv.value.valueBlock.value === "string") {
        val = tv.value.valueBlock.value;
      }
      subjectList.push({
        oid,
        short: info.short,
        name: info.name,
        value: val
      });
      if (info.short && !subjectMap[info.short]) {
        subjectMap[info.short] = val;
      }
    }
  }

  // Public key
  const spkiAlg = req.subjectPublicKeyInfo.algorithm.algorithmId;
  let keyType = "UNKNOWN";
  let keySize = null;
  let ecCurve = null;

  if (spkiAlg === "1.2.840.113549.1.1.1") {
    keyType = "RSA";
    try {
      const rsaAsn1 = asn1js.fromBER(req.subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHexView);
      const rsaPubKey = new pkijs.RSAPublicKey({ schema: rsaAsn1.result });
      const view = new Uint8Array(rsaPubKey.modulus.valueBlock.valueHexView);
      let start = 0;
      while (start < view.length && view[start] === 0) start++;
      keySize = (view.length - start) * 8;
    } catch (e) {
      console.warn("Could not parse RSA key bits in CSR", e);
    }
    try {
      signatureValid = await req.verify();
    } catch (e) {}
  } else if (spkiAlg === "1.2.840.10045.2.1") {
    keyType = "ECDSA";
    const params = req.subjectPublicKeyInfo.algorithm.algorithmParams;
    if (params && params.valueBlock) {
      const curveOid = params.valueBlock.toString();
      const curveInfo = OID_MAP[curveOid];
      ecCurve = curveInfo ? curveInfo.name : curveOid;
    }
    try {
      signatureValid = await req.verify();
    } catch (e) {}
  } else if (spkiAlg === "1.3.101.112") {
    keyType = "ED25519";
    ecCurve = "Ed25519";
    try {
      const spkiDer = req.subjectPublicKeyInfo.toSchema().toBER(false);
      const pubKey = await cryptoObj.subtle.importKey("spki", spkiDer, { name: "Ed25519" }, false, ["verify"]);
      signatureValid = await cryptoObj.subtle.verify({ name: "Ed25519" }, pubKey, req.signatureValue.valueBlock.valueHexView, req.tbsView);
    } catch (e) {
      console.warn("Ed25519 verify error:", e);
    }
  } else if (spkiAlg.startsWith("2.16.840.1.101.3.4.3.")) {
    const pqcMap = {
      "2.16.840.1.101.3.4.3.17": "ML-DSA-44",
      "2.16.840.1.101.3.4.3.18": "ML-DSA-65",
      "2.16.840.1.101.3.4.3.19": "ML-DSA-87"
    };
    keyType = pqcMap[spkiAlg] || "ML-DSA";
    signatureValid = true;
  }

  // Extensions
  const sanList = [];
  const ekuList = [];
  let hasKeyUsage = false;
  const keyUsageFlags = {};

  if (req.attributes) {
    for (const attr of req.attributes) {
      if (attr.type === "1.2.840.113549.1.9.14" && attr.values && attr.values.length > 0) {
        try {
          const exts = new pkijs.Extensions({ schema: attr.values[0] });
          for (const ext of (exts.extensions || [])) {
            if (ext.extnID === "2.5.29.17") {
              const sanAsn1 = asn1js.fromBER(ext.extnValue.valueBlock.valueHexView);
              const generalNames = new pkijs.GeneralNames({ schema: sanAsn1.result });
              for (const item of generalNames.names) {
                if (item.type === 2) sanList.push({ type: "dns", value: item.value });
                else if (item.type === 7) {
                  const u8 = new Uint8Array(item.value.valueBlock.valueHexView);
                  const ip = ipBytesToString(u8);
                  if (ip) sanList.push({ type: "ip", value: ip });
                } else if (item.type === 1) sanList.push({ type: "email", value: item.value });
                else if (item.type === 6) sanList.push({ type: "uri", value: item.value });
              }
            } else if (ext.extnID === "2.5.29.37") {
              const ekuAsn1 = asn1js.fromBER(ext.extnValue.valueBlock.valueHexView);
              const eku = new pkijs.ExtKeyUsage({ schema: ekuAsn1.result });
              for (const p of eku.keyPurposes) {
                const info = OID_MAP[p] || { id: p, name: p };
                ekuList.push({ oid: p, id: info.id || p, name: info.name });
              }
            } else if (ext.extnID === "2.5.29.15") {
              hasKeyUsage = true;
              const kuAsn1 = asn1js.fromBER(ext.extnValue.valueBlock.valueHexView);
              const u8 = new Uint8Array(kuAsn1.result.valueBlock.valueHexView);
              if (u8.length > 0) {
                keyUsageFlags.digitalSignature = (u8[0] & 0x80) !== 0;
                keyUsageFlags.nonRepudiation = (u8[0] & 0x40) !== 0;
                keyUsageFlags.keyEncipherment = (u8[0] & 0x20) !== 0;
                keyUsageFlags.dataEncipherment = (u8[0] & 0x10) !== 0;
                keyUsageFlags.keyAgreement = (u8[0] & 0x08) !== 0;
                keyUsageFlags.keyCertSign = (u8[0] & 0x04) !== 0;
                keyUsageFlags.cRLSign = (u8[0] & 0x02) !== 0;
              }
            }
          }
        } catch (e) {
          console.warn("Error decoding extensions from CSR", e);
        }
      }
    }
  }

  return {
    signatureValid,
    subjectList,
    subjectMap,
    keyType,
    keySize,
    ecCurve,
    sanList,
    hasKeyUsage,
    keyUsageFlags,
    ekuList
  };
}

// Generate OpenSSL Configuration (req.cnf)
export function generateOpenSSLConfig(options) {
  const {
    keyType = "RSA",
    keySize = 2048,
    hashAlgorithm = "SHA-256",
    subjectAttributes = [],
    sanList = []
  } = options;

  let defaultMd = hashAlgorithm.toLowerCase().replace("-", "");
  if (keyType === "ED25519" || keyType.startsWith("MLDSA") || keyType.startsWith("ML-DSA")) {
    defaultMd = "default";
  }

  const lines = [
    "# OpenSSL configuration generated for exact snap-in replacement",
    "[ req ]",
    `default_bits       = ${keySize || 2048}`,
    "prompt             = no",
    `default_md         = ${defaultMd}`,
    "distinguished_name = req_distinguished_name"
  ];

  if (sanList && sanList.length > 0) {
    lines.push("req_extensions     = req_ext");
  }

  lines.push("", "[ req_distinguished_name ]");

  const attrMap = {
    "2.5.4.6": "C",
    "2.5.4.8": "ST",
    "2.5.4.7": "L",
    "2.5.4.10": "O",
    "2.5.4.11": "OU",
    "2.5.4.3": "CN",
    "1.2.840.113549.1.9.1": "emailAddress"
  };

  for (const attr of subjectAttributes) {
    if (!attr.value || !attr.value.trim()) continue;
    const shortName = attrMap[attr.oid] || attr.short || "CN";
    lines.push(`${shortName.padEnd(18)} = ${attr.value.trim()}`);
  }

  if (sanList && sanList.length > 0) {
    lines.push("", "[ req_ext ]", "subjectAltName     = @alt_names", "", "[ alt_names ]");
    let dnsCount = 1, ipCount = 1, emailCount = 1, uriCount = 1;
    for (const item of sanList) {
      if (!item.value || !item.value.trim()) continue;
      const val = item.value.trim();
      if (item.type === "dns") {
        lines.push(`DNS.${dnsCount++}`.padEnd(18) + ` = ${val}`);
      } else if (item.type === "ip") {
        lines.push(`IP.${ipCount++}`.padEnd(18) + ` = ${val}`);
      } else if (item.type === "email") {
        lines.push(`email.${emailCount++}`.padEnd(18) + ` = ${val}`);
      } else if (item.type === "uri") {
        lines.push(`URI.${uriCount++}`.padEnd(18) + ` = ${val}`);
      }
    }
  }

  return lines.join("\n") + "\n";
}

// Generate Certbot / ACME commands
export function generateCertbotCommands(filename = "request.csr") {
  return [
    `# 1. Let's Encrypt / Certbot automated renewal (Webroot mode)`,
    `certbot certonly --webroot -w /var/www/html --csr ${filename}`,
    ``,
    `# 2. Let's Encrypt / Certbot DNS TXT manual verification`,
    `certbot certonly --manual --preferred-challenges dns --csr ${filename}`,
    ``,
    `# 3. Let's Encrypt / Certbot Standalone mode (temporary port 80 listener)`,
    `certbot certonly --standalone --csr ${filename}`,
    ``,
    `# 4. ACME.sh automated renewal with existing CSR`,
    `acme.sh --sign-csr --csr ${filename}`
  ].join("\n");
}

// Client-side PKCS#12 export for RSA keys (via node-forge)
export function exportPKCS12Client(keyPem, certPem, password = "", friendlyName = "certificate") {
  try {
    const pkiKey = forge.pki.privateKeyFromPem(keyPem);
    const pkiCert = forge.pki.certificateFromPem(certPem);
    const p12Asn1 = forge.pkcs12.toPkcs12Asn1(pkiKey, [pkiCert], password, {
      generateLocalKeyId: true,
      friendlyName: friendlyName
    });
    const p12Der = forge.asn1.toDer(p12Asn1).getBytes();
    const len = p12Der.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
      bytes[i] = p12Der.charCodeAt(i);
    }
    return bytes.buffer;
  } catch (err) {
    throw new Error(err.message);
  }
}
