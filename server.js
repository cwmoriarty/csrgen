const http = require("http");
const tls = require("tls");
const fs = require("fs");
const path = require("path");
const { URL } = require("url");
const { execSync } = require("child_process");

const PORT = process.env.PORT || 3000;
const PUBLIC_DIR = path.join(__dirname, "public");

const MIME_TYPES = {
  ".html": "text/html; charset=utf-8",
  ".js": "application/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
  ".ico": "image/x-icon",
  ".png": "image/png",
  ".p12": "application/x-pkcs12",
  ".pfx": "application/x-pkcs12"
};

function fetchPeerCertificate(targetUrl) {
  return new Promise((resolve, reject) => {
    let hostname, port = 443;
    try {
      let str = targetUrl.trim();
      if (!str.startsWith("http://") && !str.startsWith("https://")) {
        str = "https://" + str;
      }
      const u = new URL(str);
      hostname = u.hostname;
      if (u.port) port = parseInt(u.port, 10);
    } catch (e) {
      return reject(new Error("Invalid URL or hostname: " + targetUrl));
    }

    if (!hostname) {
      return reject(new Error("Hostname cannot be empty"));
    }

    const socket = tls.connect({
      host: hostname,
      port: port,
      servername: hostname,
      rejectUnauthorized: false,
      timeout: 10000
    }, () => {
      try {
        const cert = socket.getPeerCertificate(true);
        if (!cert || !cert.raw) {
          socket.destroy();
          return reject(new Error("No certificate presented by server at " + hostname + ":" + port));
        }

        const pem = `-----BEGIN CERTIFICATE-----\n${cert.raw.toString("base64").match(/.{1,64}/g).join("\n")}\n-----END CERTIFICATE-----\n`;

        const chain = [pem];
        let current = cert;
        while (current.issuerCertificate && current.issuerCertificate !== current) {
          current = current.issuerCertificate;
          if (current.raw) {
            chain.push(`-----BEGIN CERTIFICATE-----\n${current.raw.toString("base64").match(/.{1,64}/g).join("\n")}\n-----END CERTIFICATE-----\n`);
          }
        }

        socket.end();
        resolve({
          host: hostname,
          port: port,
          subject: cert.subject,
          issuer: cert.issuer,
          valid_from: cert.valid_from,
          valid_to: cert.valid_to,
          fingerprint256: cert.fingerprint256,
          pem: pem,
          chain: chain
        });
      } catch (err) {
        socket.destroy();
        reject(err);
      }
    });

    socket.on("error", (err) => {
      reject(err);
    });

    socket.on("timeout", () => {
      socket.destroy();
      reject(new Error(`Connection to ${hostname}:${port} timed out after 10 seconds`));
    });
  });
}

function exportPKCS12Server(keyPem, certPem, password = "", friendlyName = "certificate") {
  const tmpKey = path.join("/tmp", `key_${Date.now()}_${Math.random().toString(36).substring(7)}.key`);
  const tmpCert = path.join("/tmp", `cert_${Date.now()}_${Math.random().toString(36).substring(7)}.crt`);
  const tmpP12 = path.join("/tmp", `p12_${Date.now()}_${Math.random().toString(36).substring(7)}.p12`);

  try {
    fs.writeFileSync(tmpKey, keyPem.trim() + "\n");
    fs.writeFileSync(tmpCert, certPem.trim() + "\n");
    execSync(`openssl pkcs12 -export -inkey "${tmpKey}" -in "${tmpCert}" -out "${tmpP12}" -name "${friendlyName}" -passout "pass:${password}"`);
    return fs.readFileSync(tmpP12);
  } finally {
    try { fs.unlinkSync(tmpKey); } catch (e) {}
    try { fs.unlinkSync(tmpCert); } catch (e) {}
    try { fs.unlinkSync(tmpP12); } catch (e) {}
  }
}

function generatePqcOpenSSL(alg, subjectAttributes = [], sanList = []) {
  const tmpCnf = path.join("/tmp", `pqc_${Date.now()}_${Math.random().toString(36).substring(7)}.cnf`);
  const tmpKey = path.join("/tmp", `pqc_${Date.now()}_${Math.random().toString(36).substring(7)}.key`);
  const tmpCsr = path.join("/tmp", `pqc_${Date.now()}_${Math.random().toString(36).substring(7)}.csr`);

  let cnf = `[ req ]\nprompt = no\ndistinguished_name = req_dn\n`;
  if (sanList && sanList.length > 0) {
    cnf += `req_extensions = req_ext\n[ req_ext ]\nsubjectAltName = @alt\n[ alt ]\n`;
    let dnsIdx = 1, ipIdx = 1;
    for (const item of sanList) {
      if (!item.value) continue;
      if (item.type === "dns") cnf += `DNS.${dnsIdx++} = ${item.value}\n`;
      else if (item.type === "ip") cnf += `IP.${ipIdx++} = ${item.value}\n`;
    }
  }

  cnf += `[ req_dn ]\n`;
  const attrMap = {
    "2.5.4.6": "C", "2.5.4.8": "ST", "2.5.4.7": "L",
    "2.5.4.10": "O", "2.5.4.11": "OU", "2.5.4.3": "CN"
  };
  for (const a of subjectAttributes) {
    if (!a.value) continue;
    const key = attrMap[a.oid] || a.short || "CN";
    cnf += `${key} = ${a.value}\n`;
  }

  try {
    fs.writeFileSync(tmpCnf, cnf);
    execSync(`openssl req -new -newkey ${alg} -keyout "${tmpKey}" -nodes -out "${tmpCsr}" -config "${tmpCnf}" 2>/dev/null`);
    const csrPem = fs.readFileSync(tmpCsr, "utf8");
    const keyPem = fs.readFileSync(tmpKey, "utf8");
    return { csrPem, keyPem };
  } finally {
    try { fs.unlinkSync(tmpCnf); } catch(e){}
    try { fs.unlinkSync(tmpKey); } catch(e){}
    try { fs.unlinkSync(tmpCsr); } catch(e){}
  }
}

const server = http.createServer((req, res) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");

  if (req.method === "OPTIONS") {
    res.writeHead(204);
    res.end();
    return;
  }

  const parsedUrl = new URL(req.url, `http://${req.headers.host || "localhost"}`);
  const pathname = parsedUrl.pathname;

  // API: Status
  if (pathname === "/api/status") {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ status: "ok", mode: "companion-server", port: PORT }));
    return;
  }

  // API: Fetch Certificate from live HTTPS URL
  if (pathname === "/api/fetch-cert") {
    const targetUrl = parsedUrl.searchParams.get("url");
    if (!targetUrl) {
      res.writeHead(400, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ success: false, error: "Missing 'url' parameter" }));
      return;
    }
    fetchPeerCertificate(targetUrl)
      .then(result => {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ success: true, ...result }));
      })
      .catch(err => {
        res.writeHead(500, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ success: false, error: err.message }));
      });
    return;
  }

  // API: PKCS#12 Export
  if (pathname === "/api/export-p12" && req.method === "POST") {
    let body = "";
    req.on("data", chunk => { body += chunk; });
    req.on("end", () => {
      try {
        const { keyPem, certPem, password, friendlyName } = JSON.parse(body || "{}");
        if (!keyPem || !certPem) {
          res.writeHead(400, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: "Missing keyPem or certPem" }));
          return;
        }
        const p12Buffer = exportPKCS12Server(keyPem, certPem, password || "", friendlyName || "certificate");
        res.writeHead(200, {
          "Content-Type": "application/x-pkcs12",
          "Content-Disposition": 'attachment; filename="bundle.p12"',
          "Content-Length": p12Buffer.length
        });
        res.end(p12Buffer);
      } catch (err) {
        res.writeHead(500, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: err.message }));
      }
    });
    return;
  }

  // API: Post-Quantum CSR Generation (OpenSSL 4.1)
  if (pathname === "/api/generate-pqc" && req.method === "POST") {
    let body = "";
    req.on("data", chunk => { body += chunk; });
    req.on("end", () => {
      try {
        const { algorithm, subjectAttributes, sanList } = JSON.parse(body || "{}");
        const validAlgs = ["mldsa44", "mldsa65", "mldsa87"];
        const alg = (algorithm || "").toLowerCase().replace(/[^a-z0-9]/g, "");
        if (!validAlgs.includes(alg)) {
          res.writeHead(400, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: "Unsupported PQC algorithm: " + algorithm }));
          return;
        }
        const result = generatePqcOpenSSL(alg, subjectAttributes, sanList);
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ success: true, ...result, keyType: alg.toUpperCase() }));
      } catch (err) {
        res.writeHead(500, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: err.message }));
      }
    });
    return;
  }

  // Static File Serving
  let filePath = path.join(PUBLIC_DIR, pathname === "/" ? "index.html" : pathname);
  if (!filePath.startsWith(PUBLIC_DIR)) {
    res.writeHead(403);
    res.end("Forbidden");
    return;
  }

  fs.stat(filePath, (err, stats) => {
    if (err || !stats.isFile()) {
      res.writeHead(404, { "Content-Type": "text/plain" });
      res.end("404 Not Found");
      return;
    }

    const ext = path.extname(filePath).toLowerCase();
    const contentType = MIME_TYPES[ext] || "application/octet-stream";
    res.writeHead(200, { "Content-Type": contentType });
    fs.createReadStream(filePath).pipe(res);
  });
});

if (require.main === module) {
  server.listen(PORT, () => {
    console.log(`\n======================================================`);
    console.log(` Snap-In CSR Generator running at http://localhost:${PORT}`);
    console.log(` Live HTTPS cert inspection available via /api/fetch-cert`);
    console.log(` PKCS#12 export available via /api/export-p12`);
    console.log(` Post-Quantum PQC (ML-DSA) available via /api/generate-pqc`);
    console.log(`======================================================\n`);
  });
}

module.exports = { server, fetchPeerCertificate, exportPKCS12Server, generatePqcOpenSSL };
