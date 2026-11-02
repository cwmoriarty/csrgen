const fs = require("fs");
const path = require("path");

const rootDir = path.join(__dirname, "..");
const publicDir = path.join(rootDir, "public");
const distDir = path.join(rootDir, "dist");

if (!fs.existsSync(distDir)) {
  fs.mkdirSync(distDir, { recursive: true });
}

// Read raw template from src or public
const templatePath = path.join(publicDir, "index.template.html");
const baseHtmlPath = fs.existsSync(templatePath) ? templatePath : path.join(publicDir, "index.html");
let html = fs.readFileSync(baseHtmlPath, "utf8");

// Save template if not already saved
if (!fs.existsSync(templatePath)) {
  fs.writeFileSync(templatePath, html, "utf8");
}

const css = fs.readFileSync(path.join(publicDir, "style.css"), "utf8");
const bundleJs = fs.readFileSync(path.join(publicDir, "snap-in-bundle.js"), "utf8");
const appJs = fs.readFileSync(path.join(publicDir, "app.js"), "utf8");

// Inline CSS
html = html.replace(
  '<link rel="stylesheet" href="style.css">',
  `<style>\n${css}\n</style>`
);

// Inline JS
html = html.replace(
  '<script src="snap-in-bundle.js"></script>',
  `<script>\n${bundleJs}\n</script>`
);

html = html.replace(
  '<script src="app.js"></script>',
  `<script>\n${appJs}\n</script>`
);

// Write standalone index.html at root of repo (for GitHub Pages / direct offline open)
fs.writeFileSync(path.join(rootDir, "index.html"), html, "utf8");

// Write to public/index.html (for server.js static serving)
fs.writeFileSync(path.join(publicDir, "index.html"), html, "utf8");

// Also keep dist/index.html and standalone.html
fs.writeFileSync(path.join(distDir, "index.html"), html, "utf8");
fs.writeFileSync(path.join(distDir, "standalone.html"), html, "utf8");
fs.writeFileSync(path.join(publicDir, "standalone.html"), html, "utf8");

console.log(`Standalone index.html generated successfully!`);
console.log(`Size: ${(html.length / 1024).toFixed(1)} KB`);
console.log(`Wrote: ${path.join(rootDir, "index.html")}`);
console.log(`Wrote: ${path.join(publicDir, "index.html")}`);
