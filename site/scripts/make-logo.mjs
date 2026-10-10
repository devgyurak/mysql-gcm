// Draws the header wordmark from the banner's own type: "MySQL-GCM" in IBM Plex Sans Bold with
// the banner's -0.035em tracking (Claude Design "README Banner", 1a Dark). The glyphs are
// written as outlines, so the logo looks the same before, after and without the web font.
// Run once after a font or wording change; the SVGs in src/assets are committed.
import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import opentype from "opentype.js";

const SITE = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const FONT = path.join(SITE, "node_modules/@fontsource/ibm-plex-sans/files/ibm-plex-sans-latin-700-normal.woff");
const TEXT = "MySQL-GCM";
const SIZE = 100;          // font units are scaled to this many px per em
const TRACKING = -0.035;   // em, as in the banner
const COLOURS = { dark: "#e9ebec", light: "#16191b" };

const buf = await readFile(FONT);
const font = opentype.parse(buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength));
const scale = SIZE / font.unitsPerEm;
const glyphs = font.stringToGlyphs(TEXT);

let x = 0;
const commands = [];
glyphs.forEach((glyph, i) => {
  commands.push(...glyph.getPath(x, SIZE, SIZE).commands);
  const kern = i + 1 < glyphs.length ? font.getKerningValue(glyph, glyphs[i + 1]) : 0;
  x += (glyph.advanceWidth + kern) * scale + TRACKING * SIZE;
});
const p = new opentype.Path();
p.commands = commands;
const box = p.getBoundingBox();
const pad = 2;
const vb = [box.x1 - pad, box.y1 - pad, box.x2 - box.x1 + 2 * pad, box.y2 - box.y1 + 2 * pad].map((n) => +n.toFixed(2));
// Serialised here rather than with Path.toPathData, which in opentype.js 2.0.0 flips the y axis by
// default and emits NaN coordinates once its optimiser runs.
const n = (v) => +v.toFixed(2);
const d = commands
  .map((c) => {
    switch (c.type) {
      case "M":
      case "L":
        return `${c.type}${n(c.x)} ${n(c.y)}`;
      case "Q":
        return `Q${n(c.x1)} ${n(c.y1)} ${n(c.x)} ${n(c.y)}`;
      case "C":
        return `C${n(c.x1)} ${n(c.y1)} ${n(c.x2)} ${n(c.y2)} ${n(c.x)} ${n(c.y)}`;
      case "Z":
        return "Z";
      default:
        throw new Error(`unexpected path command ${c.type}`);
    }
  })
  .join("");

for (const [mode, fill] of Object.entries(COLOURS)) {
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="${vb.join(" ")}" role="img" aria-label="MySQL-GCM"><path fill="${fill}" d="${d}"/></svg>\n`;
  await writeFile(path.join(SITE, `src/assets/logo-${mode}.svg`), svg);
}
console.log(`wrote src/assets/logo-{dark,light}.svg, viewBox ${vb.join(" ")}`);
