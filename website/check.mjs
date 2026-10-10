import { readFile } from "node:fs/promises";
const data=JSON.parse(await readFile(new URL("./data/standard.json",import.meta.url)));
if(!Array.isArray(data.families)||!Array.isArray(data.profiles)||!Array.isArray(data.specifications))throw Error("Malformed publication");
if(!data.families.length||!data.profiles.length||!data.specifications.length)throw Error("Empty standard publication");
const families=new Set(data.families.map(x=>x.family_id));
for(const p of data.profiles)if(!families.has(p.family_id))throw Error("Missing family: "+p.family_id);
for(const s of data.specifications)if(!/^spec\/[a-z0-9-]+\.md$/i.test(s.path))throw Error("Unexpected specification path");
console.log("Publication checks passed");


// Verify both the browser entry point and every generated full-text link before
// Render is allowed to publish. This specifically prevents a "live" deployment
// whose website remains stuck on the opening/loading screen.
import { Script } from "node:vm";
const browserScript=await readFile(new URL("./app.js",import.meta.url),"utf8");
new Script(browserScript,{filename:"website/app.js"});
const index=await readFile(new URL("./index.html",import.meta.url),"utf8");
const builtAsset=index.match(/<script type="module" src="\.\/(app-[a-f0-9]{16}\.js)"><\/script>/);
if(!builtAsset)throw Error("Published HTML does not point to a unique content-hashed script");
const browserAsset=await readFile(new URL("./"+builtAsset[1],import.meta.url),"utf8");
if(browserAsset!==browserScript)throw Error("Published script does not match the current validated source");

if(!index.includes('data-route="profiles"')||!index.includes('standards/README.html'))throw Error("Accessible navigation or static fallback missing");
for(const doc of data.specifications) {
  if (!doc.url || !/^standards\/[a-z0-9-]+\.html$/i.test(doc.url)) throw Error("Invalid local document URL: "+doc.path);
  const html=await readFile(new URL("./"+doc.url,import.meta.url),"utf8");
  if(!html.includes("<!doctype html>")||!html.includes("reader-article"))throw Error("Document is not readable: "+doc.url);
  if (/href=["']\s*(?:javascript:|data:)/i.test(html))throw Error("Unsafe document hyperlink: "+doc.url);
}
await import("./smoke.mjs");
console.log("All", data.specifications.length, "published documents and browser entry points validated.");
