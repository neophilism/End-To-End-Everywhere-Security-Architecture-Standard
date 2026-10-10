#!/usr/bin/env node
/**
 * Generate the entire public portal's catalog from the checked-in source files.
 * No parallel CMS or hand-maintained standard copy is used.
 */
import { readFile, readdir, mkdir, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { execFileSync } from "node:child_process";
import { renderMarkdown, escapeHtml } from "./markdown.mjs";
import {createHash} from "node:crypto";
const root=resolve(import.meta.dirname,"..");
const read=async p=>readFile(join(root,p),"utf8");
const catalog=JSON.parse(await read("profiles/catalog.json"));
if(!Array.isArray(catalog.families)||!Array.isArray(catalog.profiles)||!catalog.families.length)throw Error("Invalid profiles/catalog.json");
const names=(await readdir(join(root,"spec"))).filter(name=>name.endsWith(".md")).sort();
const specifications=await Promise.all(names.map(async name=>{
  const text=await read("spec/"+name);
  const title=(text.match(/^#\s+(.+)$/m)||[])[1]||name.replace(/\.md$/,"").replace(/-/g," ");
  return{title,path:"spec/"+name,status:(text.match(/^\*\*Status:\*\*\s*(.+)$/mi)||[])[1]||"unspecified",url:"standards/"+encodeURIComponent(name.slice(0,-3))+".html"};
}));
const readVersion=(await read("VERSION")).trim();
let commit="";
try{commit=execFileSync("git",["rev-parse","HEAD"],{cwd:root,encoding:"utf8"}).trim()}catch{}
await mkdir(join(root,"website","data"),{recursive:true});
const data={standard:readVersion,commit,families:catalog.families,profiles:catalog.profiles,specifications};
await writeFile(join(root,"website","data","standard.json"),JSON.stringify(data));
console.log("Generated portal from GitHub standard:",readVersion,catalog.families.length,"families",catalog.profiles.length,"profiles",specifications.length,"specifications");


// Publish human-readable full specifications at stable, directly navigable URLs.
// Static pages work independently of the main application JavaScript and load
// from the exact checked-in GitHub Markdown at every build.
const docsDir = join(root, "website", "standards");
await mkdir(docsDir, {recursive: true});
for (const name of names) {
  const markdown = await read("spec/" + name);
  const {html, headings} = renderMarkdown(markdown, name, names);
  const meta = specifications.find(item => item.path === "spec/" + name);
  const sourceLink = "https://github.com/neophilism/End-To-End-Everywhere-Security-Architecture-Standard/blob/main/spec/" + encodeURIComponent(name);
  const toc = headings.filter(h => h.level > 1 && h.level < 4).slice(0, 70).map(h => {
    return '<a class="' + (h.level === 3 ? "subsection" : "") + '" href="#' + escapeHtml(h.id) + '">' + escapeHtml(h.title) + '</a>';
  }).join("\n");
  const title = escapeHtml(meta.title);
  const version = escapeHtml(readVersion);
  const document = [
    '<!doctype html><html lang="en"><head><meta charset="utf-8">',
    '<meta name="viewport" content="width=device-width, initial-scale=1">',
    '<meta name="description" content="Read the source-backed ' + title + ' specification of the End-to-End Everywhere Security Architecture Standard.">',
    '<title>' + title + ' | E2E Everywhere Standard</title>',
    '<link rel="icon" type="image/svg+xml" href="../icon.svg">',
    '<link rel="stylesheet" href="../styles.css"><link rel="stylesheet" href="../docs.css">',
    '</head><body class="reader-body"><div class="reader-shell">',
    '<header class="reader-topbar"><div class="reader-crumb"><a href="../">e ↔ e <strong>everywhere.</strong></a><span>/</span><a href="../?view=library">Standards library</a></div>',
    '<a href="' + sourceLink + '" target="_blank" rel="noopener noreferrer">View GitHub source ↗</a></header>',
    '<section class="reader-intro"><div class="eyebrow">THE AUTHORITATIVE SOURCE · ' + version + '</div><h1>' + title + '</h1>',
    '<p>Read the full specification in a comfortable, navigable format. Generated automatically from the GitHub repository, with no separately maintained copy.</p>',
    '<div class="reader-actions"><a href="../?view=library">← Back to library</a><a href="../?view=profiles">Explore profiles →</a></div></section>',
    '<div class="reader-layout"><aside class="reader-toc" aria-label="On this page"><h2>On this page</h2>' + (toc || '<a href="#main-document">Document</a>') + '</aside>',
    '<main id="main-document" class="reader-article"><div class="reader-status-note">The standard is a release candidate undergoing expert review. Reading this document does not confer certification or production approval.</div>',
    html,
    '<div class="reader-status-note">Source file: <a href="' + sourceLink + '" target="_blank" rel="noopener noreferrer">spec/' + escapeHtml(name) + '</a> · Git commit ' + escapeHtml(commit.slice(0,12) || "unknown") + '</div></main></div>',
    '<footer class="reader-bottom"><span>End-to-End Everywhere — clarity first, security always.</span><a href="../?view=library">Back to all specifications →</a></footer>',
    '</div></body></html>'
  ].join("\n");
  await writeFile(join(docsDir, name.slice(0,-3) + ".html"), document, "utf8");
}
console.log("Published", names.length, "fully readable specification pages.");


// Avoid CDN and browser cache ambiguity. The generated HTML always points to
// a filename derived from the *actual* JavaScript bytes, never a query-string
// cache buster which some CDNs may ignore.
const appSource=await read("website/app.js");
const hash=createHash("sha256").update(appSource,"utf8").digest("hex").slice(0,16);
const appAsset="app-"+hash+".js";
await writeFile(join(root,"website",appAsset),appSource,"utf8");
const template=await read("website/index.html");
const scriptSrc=/src="\.\/(?:app\.js(?:\?[^"]*)?|app-[a-f0-9]{16}\.js)"/;
if(!scriptSrc.test(template))throw Error("Index must reference the source app.js script");
await writeFile(join(root,"website","index.html"),template.replace(scriptSrc,'src="./'+appAsset+'"'),"utf8");
console.log("Published content-addressed JavaScript bundle:",appAsset);
