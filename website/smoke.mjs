// Production smoke test. Executes the real browser entry point with a minimal
// DOM, ensuring the opening screen, routes and source-backed links actually render.
import assert from "node:assert/strict";
import {readFile} from "node:fs/promises";
import vm from "node:vm";

const code = await readFile(new URL("./app.js", import.meta.url), "utf8");
const catalog = JSON.parse(await readFile(new URL("./data/standard.json", import.meta.url), "utf8"));
new vm.Script(code, {filename: "website/app.js"});
const nodes = new Map();
const make = () => ({
  innerHTML: "", textContent: "", value: "", hidden: false,
  classList: {toggle() {}, add() {}, remove() {}},
  setAttribute() {}, addEventListener() {}, querySelector() {return null}
});
for (const id of ["app","breadcrumb-label","source-version","menu-button","site-search","search-results","guide-result"])nodes.set(id,make());
const docEvents = new Map(), windowEvents = new Map();
const doc = {
  getElementById(id) {return nodes.get(id) || null},
  querySelectorAll() {return [{dataset:{nav:"home"},classList:{toggle(){}}}]},
  querySelector() {return {classList:{remove() {}}}},
  addEventListener(type, cb) {docEvents.set(type,[...(docEvents.get(type)||[]),cb])},
  activeElement:{tagName:"BODY"}
};
const location = {search:"?view=home",href:"https://test.local/?view=home"};
const history = {
  pushState(_state,_title,href) {location.search=href.includes("?")?href.slice(href.indexOf("?")):"";location.href="https://test.local/"+location.search},
  replaceState(_state,_title,href) {location.search=href.includes("?")?href.slice(href.indexOf("?")):"";location.href="https://test.local/"+location.search}
};
const fakeWindow = {
  addEventListener(type, cb) {windowEvents.set(type, cb)},
  scrollTo() {}
};
const context = {
  document: doc,window:fakeWindow,location,history,URL,URLSearchParams,
  fetch: async () => ({ok:true,json:async()=>catalog}),
  console: {error(...x){throw Error(x.join(" "))}},
};
vm.runInNewContext(code, context, {timeout:2500, filename:"website/app.js"});
await new Promise(resolve=>setImmediate(resolve));
const html = () => nodes.get("app").innerHTML;
assert.match(html(), /Security for/, "Homepage must render instead of hanging at loading screen");
assert.match(html(), /Find the right approach/, "Homepage action missing");
assert.match(nodes.get("source-version").textContent, /Source: GitHub/);

function visit(query) {
  location.search=query;
  location.href="https://test.local/"+query;
  windowEvents.get("popstate")();
  return html();
}
assert.match(visit("?view=guide"), /What are you building/, "Guided discovery not accessible");
assert.match(visit("?view=profiles"), /profile-card/, "Profiles grid did not load");
assert.match(visit("?view=profiles&family=pairwise-e2ee"), /Pairwise/, "Family deep link unavailable");
const sample=catalog.profiles.find(p=>p.family_id==="pairwise-e2ee");
assert.ok(sample);
assert.match(visit("?view=profile&id="+encodeURIComponent(sample.profile_id+"@"+sample.profile_version)), /What this approach means/);
const library=visit("?view=library");
assert.match(library, /standards\/.+\.html/, "Library must link to in-site specification pages");
assert.doesNotMatch(library,/Read on GitHub/, "Library must be readable without navigating to GitHub");
assert.match(visit("?view=about"), /One standard/, "About page missing");
const handlers=docEvents.get("click") || [];
visit("?view=home");
const anchor={dataset:{route:"profiles",id:"",family:"pairwise-e2ee"},href:"https://test.local/?view=profiles&family=pairwise-e2ee"};
const event={target:{closest(selector){return selector==="a[data-route]"?anchor:null}},preventDefault(){}};
for(const handler of handlers)handler(event);
assert.match(location.search, /family=pairwise-e2ee/, "Profile filters were discarded on click");
assert.match(html(), /Pairwise/, "Navigation click failed");
console.log("Portal startup, homepage, guide, filters, search-linked routes, profile, library and about smoke checks passed.");
