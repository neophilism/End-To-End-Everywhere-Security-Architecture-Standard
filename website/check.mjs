import { readFile } from "node:fs/promises";
const data=JSON.parse(await readFile(new URL("./data/standard.json",import.meta.url)));
if(!Array.isArray(data.families)||!Array.isArray(data.profiles)||!Array.isArray(data.specifications))throw Error("Malformed publication");
if(!data.families.length||!data.profiles.length||!data.specifications.length)throw Error("Empty standard publication");
const families=new Set(data.families.map(x=>x.family_id));
for(const p of data.profiles)if(!families.has(p.family_id))throw Error("Missing family: "+p.family_id);
for(const s of data.specifications)if(!/^spec\/[a-z0-9-]+\.md$/i.test(s.path))throw Error("Unexpected specification path");
console.log("Publication checks passed");
