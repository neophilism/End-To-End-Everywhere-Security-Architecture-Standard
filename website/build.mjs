#!/usr/bin/env node
/**
 * Generate the entire public portal's catalog from the checked-in source files.
 * No parallel CMS or hand-maintained standard copy is used.
 */
import { readFile, readdir, mkdir, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { execFileSync } from "node:child_process";
const root=resolve(import.meta.dirname,"..");
const read=async p=>readFile(join(root,p),"utf8");
const catalog=JSON.parse(await read("profiles/catalog.json"));
if(!Array.isArray(catalog.families)||!Array.isArray(catalog.profiles)||!catalog.families.length)throw Error("Invalid profiles/catalog.json");
const names=(await readdir(join(root,"spec"))).filter(name=>name.endsWith(".md")).sort();
const specifications=await Promise.all(names.map(async name=>{
  const text=await read("spec/"+name);
  const title=(text.match(/^#\s+(.+)$/m)||[])[1]||name.replace(/\.md$/,"").replace(/-/g," ");
  return{title,path:"spec/"+name,status:(text.match(/^\*\*Status:\*\*\s*(.+)$/mi)||[])[1]||"unspecified"};
}));
const readVersion=(await read("VERSION")).trim();
let commit="";
try{commit=execFileSync("git",["rev-parse","HEAD"],{cwd:root,encoding:"utf8"}).trim()}catch{}
await mkdir(join(root,"website","data"),{recursive:true});
const data={standard:readVersion,commit,families:catalog.families,profiles:catalog.profiles,specifications};
await writeFile(join(root,"website","data","standard.json"),JSON.stringify(data));
console.log("Generated portal from GitHub standard:",readVersion,catalog.families.length,"families",catalog.profiles.length,"profiles",specifications.length,"specifications");
