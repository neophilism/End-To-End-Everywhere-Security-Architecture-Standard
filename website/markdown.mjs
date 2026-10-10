// Static, dependency-free Markdown rendering for the public standards reader.
// Source documents are always loaded from spec/ during the build, never duplicated.
const SOURCE_ROOT = "https://github.com/neophilism/End-To-End-Everywhere-Security-Architecture-Standard/blob/main/";
export function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, ch => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  })[ch]);
}
function slug(text) {
  return String(text).toLowerCase().replace(/<[^>]*>/g, "")
    .replace(/[^a-z0-9 -]/g, "").trim().replace(/\s+/g, "-");
}
function urlFor(raw, currentName, available) {
  const input = String(raw ?? "").trim();
  if (input.startsWith("#") && /^#[A-Za-z0-9_-]+$/.test(input)) return {href: input, external: false};
  if (/^https:\/\/[^\s<>"']+$/i.test(input)) return {href: input, external: true};
  if (/^mailto:[^\s<>"']+$/i.test(input)) return {href: input, external: true};
  if (!input || /^(?:\/|\\|\/\/|javascript:|data:)/i.test(input)) return null;
  const [path, fragment] = input.split("#", 2);
  if (!/^[a-zA-Z0-9./_-]+$/.test(path)) return null;
  const normalized = [];
  for (const part of path.split("/")) {
    if (part === "." || part === "") continue;
    if (part === "..") {
      if (!normalized.length) return null;
      normalized.pop();
      continue;
    }
    normalized.push(part);
  }
  const filename = normalized.join("/");
  if (filename.endsWith(".md") && available.has(filename)) {
    const name = filename.slice(0, -3);
    return {href: "./" + encodeURIComponent(name) + ".html" + (fragment ? "#" + encodeURIComponent(fragment) : ""), external: false};
  }
  if (!filename) return null;
  return {href: SOURCE_ROOT + "spec/" + filename.split("/").map(encodeURIComponent).join("/") + (fragment ? "#" + encodeURIComponent(fragment) : ""), external: true};
}
function plainInline(input) {
  let t = escapeHtml(input);
  t = t.replace(/[\x60]([^\x60\n]+)[\x60]/g, (_m, a) => '<code>' + a + '</code>');
  t = t.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
  t = t.replace(/(^|[\s(])\*([^*]+)\*/g, '$1<em>$2</em>');
  t = t.replace(/~~([^~]+)~~/g, '<del>$1</del>');
  return t;
}
function inline(text, currentName, available) {
  // Escape everything by default, and opt in only explicitly validated href targets.
  const s = String(text ?? "");
  const expr = /!?\[([^\]]+)\]\(([^)\s]+)(?:\s+"[^"]*")?\)/g;
  let result = "", pos = 0, match;
  while ((match = expr.exec(s))) {
    result += plainInline(s.slice(pos, match.index));
    const target = urlFor(match[2], currentName, available);
    const label = plainInline(match[1]);
    if (target) {
      result += '<a href="' + escapeHtml(target.href) + '"' +
        (target.external ? ' target="_blank" rel="noopener noreferrer"' : "") + '>' + label + '</a>';
    } else result += label;
    pos = match.index + match[0].length;
  }
  return result + plainInline(s.slice(pos));
}
function isBlock(line) {
  return /^\s*(?:#{1,6}\s|>|\*{3,}$|-{3,}$|[\x60]{3}|~{3}|(?:-|\*|\+)\s|[0-9]+\.\s|\|)/.test(line);
}
export function renderMarkdown(markdown, currentName, specNames) {
  const available = new Set(specNames);
  const lines = String(markdown ?? "").replace(/\r\n/g, "\n").split("\n");
  const result = [], headings = [];
  let i = 0;
  const renderText = s => inline(s, currentName, available);
  const marker = /^(\s*)(?:[-*+]|\d+[.])\s+/;
  while (i < lines.length) {
    const line = lines[i];
    if (!line.trim()) { i++; continue; }
    let m;
    if ((m = line.match(/^\s*([\x60]{3,}|~{3,})(.*)$/))) {
      const fence = m[1], lang = (m[2] || "").trim();
      i++;
      const code = [];
      while (i < lines.length && !lines[i].trimStart().startsWith(fence)) code.push(lines[i++]);
      if (i < lines.length) i++;
      result.push('<pre><code' + (lang && /^[a-z0-9_+#.-]+$/i.test(lang) ? ' class="language-' + escapeHtml(lang) + '"' : "") + '>' + escapeHtml(code.join("\n")) + '</code></pre>');
      continue;
    }
    if ((m = line.match(/^(#{1,6})\s+(.+?)\s*#*\s*$/))) {
      const level = Math.min(m[1].length, 5), title = m[2], id = slug(title) || "section-" + i;
      headings.push({level, title: title.replace(/[\x60*]/g, ""), id});
      result.push('<h' + level + ' id="' + escapeHtml(id) + '">' + renderText(title) + '</h' + level + '>');
      i++; continue;
    }
    if (/^(\s*)(---+|\*\*\*+|___+)\s*$/.test(line)) {result.push("<hr>"); i++; continue;}
    if (/^\s*>/.test(line)) {
      const body=[];
      while (i<lines.length && /^\s*>/.test(lines[i])) body.push(lines[i++].replace(/^\s*>\s?/, ""));
      result.push("<blockquote><p>" + body.map(renderText).join(" ") + "</p></blockquote>");continue;
    }
    if (/^\s*\|.+\|\s*$/.test(line) && i+1<lines.length && /^\s*\|?[\s:|-]+\|\s*$/.test(lines[i+1])) {
      const cells = row => row.trim().replace(/^\|/,"").replace(/\|$/,"").split("|").map(x=>renderText(x.trim()));
      const head=cells(line);
      i+=2;
      const rows=[];
      while(i<lines.length && /^\s*\|/.test(lines[i])) rows.push(cells(lines[i++]));
      result.push("<div class=\"table-scroll\"><table><thead><tr>"+head.map(c=>"<th>"+c+"</th>").join("")+"</tr></thead><tbody>"+rows.map(row=>"<tr>"+row.map(c=>"<td>"+c+"</td>").join("")+"</tr>").join("")+"</tbody></table></div>");continue;
    }
    if (marker.test(line)) {
      const ordered=/^\s*\d+\./.test(line), items=[];
      while (i<lines.length && marker.test(lines[i]) && /^\s*\d+\./.test(lines[i])===ordered) {
        let item=lines[i++].replace(marker,"");
        while(i<lines.length && lines[i].trim() && /^\s{2,}\S/.test(lines[i]) && !marker.test(lines[i]))item+=" "+lines[i++].trim();
        items.push("<li>"+renderText(item)+"</li>");
      }
      const tag=ordered?"ol":"ul";result.push("<"+tag+">"+items.join("")+"</"+tag+">");continue;
    }
    const para=[line.trim()];i++;
    while(i<lines.length && lines[i].trim() && !isBlock(lines[i]))para.push(lines[i++].trim());
    result.push("<p>"+para.map(renderText).join(" ")+"</p>");
  }
  return {html:result.join("\n"), headings};
}
