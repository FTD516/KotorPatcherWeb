const REPOSITORY = "FTD516/Kotor-Patch-Manager";
const BRANCH = "master";
const TREE_URL = `https://api.github.com/repos/${REPOSITORY}/git/trees/${BRANCH}?recursive=1`;
const RAW_ROOT = `https://raw.githubusercontent.com/${REPOSITORY}/${BRANCH}/`;
const SAFE_TYPES = new Set(["simple", "static"]);

let treePromise = null;

function parseQuoted(value) {
  try {
    return JSON.parse(value);
  } catch {
    return value.slice(1, -1);
  }
}

function stringValue(text, key) {
  const escapedKey = key.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const triple = text.match(new RegExp(`^\\s*${escapedKey}\\s*=\\s*"""([\\s\\S]*?)"""`, "m"));
  if (triple) return triple[1];
  const quoted = text.match(new RegExp(`^\\s*${escapedKey}\\s*=\\s*("(?:\\\\.|[^"\\\\])*")`, "m"));
  return quoted ? parseQuoted(quoted[1]) : "";
}

function stringArray(text, key) {
  const escapedKey = key.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const match = text.match(new RegExp(`^\\s*${escapedKey}\\s*=\\s*\\[([\\s\\S]*?)\\]`, "m"));
  if (!match) return [];
  const withoutComments = match[1].replace(/#.*$/gm, "");
  return Array.from(withoutComments.matchAll(/"(?:\\.|[^"\\])*"/g), item => parseQuoted(item[0]));
}

function numberValue(text, key) {
  const match = text.match(new RegExp(`^\\s*${key}\\s*=\\s*(0x[0-9a-f]+|\\d+)`, "mi"));
  return match ? Number.parseInt(match[1], match[1].toLowerCase().startsWith("0x") ? 16 : 10) : null;
}

function byteArray(text, key) {
  const match = text.match(new RegExp(`^\\s*${key}\\s*=\\s*\\[([\\s\\S]*?)\\]`, "mi"));
  if (!match) return null;
  const withoutComments = match[1].replace(/#.*$/gm, "");
  return Array.from(withoutComments.matchAll(/0x[0-9a-f]+|\b\d+\b/gi), item =>
    Number.parseInt(item[0], item[0].toLowerCase().startsWith("0x") ? 16 : 10));
}

export function parseManifest(text) {
  const versionSection = text.match(/\[patch\.supported_versions\]([\s\S]*?)(?=\n\s*\[|$)/)?.[1] ?? "";
  const supportedVersions = {};
  for (const match of versionSection.matchAll(/^\s*([A-Za-z0-9_-]+)\s*=\s*("(?:\\.|[^"\\])*")/gm)) {
    supportedVersions[match[1]] = parseQuoted(match[2]).toUpperCase();
  }
  return {
    id: stringValue(text, "id"),
    name: stringValue(text, "name"),
    author: stringValue(text, "author"),
    description: stringValue(text, "description").replace(/\\\s*\n\s*/g, "").replace(/\s+/g, " ").trim(),
    requires: stringArray(text, "requires"),
    conflicts: stringArray(text, "conflicts"),
    supportedVersions
  };
}

export function parseHooks(text) {
  const metadata = text.split(/^\s*\[\[hooks\]\]\s*$/m, 1)[0];
  const targetVersions = stringArray(metadata, "target_versions").map(hash => hash.toUpperCase());
  const blocks = text.split(/^\s*\[\[hooks\]\]\s*$/m).slice(1);
  const hooks = blocks.map(block => ({
    type: stringValue(block, "type").toLowerCase() || "detour",
    address: numberValue(block, "address"),
    original: byteArray(block, "original_bytes"),
    replacement: byteArray(block, "replacement_bytes")
  }));
  return { targetVersions, hooks };
}

async function fetchText(url, fetcher) {
  const response = await fetcher(url);
  if (!response.ok) throw new Error(`GitHub returned ${response.status} for ${url.split("/").pop()}.`);
  return response.text();
}

async function repositoryTree(fetcher) {
  if (!treePromise) {
    treePromise = fetcher(TREE_URL).then(async response => {
      if (!response.ok) throw new Error(`GitHub catalog request failed (${response.status}). Try again later.`);
      const data = await response.json();
      if (data.truncated) throw new Error("GitHub returned an incomplete patch catalog.");
      return data.tree;
    }).catch(error => {
      treePromise = null;
      throw error;
    });
  }
  return treePromise;
}

export async function loadCompatiblePatches(versionHash, versionId, fetcher = fetch) {
  versionHash = versionHash.toUpperCase();
  const tree = await repositoryTree(fetcher);
  const manifestEntries = tree.filter(entry => /^Patches\/[^/]+\/manifest\.toml$/.test(entry.path));

  const manifests = await Promise.all(manifestEntries.map(async entry => ({
    directory: entry.path.slice(0, -"/manifest.toml".length),
    manifest: parseManifest(await fetchText(RAW_ROOT + encodeURI(entry.path), fetcher))
  })));

  const supported = manifests.filter(({ directory, manifest }) => {
    if (!manifest.id || !manifest.supportedVersions[versionId] || manifest.requires.length) return false;
    return !tree.some(entry => entry.path.startsWith(`${directory}/`) && entry.path.toLowerCase().endsWith(".dll"));
  });

  const patches = await Promise.all(supported.map(async ({ directory, manifest }) => {
    const hookEntries = tree.filter(entry => {
      const relative = entry.path.slice(directory.length + 1);
      return entry.path.startsWith(`${directory}/`) && !relative.includes("/") && relative.endsWith(".hooks.toml");
    });
    const hookFiles = await Promise.all(hookEntries.map(async entry =>
      parseHooks(await fetchText(RAW_ROOT + encodeURI(entry.path), fetcher))));
    const matching = hookFiles.filter(file => !file.targetVersions.length || file.targetVersions.includes(versionHash));
    const hooks = matching.flatMap(file => file.hooks);
    if (!hooks.length || hooks.some(hook =>
      !SAFE_TYPES.has(hook.type) || hook.address === null || !hook.original?.length ||
      !hook.replacement?.length || hook.original.length !== hook.replacement.length)) return null;
    return {
      ...manifest,
      hookTypes: [...new Set(hooks.map(hook => hook.type))].sort(),
      variants: { [versionId]: hooks.map(({ address, original, replacement }) => ({ address, original, replacement })) }
    };
  }));

  return patches.filter(Boolean).sort((left, right) => left.name.localeCompare(right.name));
}
