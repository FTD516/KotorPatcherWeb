import { VERSIONS, applyPatches, sha256 } from "./patcher.js";
import { loadCompatiblePatches } from "./github-catalog.js";

const elements = {
  input: document.querySelector("#file-input"),
  dropZone: document.querySelector("#drop-zone"),
  fileCard: document.querySelector("#file-card"),
  fileName: document.querySelector("#file-name"),
  fileMeta: document.querySelector("#file-meta"),
  fileHash: document.querySelector("#file-hash"),
  fileStatus: document.querySelector("#file-status"),
  remove: document.querySelector("#remove-file"),
  patchList: document.querySelector("#patch-list"),
  selectedCount: document.querySelector("#selection-count"),
  apply: document.querySelector("#apply-button"),
  result: document.querySelector("#result")
};

let currentFile = null;
let sourceBuffer = null;
let detectedVersion = null;
let compatiblePatches = [];
let downloadUrl = null;

function formatBytes(size) {
  return size >= 1024 * 1024 ? `${(size / 1024 / 1024).toFixed(2)} MB` : `${Math.ceil(size / 1024)} KB`;
}

function setResult(message, isError = false) {
  elements.result.hidden = false;
  elements.result.classList.toggle("error", isError);
  elements.result.replaceChildren(document.createTextNode(message));
}

function clearDownload() {
  if (downloadUrl) URL.revokeObjectURL(downloadUrl);
  downloadUrl = null;
}

function updateSelection() {
  const count = elements.patchList.querySelectorAll("input:checked").length;
  elements.selectedCount.textContent = `${count} selected`;
  elements.apply.disabled = !detectedVersion || count === 0;
}

function renderPatches() {
  elements.patchList.replaceChildren();
  if (!compatiblePatches.length) {
    elements.patchList.innerHTML = '<div class="empty-state"><span>◇</span><p>GitHub currently has no compatible direct patches for this build.</p></div>';
    updateSelection();
    return;
  }
  for (const patch of compatiblePatches) {
    const label = document.createElement("label");
    label.className = "patch-option";
    const input = document.createElement("input");
    input.type = "checkbox";
    input.value = patch.id;
    const check = document.createElement("span");
    check.className = "check";
    const main = document.createElement("span");
    main.className = "patch-main";
    const title = document.createElement("h3");
    title.textContent = patch.name;
    const description = document.createElement("p");
    description.textContent = patch.description;
    main.append(title, description);
    const meta = document.createElement("span");
    meta.className = "patch-meta";
    const type = document.createElement("span");
    type.textContent = patch.hookTypes.includes("simple") ? "Direct byte patch" : "Static patch";
    const author = document.createElement("b");
    author.textContent = `BY ${patch.author}`;
    meta.append(type, author);
    input.addEventListener("change", () => {
      if (input.checked) {
        for (const option of elements.patchList.querySelectorAll("input:checked")) {
          if (option === input) continue;
          const otherPatch = compatiblePatches.find(item => item.id === option.value);
          if (patch.conflicts.includes(option.value) || otherPatch?.conflicts.includes(patch.id)) {
            option.checked = false;
            option.closest(".patch-option").classList.remove("selected");
          }
        }
      }
      label.classList.toggle("selected", input.checked);
      updateSelection();
      elements.result.hidden = true;
    });
    label.append(input, check, main, meta);
    elements.patchList.append(label);
  }
  updateSelection();
}

async function loadFile(file) {
  clearDownload();
  currentFile = file;
  detectedVersion = null;
  compatiblePatches = [];
  elements.result.hidden = true;
  elements.dropZone.hidden = true;
  elements.fileCard.hidden = false;
  elements.fileName.textContent = file.name;
  elements.fileMeta.textContent = `${formatBytes(file.size)} · Reading and identifying…`;
  elements.fileHash.textContent = "SHA-256: calculating…";
  elements.fileStatus.textContent = "Scanning";
  elements.fileStatus.className = "status-badge";
  elements.patchList.innerHTML = '<div class="empty-state"><span>◇</span><p>Checking executable fingerprint…</p></div>';
  updateSelection();

  try {
    sourceBuffer = await file.arrayBuffer();
    const hash = await sha256(sourceBuffer);
    detectedVersion = VERSIONS[hash] ?? null;
    elements.fileHash.textContent = `SHA-256: ${hash}`;
    if (!detectedVersion) {
      elements.fileMeta.textContent = `${formatBytes(file.size)} · Unknown build`;
      elements.fileStatus.textContent = "Not supported";
      elements.fileStatus.classList.add("error");
      elements.patchList.innerHTML = '<div class="empty-state"><span>◇</span><p>This executable does not match a supported clean game build. No patches are available.</p></div>';
      return;
    }
    elements.fileMeta.textContent = `${formatBytes(file.size)} · ${detectedVersion.name}`;
    elements.fileStatus.textContent = "Verified build";
    elements.fileStatus.textContent = "Loading patches";
    elements.patchList.innerHTML = '<div class="empty-state"><span>◇</span><p>Reading compatible patch definitions from GitHub…</p></div>';
    compatiblePatches = await loadCompatiblePatches(hash, detectedVersion.id);
    elements.fileStatus.textContent = "Verified build";
    renderPatches();
  } catch (error) {
    const catalogFailed = Boolean(detectedVersion && sourceBuffer);
    if (!catalogFailed) sourceBuffer = null;
    elements.fileStatus.textContent = catalogFailed ? "Catalog unavailable" : "Read failed";
    elements.fileStatus.classList.add("error");
    setResult(error.message, true);
  }
}

elements.input.addEventListener("change", () => {
  if (elements.input.files[0]) loadFile(elements.input.files[0]);
});

for (const eventName of ["dragenter", "dragover"]) {
  elements.dropZone.addEventListener(eventName, event => {
    event.preventDefault();
    elements.dropZone.classList.add("is-dragging");
  });
}
for (const eventName of ["dragleave", "drop"]) {
  elements.dropZone.addEventListener(eventName, event => {
    event.preventDefault();
    elements.dropZone.classList.remove("is-dragging");
  });
}
elements.dropZone.addEventListener("drop", event => {
  const file = event.dataTransfer.files[0];
  if (file) loadFile(file);
});

elements.remove.addEventListener("click", () => {
  clearDownload();
  currentFile = null;
  sourceBuffer = null;
  detectedVersion = null;
  compatiblePatches = [];
  elements.input.value = "";
  elements.fileName.textContent = "";
  elements.fileMeta.textContent = "";
  elements.fileHash.textContent = "";
  elements.fileStatus.textContent = "";
  elements.fileCard.hidden = true;
  elements.dropZone.hidden = false;
  elements.result.hidden = true;
  elements.patchList.innerHTML = '<div class="empty-state"><span>◇</span><p>Load a recognized game executable to see compatible direct patches.</p></div>';
  updateSelection();
});

elements.apply.addEventListener("click", () => {
  clearDownload();
  const selectedIds = Array.from(elements.patchList.querySelectorAll("input:checked"), input => input.value);
  const selected = compatiblePatches.filter(patch => selectedIds.includes(patch.id));
  try {
    const output = applyPatches(new Uint8Array(sourceBuffer), detectedVersion, selected);
    downloadUrl = URL.createObjectURL(new Blob([output], { type: "application/octet-stream" }));
    const link = document.createElement("a");
    link.download = currentFile.name;
    link.href = downloadUrl;
    link.textContent = `Save ${link.download}`;
    elements.result.className = "result";
    elements.result.replaceChildren(document.createTextNode(`${selected.length} patch${selected.length === 1 ? "" : "es"} applied successfully. Replace the game executable only after keeping a backup. `), document.createElement("br"), link);
    elements.result.hidden = false;
  } catch (error) {
    setResult(error.message, true);
  }
});

window.addEventListener("beforeunload", clearDownload);
