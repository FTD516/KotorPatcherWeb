export const VERSIONS = {
  "9C10E0450A6EECA417E036E3CDE7474FED1F0A92AAB018446D156944DEA91435": { id: "kotor1_gog_103", name: "kotor1_gog_103", format: "pe" },
  "761F9466F456A83909036BAEBB5C43167D722387BE66E54617BA20A8C49E9886": { id: "kotor1_cdcrack_103", name: "kotor1_cdcrack_103", format: "pe" },
  "34E6D971C034222A417995D8E1E8FDD9F8781795C9C289BD86C499A439F34C88": { id: "kotor1_steam_103", name: "kotor1_steam_103", format: "pe" },
  "777BEE235A9E8BDD9863F6741BC3AC54BB6A113B62B1D2E4D12BBE6DB963A914": { id: "kotor2_gog_aspyr", name: "kotor2_gog_aspyr", format: "pe" },
  "6A522E71631DCEE93467BD2010F3B23D9145326E1E2E89305F13AB104DBBFFEF": { id: "kotor2_steam_aspyr", name: "kotor2_steam_aspyr", format: "pe" },
  "ED043D21A4578FD1C6F1557F0F72BDE5589BA3572A5B6F1A687ED9FEEAB49AC3": { id: "kotor2_steam_aspyr_linux", name: "kotor2_steam_aspyr_linux", format: "elf" },
  "1C536C3EF2E8BED348B38934B381E3DC427F3EBEE21FADDFBD7524FBB2388D77": { id: "kotor2_steam_aspyr_macos", name: "kotor2_steam_aspyr_macos", format: "macho" }
};

const readU16 = (view, offset) => view.getUint16(offset, true);
const readU32 = (view, offset) => view.getUint32(offset, true);
const readU64 = (view, offset) => readU32(view, offset) + readU32(view, offset + 4) * 0x100000000;

function ensureRange(bytes, offset, length, label) {
  if (!Number.isSafeInteger(offset) || offset < 0 || offset + length > bytes.length) {
    throw new Error(`${label} is outside the file.`);
  }
}

export function createAddressMapper(bytes, expectedFormat) {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  if (expectedFormat === "pe") return createPeMapper(bytes, view);
  if (expectedFormat === "elf") return createElfMapper(bytes, view);
  if (expectedFormat === "macho") return createMachOMapper(bytes, view);
  throw new Error("Unsupported executable format.");
}

function createPeMapper(bytes, view) {
  ensureRange(bytes, 0, 0x40, "DOS header");
  if (readU16(view, 0) !== 0x5a4d) throw new Error("Expected a Windows PE executable.");
  const peOffset = readU32(view, 0x3c);
  ensureRange(bytes, peOffset, 24, "PE header");
  if (readU32(view, peOffset) !== 0x00004550) throw new Error("Invalid PE signature.");
  const sectionCount = readU16(view, peOffset + 6);
  const optionalSize = readU16(view, peOffset + 20);
  const optionalOffset = peOffset + 24;
  ensureRange(bytes, optionalOffset, optionalSize, "PE optional header");
  const magic = readU16(view, optionalOffset);
  if (magic !== 0x10b) throw new Error("Only 32-bit PE executables are supported.");
  const imageBase = readU32(view, optionalOffset + 28);
  const sectionOffset = optionalOffset + optionalSize;
  const sections = [];
  for (let index = 0; index < sectionCount; index += 1) {
    const offset = sectionOffset + index * 40;
    ensureRange(bytes, offset, 40, "PE section header");
    sections.push({
      virtualSize: readU32(view, offset + 8),
      virtualAddress: readU32(view, offset + 12),
      rawSize: readU32(view, offset + 16),
      rawOffset: readU32(view, offset + 20)
    });
  }
  const firstSection = sections.reduce((lowest, section) => Math.min(lowest, section.virtualAddress), Infinity);
  return (address, length) => {
    if (address < imageBase) throw new Error(`Address 0x${address.toString(16)} is below the PE image base.`);
    const relative = address - imageBase;
    if (relative < firstSection) {
      ensureRange(bytes, relative, length, "Mapped PE header address");
      return relative;
    }
    const section = sections.find(item => relative >= item.virtualAddress && relative < item.virtualAddress + item.virtualSize);
    if (!section) throw new Error(`Address 0x${address.toString(16)} is not mapped by a PE section.`);
    const within = relative - section.virtualAddress;
    if (within + length > section.rawSize) throw new Error(`Address 0x${address.toString(16)} is not file-backed.`);
    const fileOffset = section.rawOffset + within;
    ensureRange(bytes, fileOffset, length, "Mapped PE address");
    return fileOffset;
  };
}

function createElfMapper(bytes, view) {
  ensureRange(bytes, 0, 52, "ELF header");
  if (bytes[0] !== 0x7f || bytes[1] !== 0x45 || bytes[2] !== 0x4c || bytes[3] !== 0x46) throw new Error("Expected an ELF executable.");
  if (bytes[4] !== 1 || bytes[5] !== 1) throw new Error("Only 32-bit little-endian ELF executables are supported.");
  const programOffset = readU32(view, 28);
  const entrySize = readU16(view, 42);
  const entryCount = readU16(view, 44);
  const loads = [];
  for (let index = 0; index < entryCount; index += 1) {
    const offset = programOffset + index * entrySize;
    ensureRange(bytes, offset, entrySize, "ELF program header");
    if (readU32(view, offset) === 1) {
      loads.push({ fileOffset: readU32(view, offset + 4), virtualAddress: readU32(view, offset + 8), fileSize: readU32(view, offset + 16) });
    }
  }
  if (!loads.length) throw new Error("ELF executable has no loadable segments.");
  return (address, length) => {
    const segment = loads.find(item => address >= item.virtualAddress && address + length <= item.virtualAddress + item.fileSize);
    if (!segment) throw new Error(`Address 0x${address.toString(16)} is not mapped by an ELF load segment.`);
    const fileOffset = segment.fileOffset + address - segment.virtualAddress;
    ensureRange(bytes, fileOffset, length, "Mapped ELF address");
    return fileOffset;
  };
}

function createMachOMapper(bytes, view) {
  ensureRange(bytes, 0, 8, "Mach-O header");
  let sliceOffset = 0;
  let sliceSize = bytes.length;
  if (view.getUint32(0, false) === 0xcafebabe) {
    const architectureCount = view.getUint32(4, false);
    ensureRange(bytes, 8, architectureCount * 20, "Mach-O architecture table");
    let architecture = null;
    for (let index = 0; index < architectureCount; index += 1) {
      const offset = 8 + index * 20;
      if (view.getUint32(offset, false) === 0x01000007) {
        architecture = { offset: view.getUint32(offset + 8, false), size: view.getUint32(offset + 12, false) };
        break;
      }
    }
    if (!architecture) throw new Error("Mach-O executable has no x86_64 slice.");
    sliceOffset = architecture.offset;
    sliceSize = architecture.size;
    ensureRange(bytes, sliceOffset, sliceSize, "Mach-O x86_64 slice");
  }

  ensureRange(bytes, sliceOffset, 32, "64-bit Mach-O header");
  if (readU32(view, sliceOffset) !== 0xfeedfacf || readU32(view, sliceOffset + 4) !== 0x01000007) {
    throw new Error("Expected a 64-bit little-endian x86 Mach-O executable.");
  }
  const commandCount = readU32(view, sliceOffset + 16);
  const commandBytes = readU32(view, sliceOffset + 20);
  ensureRange(bytes, sliceOffset + 32, commandBytes, "Mach-O load commands");
  const segments = [];
  let commandOffset = sliceOffset + 32;
  for (let index = 0; index < commandCount; index += 1) {
    ensureRange(bytes, commandOffset, 8, "Mach-O load command");
    const command = readU32(view, commandOffset);
    const commandSize = readU32(view, commandOffset + 4);
    if (commandSize < 8 || commandOffset + commandSize > sliceOffset + 32 + commandBytes) {
      throw new Error("Invalid Mach-O load command.");
    }
    if (command === 0x19) {
      if (commandSize < 72) throw new Error("Invalid Mach-O segment command.");
      const fileSize = readU64(view, commandOffset + 48);
      if (fileSize) {
        segments.push({
          fileOffset: readU64(view, commandOffset + 40),
          fileSize
        });
      }
    }
    commandOffset += commandSize;
  }
  if (!segments.length) throw new Error("Mach-O executable has no file-backed segments.");
  return (address, length) => {
    const withinSlice = address - sliceOffset;
    const segment = segments.find(item => withinSlice >= item.fileOffset && withinSlice + length <= item.fileOffset + item.fileSize);
    if (!segment) throw new Error(`Address 0x${address.toString(16)} is not mapped by a Mach-O segment.`);
    if (address + length > sliceOffset + sliceSize) throw new Error(`Address 0x${address.toString(16)} is outside the Mach-O slice.`);
    ensureRange(bytes, address, length, "Mapped Mach-O address");
    return address;
  };
}

function bytesEqual(bytes, offset, expected) {
  return expected.every((value, index) => bytes[offset + index] === value);
}

export function applyPatches(sourceBytes, version, patches) {
  const selectedIds = new Set(patches.map(patch => patch.id));
  for (const patch of patches) {
    const conflict = (patch.conflicts ?? []).find(id => selectedIds.has(id));
    if (conflict) throw new Error(`${patch.name} conflicts with another selected patch.`);
  }
  const output = new Uint8Array(sourceBytes);
  const mapAddress = createAddressMapper(output, version.format);
  const writes = [];

  for (const patch of patches) {
    const hooks = patch.variants[version.id];
    if (!hooks) throw new Error(`${patch.name} is not compatible with this executable.`);
    for (const hook of hooks) {
      if (hook.original.length !== hook.replacement.length) throw new Error(`${patch.name} contains an invalid size-changing hook.`);
      const offset = mapAddress(hook.address, hook.original.length);
      if (bytesEqual(output, offset, hook.replacement)) continue;
      if (!bytesEqual(output, offset, hook.original)) {
        const actual = Array.from(output.slice(offset, offset + hook.original.length), byte => byte.toString(16).padStart(2, "0")).join(" ");
        throw new Error(`${patch.name} stopped: bytes at 0x${hook.address.toString(16).toUpperCase()} do not match the expected build (found ${actual}).`);
      }
      writes.push({ offset, replacement: hook.replacement });
    }
  }

  for (const write of writes) output.set(write.replacement, write.offset);
  return output;
}

export async function sha256(buffer) {
  const digest = await crypto.subtle.digest("SHA-256", buffer);
  return Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, "0")).join("").toUpperCase();
}
