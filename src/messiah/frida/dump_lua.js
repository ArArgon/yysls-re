// Frida hook for luaU_undump — dumps Lua bytecode with filenames.
//
// Locates luaU_undump by SIGNATURE SCAN, never by RVA, so it survives game
// updates. This is the house style: a hook with a hardcoded address is
// already broken. See docs/methodology.md section 7.
//
// The target module defaults to the process's own main module, so the
// executable name is not baked in. Override with `--target-module` if the Lua
// runtime lives in a DLL rather than the exe.
//
// Usage:
//   frida -p <pid> -l dump_lua.js
//   frida -f <game.exe> -l dump_lua.js --no-pause
//
// Writes lua_dump/ in the current working directory. Prefer driving this via
// messiah.frida.dump_lua_host, which receives the payloads over the message
// channel instead of relying on in-process file writes.

"use strict";

// Resolve the main module at load time rather than naming an executable.
const MODULE_NAME = (function () {
    const override = (typeof targetModule !== "undefined") ? targetModule : null;
    if (override) return override;
    try {
        const main = Process.enumerateModules()[0];
        if (main) return main.name;
    } catch (e) { /* fall through */ }
    return null;
})();

// ZIO struct offsets (all 8 bytes on x64)
const ZIO_N      = 0x00;  // uint64_t n — bytes remaining in current buffer
const ZIO_P      = 0x08;  // const char* p — current position in buffer
const ZIO_READER = 0x10;  // lua_Reader reader
const ZIO_DATA   = 0x18;  // void* data (opaque reader state, e.g. LoadS)
const ZIO_L      = 0x20;  // void* L

let dumpIndex = 0;

// ═══════════════════════════════════════════════════════════════════
// Signature scanning — find luaU_undump without a hardcoded RVA
// ═══════════════════════════════════════════════════════════════════

function findLuaUUndump(moduleName) {
    const mod = Process.getModuleByName(moduleName);
    console.log(`[*] Scanning ${mod.name} (${mod.base}, ${mod.size} bytes) for luaU_undump...`);

    // ── Strategy 1: pattern scan for the name-prefix check ─────────
    //
    // luaU_undump checks the first byte of `name` against three values:
    //   cmp reg8, 0x40  ('@')   →  je ...
    //   cmp reg8, 0x3d  ('=')   →  je ...
    //   cmp reg8, 0x1b  (LUA_SIGNATURE[0])
    //
    // Encoded as:  80 ?? 40  74 ??  80 ?? 3d  74 ??  80 ?? 1b
    // The ?? after 80 is the ModRM byte (register varies by compilation).
    // The ?? after 74 is the je displacement.
    //
    // This triplet is unique to luaU_undump across Lua 5.1–5.4.

    const SIG_PATTERN = "80 ?? 40 74 ?? 80 ?? 3d 74 ?? 80 ?? 1b";
    const matches = Memory.scanSync(mod.base, mod.size, SIG_PATTERN);

    console.log(`[*] Pattern matches: ${matches.length}`);

    for (const m of matches) {
        // Verify the 80 XX bytes are actually CMP (ModRM /7 = bits 5:3 = 111)
        // ModRM for cmp r8, imm8 with mod=11: 11 111 rrr = 0xF8..0xFF
        const modrm1 = m.address.add(1).readU8();
        const modrm2 = m.address.add(6).readU8();
        const modrm3 = m.address.add(11).readU8();
        if ((modrm1 & 0xF8) !== 0xF8 || (modrm2 & 0xF8) !== 0xF8 || (modrm3 & 0xF8) !== 0xF8) {
            console.log(`    ${m.address}: ModRM check failed (${modrm1.toString(16)}, ${modrm2.toString(16)}, ${modrm3.toString(16)}), skipping`);
            continue;
        }

        // Walk backwards to find function start
        const funcStart = findFunctionStart(m.address);
        if (funcStart) {
            const rva = funcStart.sub(mod.base);
            console.log(`[*] Found luaU_undump at ${funcStart} (RVA 0x${rva.toString(16)})`);
            console.log(`    Pattern matched at ${m.address} (offset +${m.address.sub(funcStart)} into function)`);
            return funcStart;
        }
    }

    // ── Strategy 2: find "binary string" literal xref ──────────────
    //
    // luaU_undump references the string "binary string" via a
    // RIP-relative LEA, right after the cmp 0x1b check.

    console.log("[*] Pattern scan failed, trying 'binary string' xref...");

    const STR_PATTERN = "62 69 6E 61 72 79 20 73 74 72 69 6E 67 00";
    const strMatches = Memory.scanSync(mod.base, mod.size, STR_PATTERN);

    for (const sm of strMatches) {
        console.log(`[*] Found "binary string" at ${sm.address}`);

        // Scan .text for RIP-relative LEA referencing this string.
        // LEA rax, [rip+disp32] = 48 8D 05 xx xx xx xx
        // We scan for 48 8D 05 and check if target == sm.address.
        const leaMatches = Memory.scanSync(mod.base, mod.size, "48 8D 05");
        for (const lm of leaMatches) {
            const disp = lm.address.add(3).readS32();
            const target = lm.address.add(7).add(disp);
            if (target.equals(sm.address)) {
                console.log(`[*] LEA xref at ${lm.address} -> "binary string"`);
                const funcStart = findFunctionStart(lm.address);
                if (funcStart) {
                    const rva = funcStart.sub(mod.base);
                    console.log(`[*] Found luaU_undump at ${funcStart} (RVA 0x${rva.toString(16)})`);
                    return funcStart;
                }
            }
        }
    }

    return null;
}

function findFunctionStart(addrInFunc) {
    // MSVC x64 typically pads between functions with CC (int3) bytes
    // for alignment. Walk backwards to find CC padding, then the
    // first non-CC byte after it is the function entry.
    //
    // The cmp pattern is typically 0x20–0x50 bytes into the function,
    // so we scan back up to 256 bytes.

    for (let off = 1; off <= 256; off++) {
        const p = addrInFunc.sub(off);
        if (p.readU8() === 0xCC) {
            // Found int3 — skip any consecutive CC bytes
            let start = p.add(1);
            while (start.readU8() === 0xCC && start.compare(addrInFunc) < 0) {
                start = start.add(1);
            }
            if (start.compare(addrInFunc) < 0) {
                return start;
            }
        }
    }

    // Fallback: look for common MSVC function prologues
    // 40 55          push rbp (with REX)
    // 48 89 5C 24    mov [rsp+xx], rbx
    // 48 83 EC       sub rsp, imm8
    // 48 81 EC       sub rsp, imm32
    const prologues = [
        [0x40, 0x55],             // push rbp (REX)
        [0x48, 0x89, 0x5C, 0x24], // mov [rsp+xx], rbx
        [0x55],                   // push rbp
    ];

    for (let off = 1; off <= 256; off++) {
        const p = addrInFunc.sub(off);
        for (const prol of prologues) {
            let match = true;
            for (let j = 0; j < prol.length; j++) {
                if (p.add(j).readU8() !== prol[j]) { match = false; break; }
            }
            if (match) {
                // Extra sanity: check that there's a sub rsp within the next 20 bytes
                // (all non-leaf x64 functions allocate stack space)
                for (let k = 0; k < 20; k++) {
                    const b0 = p.add(k).readU8();
                    const b1 = p.add(k + 1).readU8();
                    const b2 = p.add(k + 2).readU8();
                    if (b0 === 0x48 && b1 === 0x81 && b2 === 0xEC) return p; // sub rsp, imm32
                    if (b0 === 0x48 && b1 === 0x83 && b2 === 0xEC) return p; // sub rsp, imm8
                }
            }
        }
    }

    console.log(`  [!] Could not find function start near ${addrInFunc}`);
    return null;
}

// ═══════════════════════════════════════════════════════════════════
// Bytecode dumping logic
// ═══════════════════════════════════════════════════════════════════

function sanitizeName(name) {
    return name
        .replace(/^[@=]/, "")
        .replace(/[^a-zA-Z0-9._\-]/g, "_")
        .substring(0, 100);
}

function tryReadString(ptr) {
    try {
        const s = ptr.readUtf8String();
        return s || null;
    } catch (e) {
        return null;
    }
}

function dumpBuffer(buf, size, name) {
    const idx = String(dumpIndex).padStart(4, "0");
    const safeName = sanitizeName(name);
    const outPath = `lua_dump/${idx}_${safeName}.luac`;

    const data = buf.readByteArray(size);
    if (!data) {
        console.log(`  [!] readByteArray returned null`);
        return;
    }

    // Send via message channel so the Python host can save reliably.
    // Also write locally as a fallback.
    send({ type: "lua_dump", index: dumpIndex, name: name, path: outPath, size: size }, data);

    try {
        const f = new File(outPath, "wb");
        f.write(data);
        f.flush();
        f.close();
        console.log(`  => dumped ${size} bytes to ${outPath}`);
    } catch (e) {
        console.log(`  => File write failed (${e}), data sent via message channel`);
    }
}

// ═══════════════════════════════════════════════════════════════════
// Hook installation
// ═══════════════════════════════════════════════════════════════════

function hookLuaUUndump() {
    if (!MODULE_NAME) {
        console.error("[!] Could not determine the main module.");
        return;
    }

    let mod = null;
    try {
        mod = Process.getModuleByName(MODULE_NAME);
    } catch (e) { /* reported below */ }

    if (!mod) {
        console.error(`[!] Module "${MODULE_NAME}" not found. Loaded modules:`);
        Process.enumerateModules().slice(0, 20).forEach(m => {
            console.log(`    ${m.name}  base=${m.base}  size=${m.size}`);
        });
        return;
    }
    console.log(`[*] Target module: ${mod.name} base=${mod.base} size=${mod.size}`);

    // Dynamically find luaU_undump
    const target = findLuaUUndump(MODULE_NAME);
    if (!target) {
        console.error("[!] Could not locate luaU_undump. Hook not installed.");
        return;
    }

    Interceptor.attach(target, {
        onEnter(args) {
            // Windows x64 ABI: rcx = L, rdx = z (ZIO*), r8 = name
            const L       = args[0];
            const zio     = args[1];
            const namePtr = args[2];

            // ── Read name ──────────────────────────────────────────────
            const name = tryReadString(namePtr) || `chunk_${dumpIndex}`;

            // ── Read ZIO fields ────────────────────────────────────────
            const n      = zio.add(ZIO_N).readU64();
            const p      = zio.add(ZIO_P).readPointer();
            const reader = zio.add(ZIO_READER).readPointer();
            const data   = zio.add(ZIO_DATA).readPointer();

            const bufSize = n.toNumber();

            console.log(`\n[luaU_undump #${dumpIndex}]`);
            console.log(`  name     = "${name}"`);
            console.log(`  ZIO.n    = ${bufSize}`);
            console.log(`  ZIO.p    = ${p}`);
            console.log(`  ZIO.data = ${data}`);

            // ── Attempt 1: read directly from ZIO buffer ───────────────
            // The caller (f_parser) already consumed the first byte (0x1b)
            // via zgetc (z->n--, z->p++), so we back up by 1 to capture
            // the full chunk including the Lua signature.
            if (bufSize > 0 && bufSize < 50 * 1024 * 1024) {
                const fullBuf = p.sub(1);
                const fullSize = bufSize + 1;

                const peek = fullBuf.readByteArray(Math.min(fullSize, 32));
                console.log(`  header   = ${hexdump(peek, { length: Math.min(fullSize, 32), header: false, ansi: true })}`);

                dumpBuffer(fullBuf, fullSize, name);
                dumpIndex++;
                return;
            }

            // ── Attempt 2: ZIO.n == 0, try LoadS at ZIO.data ──────────
            // When Lua uses luaL_loadbuffer, ZIO.data points to:
            //   struct LoadS { const char* s; size_t size; };
            // The reader hasn't been called yet, so n=0 but the full
            // buffer is at LoadS.s with LoadS.size bytes.
            if (bufSize === 0 && !data.isNull()) {
                try {
                    const loadS_s    = data.readPointer();
                    const loadS_size = data.add(Process.pointerSize).readULong();

                    console.log(`  LoadS.s    = ${loadS_s}`);
                    console.log(`  LoadS.size = ${loadS_size}`);

                    if (loadS_size > 0 && loadS_size < 50 * 1024 * 1024) {
                        // LoadS still has the full original buffer (the
                        // zgetc consumed from ZIO, not from LoadS), so
                        // no -1 adjustment needed here.
                        const peek = loadS_s.readByteArray(Math.min(loadS_size, 32));
                        console.log(`  header     = ${hexdump(peek, { length: Math.min(loadS_size, 32), header: false, ansi: true })}`);

                        dumpBuffer(loadS_s, loadS_size, name);
                        dumpIndex++;
                        return;
                    }
                } catch (e) {
                    console.log(`  [!] LoadS read failed: ${e}`);
                }
            }

            // ── Attempt 3: diagnostic peek at ZIO.p ───────────────────
            if (!p.isNull()) {
                try {
                    const sig = p.readByteArray(4);
                    console.log(`  raw sig  = ${hexdump(sig, { length: 4, header: false, ansi: true })}`);
                } catch (e) {
                    console.log(`  [!] Cannot read ZIO.p: ${e}`);
                }
            }

            console.log(`  => SKIPPED (could not determine buffer bounds)`);
            dumpIndex++;
        }
    });

    console.log(`[*] Hook installed. Waiting for luaU_undump calls...`);
    console.log(`[*] Dumps will be saved to ./lua_dump/`);
}

// ═══════════════════════════════════════════════════════════════════
// Initialization
// ═══════════════════════════════════════════════════════════════════

// Create output directory (best-effort)
try {
    const mkdirAddr = Module.findExportByName(null, "_mkdir") ||
                      Module.findExportByName(null, "mkdir") ||
                      Module.findExportByName("msvcrt.dll", "_mkdir") ||
                      Module.findExportByName("ucrtbase.dll", "_mkdir");
    if (mkdirAddr) {
        const _mkdir = new NativeFunction(mkdirAddr, "int", ["pointer"]);
        _mkdir(Memory.allocUtf8String("lua_dump"));
    }
} catch (e) {
    console.log(`[!] Create lua_dump/ manually: mkdir lua_dump`);
}

hookLuaUUndump();
