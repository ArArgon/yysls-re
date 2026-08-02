# The `MPatch` Lua API

**Scope:** the native API the launcher exposes to its Lua scripts. This is the
seam between the patcher's logic (Lua, extractable) and its implementation
(native) — knowing the names tells you what to look for in either.

**Prerequisites:** none. [methodology.md](methodology.md) for the location recipe.

---

## 1. What it is

A single large routine, called during launcher Lua initialisation, builds a global
Lua table named **`MPatch`** and populates it with base metadata plus a large
number of native callbacks.

It is entirely patch / filesystem / network / system glue — there is no renderer
or engine setup in it. That makes it a compact and complete map of the patcher's
native capabilities.

> Earlier notes named this doc after the routine's address in one build. Three
> separate notes recorded three different addresses across two binaries for the
> *same* routine. Addresses are worthless here; the recipe in §4 is not.

## 2. Base metadata fields

Written before the callbacks, and useful as an anchor because they cluster:

`Args`, `Version`, `IsLauncher`, `AppAssetPath`, `AppAssetPathUtf8`,
`AppLocalPath`, `AppLocalPathUtf8`, `Platform` (set to `"windows"` on PC builds).

## 3. Registered callbacks

### Filesystem — the trio pattern

The most structurally informative group. Most filesystem operations exist in
**three parallel namespaces**, telling you the launcher sees three distinct
storage domains:

- `*InSystem` — the real OS filesystem
- `*InPatch` — the patch VFS
- `*InPackage` — the packaged/shipped assets

```
FileExistIn{System,Patch,Package}    DirExistIn{System,Patch,Package}
GetRawDataIn{System,Patch,Package}   FileMD5In{Patch,Package}
FileSizeIn{System,Patch,Package}     FileTimeIn{System,Patch}
CreateFileIn{System,Patch}           DeleteFileIn{System,Patch}
CreateDirectoryIn{System,Patch}      DeleteDirectoryIn{System,Patch}
RenameFileInPatch
CopyFileAsync   CopyFileSync   ListDir
```

`ListDir` is the highest-value name in the whole table: **directory listing
implies an internal name registry.** MPK containers have no filenames, so
whatever `ListDir` walks is the closest thing to a recoverable directory, which
makes it the natural pressure point for the path-recovery problem.

### MPK index management

```
SetPatchMpkMode      GetPatchMpkMode        IsUsingMPK
AddPatchMpkEntry     AddBatchPatchMpkEntry  SetUseByteMpkEntry
AddPatchMpkEntryByMpkinfo   AddPatchMpkEntryByMpkinfos
ClearPatchMpkEntry   ClearPatchMpkIndexEntry   GetPatchMpkEntryCount
InitPatchMpkPackCache       InitLTMpkPackCache
CacheMpkIndexFile    CachePatchMpkIndexFile    CacheScriptMpkIndexFile
FreeCacheMpkIndexFile       FreeCachePatchMpkIndexFile
StartPatchLoaders    FixedPkgLT   EnableFastInitialize   IsFastInitialize
PatchRepositoryInfo
```

`AddPatchMpkEntryByMpkinfo` is the consumer of the `.mpkinfo` format
([mpkinfo-index.md](mpkinfo-index.md)) — a good entry point for confirming that
format against a new build. `CacheScriptMpkIndexFile` singling out *scripts* lines
up with the script-flagged rows in [patchdb.md](patchdb.md).

### Data transforms and hashing

```
GetContentMMH3                       -> content-hash.md
XorExcrypt                           -> patchdb.md §4 (repeating-key XOR)
ZipDecompress  ZipCompress  ZipDecompressFast   -> patchlist.md §1 (HEX_ chain)
JsonDecodeCompressData   MsgpackDecodeCompressData
```

Note `XorExcrypt` and `ZipDecompress` are **different primitives**; conflating
them is a documented past mistake. See [patchdb.md](patchdb.md) §5.

### Launcher / OS / network bridge

```
GetNetworkStatus  SetNetworkStatusChangedCallback
GetDeviceInfo  GetOsName  GetOsVersion  GetIpInfo  GetIspInfo  GetCountryCode
GetScreenWidth  GetScreenHeight  GetWinPatchAvailableSpace
GetClipboardText  SetClipboardText  GotoUrl
ShowPatcherAlert  ShowPatcherHint  SetPatcherAlertStyle
SetPatcherAlertCallback  SetPatcherRepairCallback
SetLauncherState  FinishPatch  ExitPatch  IsPausePatching
RemoveEngineSplash  UseSplitUITexture
DetectInit  DetectDiagnose  DetectGetPropStr  DetectSetPropStr
```

## 4. Locating the routine in a new build

1. `izz~MPatch` — find the table-name string.
2. `axt @ <str>` — the registration routine is the large function referencing it.
3. Confirm by shape: it pushes the table, writes the §2 metadata fields, then
   repeats a push-callback / set-field pair many dozens of times.

### The registration-order trap

**The callback pointer is pushed immediately *before* the name it belongs to.**

Reading the pointer that appears *after* a name attributes every callback to its
neighbour, shifting the whole table by one. This is exactly the error that
produced the `XorExcrypt` / `ZipDecompress` mix-up. Always confirm an attribution
independently — argument count is a cheap discriminator.

Helper functions used by the loop (push callback object, set table field by name,
push string value) are worth identifying once, since they make the pairing
unambiguous.

## 5. Adjacent code worth knowing

Near the registration routine sit:

- The `HEX_` / `HEXB_` prefix-recognising decode path, which compares a dword
  against those ASCII values — a reliable signature for finding the wrapper
  decoder ([patchlist.md](patchlist.md) §1).
- A reusable repeating-XOR helper backing `XorExcrypt`.
- A dotted version-check string. The literal changes per build, so search for
  the *shape* (a short `N.N.NN` string near the wrapper decoder), not a
  remembered value.
