# Building detect with xmake

This project has migrated from MSBuild / Visual Studio solutions to
[xmake](https://xmake.io). The repo is self-contained: every external
dependency is vendored under `ext/`, so the only thing a clean machine
needs is **xmake itself** and the standard MSVC build tools that ship
with Visual Studio (or just the Build Tools for Visual Studio package).

---

## 1. One-time setup

### 1a. Install Visual Studio Build Tools (MSVC) 2019/2022
Either Visual Studio with the **Desktop development with C++** workload,
or the standalone
[Build Tools for Visual Studio](https://visualstudio.microsoft.com/downloads/#build-tools-for-visual-studio-2022).

### 1b. Install xmake
PowerShell (one line, no admin):

```powershell
irm https://xmake.io/psget.text | iex
```

scoop / winget work too:

```powershell
scoop install xmake
# or
winget install xmake-io.xmake
```

Reopen your shell so `xmake` is on `PATH`, then `xmake --version` should
print a version number.

---

## 2. Build

Just run the interactive launcher from the repository root:

```powershell
.\build.ps1
```

You get a menu like this:

```
  detect.ac - select game variants to build

  number keys = toggle  |  A = toggle all  |  Ctrl+B = build  |  Esc = quit
  build mode: release

    [ ] 1.  minecraft
    [ ] 2.  siege
    [ ] 3.  gmod
    [ ] 4.  fivem
    [ ] 5.  freefire
    [ ] 6.  roblox
    [ ] 7.  fortnite
    [ ] 8.  cod
    [ ] 9.  rust
    [ ] 0.  dayz
    [ ] C.  cs

  nothing selected
```

Press the key next to a game to toggle it on (it becomes `[X]` and
turns green). The ten digits are all spoken for, so Counter-Strike is
toggled with **C** instead. Toggle as many as you want, then press
**Ctrl+B** to build every selected variant.

Each selected game ends up as a separate, ready-to-ship executable
under `build\detect\`:

```
build\detect\detect-fivem.exe
build\detect\detect-roblox.exe
build\detect\...
```

The per-game intermediate trees (object files, PCH, link inputs, ...)
live under `build\intermediate\<game>\`, so re-running the script with
the same selection later does an incremental rebuild — only files that
actually changed recompile.

### Common options

```powershell
# Debug binaries instead of release
.\build.ps1 -Mode debug

# Skip the menu (great for scripts/CI)
.\build.ps1 -Game fivem,roblox

# Override parallelism (defaults to logical CPU count)
.\build.ps1 -Jobs 16

# Enable xmake's local object cache - repeat builds become near-instant
.\build.ps1 -Game roblox -Cache

# Wipe every build / dist / cache folder
.\build.ps1 -Clean
```

### Speeding up compiles

Most of the heavy lifting is already wired into `xmake.lua`:

| What                                       | Why                                                       |
|--------------------------------------------|-----------------------------------------------------------|
| `/MP` on every target                      | Keeps `cl.exe` workers warm so the PCH isn't reloaded for every `.cpp`. |
| `xmake -j <cpu count>`                     | Parallel job pool, one `cl.exe` per source file at a time.|
| `set_pcxxheader("detect/pch.h")`           | The huge include block (`<Windows.h>` + every stdlib header) compiles once per target. |
| `/Zc:inline`                               | Drops unreferenced inline COMDATs early — smaller `.obj`, faster link. |
| One `build\intermediate\<game>\` per variant | Switching game variants doesn't blow away the previous game's incremental cache. |
| Debug mode: `/INCREMENTAL` + LTCG off      | Debug links stay snappy.                                 |
| `-Cache` (opt-in) -> `set_policy("build.ccache", true)` | xmake-local object cache. ~1s repeat builds.       |

Two extra things you should consider doing **once** on this machine —
they're outside the build system but make a big difference on Windows:

1. **Exclude the repo from Windows Defender real-time scanning.**
   The build writes thousands of small `.obj`/`.pch`/`.lib` files;
   AV scanning each one is often the biggest wall-clock cost. From an
   elevated PowerShell:

   ```powershell
   Add-MpPreference -ExclusionPath 'C:\detect-ss'
   ```

2. **Exclude `cl.exe` and `link.exe`** while you're at it:

   ```powershell
   $vs = (& "${env:ProgramFiles}\Microsoft Visual Studio\Installer\vswhere.exe" -latest -property installationPath)
   $tools = Get-ChildItem -Recurse -Path "$vs\VC\Tools\MSVC" -Filter cl.exe | Select-Object -ExpandProperty FullName
   $tools | ForEach-Object { Add-MpPreference -ExclusionProcess $_ }
   ```

After those exclusions, repeat cold builds typically drop by 30-50%.

Day-to-day workflow:

- After a clean first build, editing one `.cpp` and re-running
  `.\build.ps1 -Game <same>` only recompiles that file plus the link
  step (typically a few seconds).
- `.\build.ps1 -Game <same> -Cache` makes back-to-back identical
  rebuilds essentially free.

### Driving xmake by hand

If you want to bypass the launcher:

```powershell
xmake config -m release -p windows -a x64 --game=fivem --builddir=build\intermediate\fivem
xmake
# -> build\intermediate\fivem\windows\x64\release\detect.exe
```

A `--game=<name>` is **required** — there is no generic / default
build because `i_total_stages` is declared per-game inside `vars.h`.

---

## 3. Available game variants

| `--game=`   | `#define` added     |
|-------------|---------------------|
| `minecraft` | `DETECT_MINECRAFT`  |
| `siege`     | `DETECT_SIEGE`      |
| `gmod`      | `DETECT_GMOD`       |
| `fivem`     | `DETECT_FIVEM`      |
| `freefire`  | `DETECT_FREEFIRE`   |
| `roblox`    | `DETECT_ROBLOX`     |
| `fortnite`  | `DETECT_FORTNITE`   |
| `cod`       | `DETECT_COD`        |
| `rust`      | `DETECT_RUST`       |
| `dayz`      | `DETECT_DAYZ`       |

---

## 4. Where things live

| Path                     | What it is                                                  |
|--------------------------|-------------------------------------------------------------|
| `xmake.lua`              | Top-level build script.                                     |
| `build.ps1`              | Interactive launcher (this is what you run).                |
| `detect/`                | All source code.                                            |
| `detect/pch.h`           | Precompiled header used by most of `detect/**`.             |
| `detect/ImGui/`          | ImGui — built as a static lib (`imgui`).                    |
| `detect/detections/browser_detections/sqlite/` | SQLite — built as static lib (`sqlite3`). |
| `ext/include/`           | Vendored headers: curl, fmt, openssl, nlohmann, stb, yara.  |
| `ext/lib/`               | Vendored prebuilt static libs.                              |
| `build\intermediate\<game>\` | Per-game incremental build tree (gitignored).            |
| `build\detect\`          | Final game-tagged executables (gitignored).                 |
| `.xmake/`                | xmake's per-config cache (gitignored).                      |

---

## 5. IDE integration (optional)

xmake can emit projects / compile-commands for most IDEs:

```powershell
# VS Code / clangd / cursor: compile_commands.json
xmake project -k compile_commands

# A Visual Studio solution that drives xmake under the hood
xmake project -k vsxmake -m "debug,release"
```

(Run `xmake config --game=<one> ...` once before exporting so xmake
knows which variant to model.)

---

## 6. Troubleshooting

**`'cl.exe' is not recognized` / `MSVC not found`:**
Run from a *Developer PowerShell for VS*, or install the Visual Studio
Build Tools (see step 1a).

**`--game=<name> is required`:**
That's the xmake.lua telling you it won't build without a game
selected. Use `.\build.ps1` (it picks one for you), or pass
`--game=<name>` to `xmake config`.

**`fatal error LNK1104: cannot open file 'libyara64.lib'`:**
Make sure `ext/lib/libyara64.lib` and the `ext/include/yara*` folders
are present — they're committed in this repo. If they got nuked, copy
them back from an upstream yara 4.5.x x64 build (see the original
`detect.vcxproj` for the historic locations).

**`error C1010: unexpected end of file while looking for precompiled header`:**
A new `.cpp` was added that doesn't go through `pch.h`. Either
include `pch.h` at the top of the new file, or register it with
`{cxflags = "/Y-"}` in `xmake.lua` (look for the existing examples in
the `detect` target).

**The build links but `detect.exe` does nothing when double-clicked:**
The app requires Administrator privileges. Right-click ->
*Run as Administrator*, or launch it from an elevated PowerShell.
