# =============================================================================
#  detect - interactive multi-select builder
#
#  Run this with no arguments.  A menu appears showing every supported game
#  variant.  Press the number next to a game to toggle it on/off, then press
#  Ctrl+B to build everything that's selected.
#
#    Number keys 1..9, 0   - toggle a game in/out of the build set
#    C / c                 - toggle Counter-Strike (the digits are all used up)
#    A / a                 - toggle ALL games at once
#    Ctrl+B                - start building the selected variants
#    Esc / Q               - quit without building
#
#  Layout (everything build-related lives under  build/  now):
#    build\intermediate\<game>\  - per-game xmake build tree (object files,
#                                   .pch, link inputs, etc.)
#    build\detect\detect-<game>.exe
#                                - the final, shippable executable for each
#                                   variant.  This is what you double-click.
#
#  Switches (optional):
#    -Mode debug|release   - default: release
#    -Game <names>         - skip the menu and build these directly
#                             (e.g.  -Game fivem,roblox)
#    -Clean                - wipe build/.xmake caches and exit. Combine with
#                              -Game <names> to clean only those variants
#                              (per-game intermediate dir + detect-<game>.exe
#                              + matching .pdb), leaving everything else alone.
# =============================================================================
[CmdletBinding()]
param(
    [ValidateSet('debug','release')]
    [string]$Mode = 'release',

    [string[]]$Game,

    # Parallel compile jobs. Defaults to the number of logical CPUs.
    # Pass e.g. -Jobs 16 to push higher, -Jobs 1 to serialise for clearer
    # error output, etc.
    [int]$Jobs = [Environment]::ProcessorCount,

    # Enable xmake's local object cache. Great for repeated rebuilds
    # (~340s -> ~1s), but may slow down a cold build on Windows because
    # every .obj gets re-scanned by Defender. Off by default.
    [switch]$Cache,

    [switch]$Clean
)

$ErrorActionPreference = 'Stop'
Set-Location -Path $PSScriptRoot

# When this script is invoked through `powershell.exe -File ... -Game a,b,c`
# (e.g. from the Aegis packer's Build button or any other external launcher),
# PowerShell's -File mode does NOT split comma-separated values into array
# elements. We end up with $Game = @('a,b,c') instead of @('a','b','c').
# Normalise: split any element that still contains a comma and drop empties.
if ($Game) {
    $Game = @(
        $Game | ForEach-Object { $_ -split ',' } |
                ForEach-Object { $_.Trim() } |
                Where-Object { $_ -ne '' }
    )
}

# ---------------------------------------------------------------------------
#  All supported games (key = the digit you press to toggle it on the menu)
# ---------------------------------------------------------------------------
$Games = @(
    [pscustomobject]@{ Key = '1'; Name = 'minecraft' }
    [pscustomobject]@{ Key = '2'; Name = 'siege'     }
    [pscustomobject]@{ Key = '3'; Name = 'gmod'      }
    [pscustomobject]@{ Key = '4'; Name = 'fivem'     }
    [pscustomobject]@{ Key = '5'; Name = 'freefire'  }
    [pscustomobject]@{ Key = '6'; Name = 'roblox'    }
    [pscustomobject]@{ Key = '7'; Name = 'fortnite'  }
    [pscustomobject]@{ Key = '8'; Name = 'cod'       }
    [pscustomobject]@{ Key = '9'; Name = 'rust'      }
    [pscustomobject]@{ Key = '0'; Name = 'dayz'      }
    # Digits 1-9 and 0 are all taken, so this one is toggled with the 'C' key.
    # Anything that isn't a digit works here -- Read-MenuSelection just looks
    # the pressed character up in the $selected table (and 'a'/'q' are already
    # intercepted above it for toggle-all / quit).
    [pscustomobject]@{ Key = 'C'; Name = 'cs'        }
)
$ValidNames = $Games.Name

# ---------------------------------------------------------------------------
#  Helpers
# ---------------------------------------------------------------------------
$script:MsvcToolsetVer = $null

function Initialize-MsvcEnvironment {
    # xmake's MSVC auto-detection runs its own copy of vcvars64.bat to capture
    # INCLUDE/LIB/PATH for cl.exe -- it ignores whatever env vars we set in
    # PowerShell beforehand. On VS 2026 (v18) installs that's a problem on
    # two fronts:
    #   1. xmake 3.0.9 only knows VS versions up to 2022 (v17); from a clean
    #      shell its detection fails entirely ("checking for cl.exe ... no").
    #   2. Even when xmake DOES find cl.exe, its captured INCLUDE can point
    #      at a phantom toolset version (e.g. 14.52.36328) that was reported
    #      by some MSBuild props file but doesn't exist on disk. cl.exe then
    #      fails at the first system header with C1083 "stdarg.h" / "vcruntime.h".
    # The fix is twofold:
    #   - Load vcvars64.bat into THIS session so xmake at least finds cl.exe
    #     via PATH when its own detection can't recognise the VS version.
    #   - Discover the newest toolset that physically exists and remember it
    #     so Build-One can pass `--vs_toolset=<ver>` to xmake config, which
    #     forces xmake's own vcvars invocation to that real version.
    if (Get-Command cl.exe -ErrorAction SilentlyContinue) { return }

    $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (-not (Test-Path $vswhere)) {
        $vswhere = "${env:ProgramFiles}\Microsoft Visual Studio\Installer\vswhere.exe"
    }
    if (-not (Test-Path $vswhere)) { return }

    $vsRoot = & $vswhere -latest -prerelease -products * `
        -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
        -property installationPath 2>$null | Select-Object -First 1
    if (-not $vsRoot) { return }

    $vcVars = Join-Path $vsRoot 'VC\Auxiliary\Build\vcvars64.bat'
    if (-not (Test-Path $vcVars)) { return }

    $toolsetDir = Join-Path $vsRoot 'VC\Tools\MSVC'
    $vcVarsVer = $null
    if (Test-Path $toolsetDir) {
        $candidates = @()
        foreach ($d in Get-ChildItem $toolsetDir -Directory -ErrorAction SilentlyContinue) {
            if ((Test-Path (Join-Path $d.FullName 'include\vcruntime.h')) -and
                (Test-Path (Join-Path $d.FullName 'bin\Hostx64\x64\cl.exe'))) {
                try {
                    $parts = $d.Name -split '\.' | ForEach-Object { [int]$_ }
                    $candidates += [pscustomobject]@{ Name = $d.Name; Sort = $parts }
                } catch { }
            }
        }
        $vcVarsVer = ($candidates |
            Sort-Object @{Expression={$_.Sort[0]}}, @{Expression={$_.Sort[1]}}, @{Expression={$_.Sort[2]}} -Descending |
            Select-Object -First 1).Name
    }

    Write-Host ""
    if ($vcVarsVer) {
        Write-Host ("==>  loading MSVC environment from " + $vsRoot + " (toolset " + $vcVarsVer + ")") -ForegroundColor DarkGray
    } else {
        Write-Host ("==>  loading MSVC environment from " + $vsRoot) -ForegroundColor DarkGray
    }

    $vcVarsArgs = if ($vcVarsVer) { "-vcvars_ver=$vcVarsVer" } else { "" }
    $envDump = & cmd /c "`"$vcVars`" $vcVarsArgs >NUL 2>&1 && set" 2>$null
    foreach ($line in $envDump) {
        if ($line -match '^([^=]+)=(.*)$') {
            [Environment]::SetEnvironmentVariable($Matches[1], $Matches[2], 'Process')
        }
    }

    $script:MsvcToolsetVer = $vcVarsVer
}

function Resolve-Xmake {
    # Prefer xmake on PATH; fall back to the default install location used
    # by the official PowerShell installer.
    $cmd = Get-Command xmake -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }

    $fallback = Join-Path $env:USERPROFILE 'xmake\xmake.exe'
    if (Test-Path $fallback) {
        $env:Path = "$(Split-Path $fallback);$env:Path"
        return $fallback
    }

    Write-Host ""
    Write-Host "xmake is not installed (or not on PATH)." -ForegroundColor Yellow
    Write-Host "Install it once with this PowerShell one-liner:" -ForegroundColor Yellow
    Write-Host '    irm https://xmake.io/psget.text | iex' -ForegroundColor Cyan
    Write-Host "Then reopen this terminal and try again." -ForegroundColor Yellow
    throw "xmake not installed"
}

function Draw-Menu($selected) {
    Clear-Host
    Write-Host ""
    Write-Host "  detect.ac - select game variants to build" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  number/letter keys = toggle  |  A = toggle all  |  Ctrl+B = build  |  Esc = quit" -ForegroundColor DarkGray
    Write-Host "  build mode: " -NoNewline -ForegroundColor DarkGray
    Write-Host $Mode -NoNewline -ForegroundColor Yellow
    Write-Host "    jobs: " -NoNewline -ForegroundColor DarkGray
    Write-Host $Jobs -ForegroundColor Yellow
    Write-Host ""

    foreach ($g in $Games) {
        if ($selected[$g.Key]) {
            Write-Host ("    [X] " + $g.Key + ".  " + $g.Name) -ForegroundColor Green
        } else {
            Write-Host ("    [ ] " + $g.Key + ".  " + $g.Name) -ForegroundColor Gray
        }
    }

    $count = ($selected.Values | Where-Object { $_ }).Count
    Write-Host ""
    if ($count -eq 0) {
        Write-Host "  nothing selected" -ForegroundColor DarkGray
    } else {
        $names = ($Games | Where-Object { $selected[$_.Key] } | ForEach-Object { $_.Name }) -join ', '
        Write-Host ("  selected ($count): " + $names) -ForegroundColor Green
    }
    Write-Host ""
}

function Read-MenuSelection {
    $selected = @{}
    foreach ($g in $Games) { $selected[$g.Key] = $false }

    while ($true) {
        Draw-Menu $selected
        $key = [System.Console]::ReadKey($true)

        # Ctrl+B -> start building
        if ($key.Key -eq [System.ConsoleKey]::B -and
            ($key.Modifiers -band [System.ConsoleModifiers]::Control)) {
            $count = ($selected.Values | Where-Object { $_ }).Count
            if ($count -eq 0) {
                Write-Host "  pick at least one game first." -ForegroundColor Yellow
                Start-Sleep -Milliseconds 900
                continue
            }
            return ,($Games | Where-Object { $selected[$_.Key] })
        }

        # Esc / Q -> quit
        if ($key.Key -eq [System.ConsoleKey]::Escape -or
            $key.KeyChar -eq 'q' -or $key.KeyChar -eq 'Q') {
            Write-Host "  cancelled." -ForegroundColor DarkGray
            return @()
        }

        # A -> toggle all
        if ($key.KeyChar -eq 'a' -or $key.KeyChar -eq 'A') {
            $allOn = ($selected.Values | Where-Object { $_ }).Count -eq $Games.Count
            foreach ($g in $Games) { $selected[$g.Key] = -not $allOn }
            continue
        }

        # number key -> toggle that game
        $ch = "$($key.KeyChar)"
        if ($selected.ContainsKey($ch)) {
            $selected[$ch] = -not $selected[$ch]
        }
    }
}

function Build-One($gameName) {
    # Per-game intermediate tree lives under build/intermediate/<game>/.
    # Keeping each variant in its own subtree means switching games doesn't
    # invalidate the previous variant's .obj/.pch cache.
    $builddir = Join-Path $PSScriptRoot ("build\intermediate\" + $gameName)

    Write-Host ""
    Write-Host ("==>  building $gameName ($Mode, -j$Jobs)") -ForegroundColor Cyan

    $cacheArg = if ($Cache) { 'y' } else { 'n' }
    $toolsetArg = @()
    if ($script:MsvcToolsetVer) { $toolsetArg = @("--vs_toolset=$($script:MsvcToolsetVer)") }
    & xmake config -m $Mode -p windows -a x64 `
        --game=$gameName "--builddir=$builddir" "--ccache=$cacheArg" `
        @toolsetArg -y
    if ($LASTEXITCODE -ne 0) { throw "xmake config failed for $gameName" }

    & xmake -j $Jobs -y
    if ($LASTEXITCODE -ne 0) { throw "xmake build failed for $gameName" }

    # xmake.lua does set_basename("detect-<game>") in the detect target's
    # on_load, so both the exe and the matching pdb come out tagged with
    # the game name. We copy BOTH next to each other in build/detect/ --
    # tools like aegis read the PDB filename out of the exe's debug
    # directory and look for it next to the exe, so the matching basenames
    # mean no symbol-server config is needed.
    $exeName = "detect-" + $gameName + ".exe"
    $pdbName = "detect-" + $gameName + ".pdb"
    $srcExe  = Join-Path $builddir ("windows\x64\$Mode\" + $exeName)
    $srcPdb  = Join-Path $builddir ("windows\x64\$Mode\" + $pdbName)
    if (-not (Test-Path $srcExe)) {
        throw "build claimed success but $srcExe is missing"
    }

    # Final shippable exe lands in build/detect/detect-<game>.exe so all
    # the game-tagged binaries sit side-by-side in one place.
    $outDir = Join-Path $PSScriptRoot 'build\detect'
    New-Item -ItemType Directory -Force -Path $outDir | Out-Null
    $dstExe = Join-Path $outDir $exeName
    $dstPdb = Join-Path $outDir $pdbName
    Copy-Item -LiteralPath $srcExe -Destination $dstExe -Force
    if (Test-Path $srcPdb) {
        Copy-Item -LiteralPath $srcPdb -Destination $dstPdb -Force
    } else {
        # If we ever lose the pdb the build would still "succeed" but
        # aegis will refuse to pack. Make this loud rather than silent.
        Write-Host ("    WARN: missing $srcPdb -- aegis pack may fail") `
            -ForegroundColor Yellow
    }

    Write-Host ("    ok  ->  " + $dstExe) -ForegroundColor Green
}

# ---------------------------------------------------------------------------
#  Entry point
# ---------------------------------------------------------------------------
Resolve-Xmake | Out-Null
Initialize-MsvcEnvironment

if ($Clean) {
    # Per-game clean: -Clean -Game x,y,z removes ONLY the build artifacts that
    # belong to the listed variants -- the matching intermediate tree under
    # build\intermediate\<game>\, the shippable build\detect\detect-<game>.exe
    # (+ .pdb), and the legacy build-<game>\ / dist\<game>\ folders if any
    # are still hanging around from an older checkout. Other variants keep
    # all of their compiled state, so an incremental rebuild stays fast.
    if ($Game) {
        foreach ($name in $Game) {
            if ($ValidNames -notcontains $name) {
                throw "unknown game '$name'. Valid: $($ValidNames -join ', ')"
            }
        }
        Write-Host ("cleaning build outputs for: " + ($Game -join ', ') + "...") -ForegroundColor Yellow
        foreach ($name in $Game) {
            $candidates = @(
                (Join-Path $PSScriptRoot ("build\intermediate\" + $name)),
                (Join-Path $PSScriptRoot ("build\detect\detect-" + $name + ".exe")),
                (Join-Path $PSScriptRoot ("build\detect\detect-" + $name + ".pdb")),
                (Join-Path $PSScriptRoot ("build-" + $name)),
                (Join-Path $PSScriptRoot ("dist\" + $name))
            )
            $hit = $false
            foreach ($p in $candidates) {
                if (Test-Path -LiteralPath $p) {
                    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue -LiteralPath $p
                    Write-Host ("  removed: " + $p) -ForegroundColor DarkGray
                    $hit = $true
                }
            }
            if (-not $hit) {
                Write-Host ("  $name : nothing to remove") -ForegroundColor DarkGray
            }
        }
        Write-Host "done." -ForegroundColor Green
        return
    }

    Write-Host "cleaning build outputs..." -ForegroundColor Yellow
    & xmake clean -a 2>&1 | Out-Null
    # New layout (build\intermediate, build\detect) AND legacy layout
    # (build-<game>\, dist\) -- wipe both so a clean still works on an
    # older checkout that hasn't been rebuilt yet.
    Get-ChildItem -Directory -Path $PSScriptRoot -Filter 'build-*' -ErrorAction SilentlyContinue |
        ForEach-Object { Remove-Item -Recurse -Force $_.FullName }
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue (Join-Path $PSScriptRoot 'build')
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue (Join-Path $PSScriptRoot 'dist')
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue (Join-Path $PSScriptRoot '.xmake')
    Write-Host "done." -ForegroundColor Green
    return
}

# Either non-interactive (-Game minecraft,roblox) or interactive menu
if ($Game) {
    $picked = @()
    foreach ($name in $Game) {
        if ($ValidNames -notcontains $name) {
            throw "unknown game '$name'. Valid: $($ValidNames -join ', ')"
        }
        $picked += ,($Games | Where-Object { $_.Name -eq $name })
    }
} else {
    $picked = Read-MenuSelection
    if (-not $picked -or $picked.Count -eq 0) { return }
}

# Build each selection in turn
$results = @()
foreach ($g in $picked) {
    try {
        Build-One $g.Name
        $results += [pscustomobject]@{ Name = $g.Name; Status = 'ok' }
    } catch {
        Write-Host ("    FAIL: " + $_.Exception.Message) -ForegroundColor Red
        $results += [pscustomobject]@{ Name = $g.Name; Status = 'fail' }
    }
}

# Summary
Write-Host ""
Write-Host "==>  build summary" -ForegroundColor Cyan
foreach ($r in $results) {
    if ($r.Status -eq 'ok') {
        Write-Host ("    [ok]   " + $r.Name) -ForegroundColor Green
    } else {
        Write-Host ("    [FAIL] " + $r.Name) -ForegroundColor Red
    }
}
Write-Host ""
Write-Host ("    artifacts: " + (Join-Path $PSScriptRoot 'build\detect')) -ForegroundColor DarkGray
Write-Host ""
