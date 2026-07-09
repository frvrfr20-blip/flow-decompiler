param(
    [switch]$Uninstall,
    [switch]$NoDesktopShortcut
)

$ErrorActionPreference = "Stop"

$AppName = "Flow Decompiler"
$InstallRoot = Join-Path $env:LOCALAPPDATA "FlowDecompiler"
$VenvRoot = Join-Path $InstallRoot ".venv"
$ProjectRoot = $PSScriptRoot
$StartMenuDir = Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs\Flow Decompiler"
$DesktopShortcut = Join-Path ([Environment]::GetFolderPath("Desktop")) "Flow Decompiler.lnk"
$StartMenuShortcut = Join-Path $StartMenuDir "Flow Decompiler.lnk"

function Remove-FlowDecompiler {
    Remove-Item -LiteralPath $DesktopShortcut -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $StartMenuShortcut -Force -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath $StartMenuDir) {
        Remove-Item -LiteralPath $StartMenuDir -Force -Recurse
    }
    if (Test-Path -LiteralPath $InstallRoot) {
        Remove-Item -LiteralPath $InstallRoot -Force -Recurse
    }
    Write-Host "Flow Decompiler removed."
}

function Get-PythonLauncher {
    $commands = @(
        @{ File = "py"; Args = @("-3") },
        @{ File = "python"; Args = @() },
        @{ File = "python3"; Args = @() }
    )

    foreach ($command in $commands) {
        $candidate = Get-Command $command.File -ErrorAction SilentlyContinue
        if ($null -eq $candidate) {
            continue
        }
        & $command.File @($command.Args + @("-c", "import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)")) | Out-Null
        if ($LASTEXITCODE -eq 0) {
            return $command
        }
    }

    throw "Python 3.10 or newer is required."
}

function New-Shortcut {
    param(
        [string]$Path,
        [string]$Target,
        [string]$Arguments,
        [string]$WorkingDirectory
    )

    $shell = New-Object -ComObject WScript.Shell
    $shortcut = $shell.CreateShortcut($Path)
    $shortcut.TargetPath = $Target
    $shortcut.Arguments = $Arguments
    $shortcut.WorkingDirectory = $WorkingDirectory
    $shortcut.Description = $AppName
    $shortcut.Save()
}

if ($Uninstall) {
    Remove-FlowDecompiler
    exit 0
}

$python = Get-PythonLauncher
New-Item -ItemType Directory -Path $InstallRoot, $StartMenuDir -Force | Out-Null

if (-not (Test-Path -LiteralPath (Join-Path $VenvRoot "Scripts\python.exe"))) {
    & $python.File @($python.Args + @("-m", "venv", $VenvRoot))
}

$VenvPython = Join-Path $VenvRoot "Scripts\python.exe"
$VenvPythonw = Join-Path $VenvRoot "Scripts\pythonw.exe"
& $VenvPython -m pip install --upgrade pip
& $VenvPython -m pip install $ProjectRoot

New-Shortcut -Path $StartMenuShortcut -Target $VenvPythonw -Arguments "-m luau_decompiler.ui" -WorkingDirectory $InstallRoot
if (-not $NoDesktopShortcut) {
    New-Shortcut -Path $DesktopShortcut -Target $VenvPythonw -Arguments "-m luau_decompiler.ui" -WorkingDirectory $InstallRoot
}

Write-Host "Flow Decompiler installed."
Write-Host "Start Menu: $StartMenuShortcut"
if (-not $NoDesktopShortcut) {
    Write-Host "Desktop: $DesktopShortcut"
}
Write-Host "CLI: $VenvPython -m luau_decompiler <file>"
