# SymForge Windows Installer (Pure .NET — Zero PSModulePath Dependency)
# Usage: irm https://raw.githubusercontent.com/aloneangel45/SymForge/main/install.ps1 | iex
$ErrorActionPreference = 'Stop'

if (-not ('System.IO.Compression.ZipFile' -as [type])) {
    [void][System.Reflection.Assembly]::LoadWithPartialName('System.IO.Compression.FileSystem')
}

$Repo = if ($env:SYMFORGE_REPO) { $env:SYMFORGE_REPO } else { 'aloneangel45/SymForge' }
$Version = if ($env:SYMFORGE_VERSION) { $env:SYMFORGE_VERSION } else { 'latest' }
$BaseUrl = if ($env:SYMFORGE_BASE_URL) { $env:SYMFORGE_BASE_URL } else { "https://github.com/$Repo/releases" }

$ArchRaw = if ($env:SYMFORGE_ARCH_OVERRIDE) {
    $env:SYMFORGE_ARCH_OVERRIDE
} elseif ($env:PROCESSOR_ARCHITEW6432) {
    $env:PROCESSOR_ARCHITEW6432
} else {
    $env:PROCESSOR_ARCHITECTURE
}

$Arch = switch -Regex ($ArchRaw) {
    '^(AMD64|x86_64|amd64)$' { 'amd64'; break }
    '^(ARM64|aarch64|arm64)$' { 'arm64'; break }
    default { throw "[symforge] Unsupported Windows architecture: $ArchRaw" }
}

$Archive = "symforge-windows-$Arch.zip"
if ($Version -eq 'latest') {
    $DlPrefix = "$BaseUrl/latest/download"
} else {
    $Tag = if ($Version.StartsWith('v')) { $Version } else { "v$Version" }
    $DlPrefix = "$BaseUrl/download/$Tag"
}

$InstallDir = if ($env:SYMFORGE_INSTALL_DIR) {
    $env:SYMFORGE_INSTALL_DIR
} else {
    [System.IO.Path]::Combine($env:LOCALAPPDATA, 'Programs', 'symforge', 'bin')
}

$TmpDir = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), "symforge-install-" + [System.Guid]::NewGuid().ToString('N'))
[void][System.IO.Directory]::CreateDirectory($TmpDir)

function Download-SymForgeFile([string]$Url, [string]$Dest) {
    if ($Url.StartsWith('file://', [System.StringComparison]::OrdinalIgnoreCase)) {
        $LocalSrc = ([System.Uri]$Url).LocalPath
        [System.IO.File]::Copy($LocalSrc, $Dest, $true)
        return
    }
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12
    $wc = New-Object System.Net.WebClient
    try {
        $wc.DownloadFile($Url, $Dest)
    } finally {
        $wc.Dispose()
    }
}

function Compute-Sha256Hex([string]$FilePath) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $stream = [System.IO.File]::OpenRead($FilePath)
    try {
        $hashBytes = $sha.ComputeHash($stream)
        return ([System.BitConverter]::ToString($hashBytes)).Replace('-', '').ToLowerInvariant()
    } finally {
        $stream.Dispose()
        $sha.Dispose()
    }
}

try {
    $ZipPath = [System.IO.Path]::Combine($TmpDir, $Archive)
    $SumPath = [System.IO.Path]::Combine($TmpDir, 'checksums.txt')

    [Console]::WriteLine("[symforge] Downloading $Archive from $DlPrefix...")
    Download-SymForgeFile "$DlPrefix/$Archive" $ZipPath
    Download-SymForgeFile "$DlPrefix/checksums.txt" $SumPath

    $Expected = $null
    foreach ($line in [System.IO.File]::ReadAllLines($SumPath)) {
        $trimmed = $line.Trim()
        if ([string]::IsNullOrWhiteSpace($trimmed)) { continue }
        $parts = $trimmed -split '\s+', 2
        if ($parts.Length -eq 2) {
            $fname = $parts[1].TrimStart('*')
            if ($fname -eq $Archive) {
                $Expected = $parts[0].ToLowerInvariant()
                break
            }
        }
    }

    if (-not $Expected) {
        throw "[symforge] Entry for $Archive not found in checksums.txt"
    }

    $Actual = Compute-Sha256Hex $ZipPath
    if ($Actual -ne $Expected) {
        throw "[symforge] SHA-256 mismatch for $Archive (expected $Expected, got $Actual)"
    }

    $ExtractDir = [System.IO.Path]::Combine($TmpDir, 'extracted')
    [System.IO.Compression.ZipFile]::ExtractToDirectory($ZipPath, $ExtractDir)

    $ExeSrc = [System.IO.Path]::Combine($ExtractDir, 'symforge.exe')
    if (-not [System.IO.File]::Exists($ExeSrc)) {
        throw "[symforge] symforge.exe missing from archive $Archive"
    }

    [void][System.IO.Directory]::CreateDirectory($InstallDir)
    $ExeDest = [System.IO.Path]::Combine($InstallDir, 'symforge.exe')
    if ([System.IO.File]::Exists($ExeDest)) {
        $attrs = [System.IO.File]::GetAttributes($ExeDest)
        if (($attrs -band [System.IO.FileAttributes]::ReadOnly) -ne 0) {
            [System.IO.File]::SetAttributes($ExeDest, ($attrs -band (-bnot [System.IO.FileAttributes]::ReadOnly)))
        }
    }
    [System.IO.File]::Copy($ExeSrc, $ExeDest, $true)

    if (-not $env:SYMFORGE_SKIP_PATH) {
        $UserPath = [System.Environment]::GetEnvironmentVariable('Path', 'User')
        if (-not $UserPath) { $UserPath = '' }
        $Entries = @()
        foreach ($seg in ($UserPath -split ';')) {
            if ($seg -ne '') { $Entries += $seg }
        }
        $AlreadyPresent = $false
        foreach ($e in $Entries) {
            if ([string]::Equals($e.TrimEnd('\'), $InstallDir.TrimEnd('\'), [System.StringComparison]::OrdinalIgnoreCase)) {
                $AlreadyPresent = $true
                break
            }
        }
        if (-not $AlreadyPresent) {
            $NewPath = if ($UserPath.EndsWith(';') -or $UserPath -eq '') { "$UserPath$InstallDir" } else { "$UserPath;$InstallDir" }
            [System.Environment]::SetEnvironmentVariable('Path', $NewPath, 'User')
            $env:Path = "$env:Path;$InstallDir"
        }
    }

    [Console]::WriteLine("[symforge] Installed successfully to $ExeDest")
} finally {
    if ([System.IO.Directory]::Exists($TmpDir)) {
        [System.IO.Directory]::Delete($TmpDir, $true)
    }
}
