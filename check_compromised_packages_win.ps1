# ============================================================
# LiteLLM / Telnyx サプライチェーン攻撃 チェックスクリプト (Windows / PowerShell)
# 対象: litellm v1.82.7 / v1.82.8 (2026-03-24 公開、TeamPCP による侵害)
#       telnyx  v4.87.1 / v4.87.2 (2026-03-27 公開、TeamPCP による侵害)
# 参考: https://docs.litellm.ai/blog/security-update-march-2026
#       https://futuresearch.ai/blog/litellm-pypi-supply-chain-attack/
#       https://futuresearch.ai/blog/telnyx-compromise/
#
# 使い方:
#   .\check_compromised_packages_win.ps1                                    # 既定の共通インストール先をスキャン
#   .\check_compromised_packages_win.ps1 -ScanDirs "C:\dev"                 # 特定フォルダ
#   .\check_compromised_packages_win.ps1 -ScanDirs "$env:USERPROFILE","D:\projects"
#   .\check_compromised_packages_win.ps1 -SkipDocker                        # Docker スキャンを省略
# ============================================================

param(
    [string[]]$ScanDirs = @(),
    [switch]$SkipDocker
)

$found = $false
$litellmActiveChecked = $false
$telnyxActiveChecked = $false
$BAD_LITELLM_VERSIONS = @("1.82.7", "1.82.8")
$BAD_TELNYX_VERSIONS = @("4.87.1", "4.87.2")

function Add-ScanDir {
    param(
        [System.Collections.Generic.List[string]]$Collection,
        [string]$PathValue
    )

    if ([string]::IsNullOrWhiteSpace($PathValue)) { return }
    if (-not (Test-Path -LiteralPath $PathValue)) { return }
    if (-not $Collection.Contains($PathValue)) {
        [void]$Collection.Add($PathValue)
    }
}

function Get-DefaultScanDirs {
    $dirs = [System.Collections.Generic.List[string]]::new()
    $candidates = @()

    if ($env:USERPROFILE) { $candidates += $env:USERPROFILE }
    if ($env:LOCALAPPDATA) {
        $candidates += (Join-Path $env:LOCALAPPDATA "Programs\Python")
        $candidates += (Join-Path $env:LOCALAPPDATA "pypoetry\Cache\virtualenvs")
    }
    if ($env:ProgramFiles) { $candidates += "$env:ProgramFiles\Python*" }
    if (${env:ProgramFiles(x86)}) { $candidates += "${env:ProgramFiles(x86)}\Python*" }
    if ($env:ProgramData) {
        $candidates += "$env:ProgramData\anaconda3"
        $candidates += "$env:ProgramData\miniconda3"
    }

    foreach ($candidate in $candidates) {
        if ([string]::IsNullOrWhiteSpace($candidate)) { continue }
        if ($candidate.Contains("*")) {
            foreach ($match in Get-ChildItem -Path $candidate -Directory -ErrorAction SilentlyContinue) {
                Add-ScanDir -Collection $dirs -PathValue $match.FullName
            }
            continue
        }

        Add-ScanDir -Collection $dirs -PathValue $candidate
    }

    return $dirs.ToArray()
}

function Test-BadLitellmVersion {
    param([string]$Version)
    return $Version -in $BAD_LITELLM_VERSIONS
}

function Test-BadTelnyxVersion {
    param([string]$Version)
    return $Version -in $BAD_TELNYX_VERSIONS
}

function Show-InstalledVersion {
    param(
        [string]$PackageName,
        [string]$Label,
        [string[]]$CommandParts
    )

    try {
        if (-not $CommandParts -or $CommandParts.Count -eq 0) { return }

        $commandName = $CommandParts[0]
        $commandArgs = @()
        if ($CommandParts.Count -gt 1) {
            $commandArgs = $CommandParts[1..($CommandParts.Count - 1)]
        }

        $output = & $commandName @commandArgs show $PackageName 2>$null
        if ($output) {
            switch ($PackageName) {
                "litellm" { $script:litellmActiveChecked = $true }
                "telnyx"  { $script:telnyxActiveChecked = $true }
            }
            $versionLine = $output | Select-String "^Version:" | Select-Object -First 1
            $locationLine = $output | Select-String "^Location:" | Select-Object -First 1
            $version = if ($versionLine) { $versionLine.ToString().Split(":")[1].Trim() } else { "" }
            $location = if ($locationLine) { $locationLine.ToString().Split(":", 2)[1].Trim() } else { "unknown" }

            $isBad = switch ($PackageName) {
                "litellm" { Test-BadLitellmVersion $version }
                "telnyx"  { Test-BadTelnyxVersion $version }
                default   { $false }
            }

            if ($isBad) {
                Write-Host "  !! 危険: $PackageName $version @ $location [$Label]" -ForegroundColor Red
                $script:found = $true
            } elseif ($version) {
                Write-Host "  OK: $PackageName $version @ $location [$Label]" -ForegroundColor Green
            }
        }
    } catch {}
}

function Get-DockerShowOutput {
    param(
        [string]$ImageRef,
        [string]$PackageName
    )

    $commands = @(
        @("pip", "show", $PackageName),
        @("pip3", "show", $PackageName),
        @("python", "-m", "pip", "show", $PackageName),
        @("python3", "-m", "pip", "show", $PackageName)
    )

    foreach ($command in $commands) {
        try {
            $dockerArgs = @("run", "--rm", "--entrypoint", "", $ImageRef) + $command
            $result = & docker @dockerArgs 2>$null
            if ($result) {
                return $result
            }
        } catch {}
    }

    return $null
}

function Get-DockerPthHits {
    param([string]$ImageRef)

    try {
        return & docker run --rm --entrypoint "" $ImageRef find / -name "litellm_init.pth" -type f 2>$null
    } catch {
        return $null
    }
}

function Join-OptionalPath {
    param(
        [string]$BasePath,
        [string]$ChildPath
    )

    if ([string]::IsNullOrWhiteSpace($BasePath)) {
        return $null
    }

    return (Join-Path $BasePath $ChildPath)
}

if (-not $ScanDirs -or $ScanDirs.Count -eq 0) {
    $ScanDirs = Get-DefaultScanDirs
}

Write-Host ""
Write-Host "=================================================" -ForegroundColor Cyan
Write-Host " LiteLLM / Telnyx 侵害チェック (Windows)"        -ForegroundColor Cyan
Write-Host "=================================================" -ForegroundColor Cyan
Write-Host ""

if ($ScanDirs.Count -gt 0) {
    Write-Host "スキャン対象: $($ScanDirs -join ', ')" -ForegroundColor Gray
} else {
    Write-Host "WARN: 有効なスキャン対象ディレクトリがありません" -ForegroundColor Yellow
}
Write-Host ""

# ----------------------------------------------------------
# 1. 現在アクティブな環境の litellm バージョン確認
# ----------------------------------------------------------
Write-Host "[1/9] アクティブ環境の litellm / telnyx バージョンを確認中..." -ForegroundColor Yellow

if (Get-Command pip -ErrorAction SilentlyContinue) { Show-InstalledVersion -PackageName "litellm" -Label "pip" -CommandParts @("pip") }
if (Get-Command pip3 -ErrorAction SilentlyContinue) { Show-InstalledVersion -PackageName "litellm" -Label "pip3" -CommandParts @("pip3") }
if (Get-Command python -ErrorAction SilentlyContinue) { Show-InstalledVersion -PackageName "litellm" -Label "python -m pip" -CommandParts @("python", "-m", "pip") }
if (Get-Command py -ErrorAction SilentlyContinue) { Show-InstalledVersion -PackageName "litellm" -Label "py -m pip" -CommandParts @("py", "-m", "pip") }
if (Get-Command uv -ErrorAction SilentlyContinue) { Show-InstalledVersion -PackageName "litellm" -Label "uv pip" -CommandParts @("uv", "pip") }

if (Get-Command pip -ErrorAction SilentlyContinue) { Show-InstalledVersion -PackageName "telnyx" -Label "pip" -CommandParts @("pip") }
if (Get-Command pip3 -ErrorAction SilentlyContinue) { Show-InstalledVersion -PackageName "telnyx" -Label "pip3" -CommandParts @("pip3") }
if (Get-Command python -ErrorAction SilentlyContinue) { Show-InstalledVersion -PackageName "telnyx" -Label "python -m pip" -CommandParts @("python", "-m", "pip") }
if (Get-Command py -ErrorAction SilentlyContinue) { Show-InstalledVersion -PackageName "telnyx" -Label "py -m pip" -CommandParts @("py", "-m", "pip") }
if (Get-Command uv -ErrorAction SilentlyContinue) { Show-InstalledVersion -PackageName "telnyx" -Label "uv pip" -CommandParts @("uv", "pip") }

if (-not $litellmActiveChecked) {
    Write-Host "  INFO: アクティブ環境に litellm はインストールされていません" -ForegroundColor Gray
}
if (-not $telnyxActiveChecked) {
    Write-Host "  INFO: アクティブ環境に telnyx はインストールされていません" -ForegroundColor Gray
}

# ----------------------------------------------------------
# 2. 仮想環境を横断して litellm の全インストール箇所を一覧表示
# ----------------------------------------------------------
Write-Host "[2/9] 仮想環境内の litellm / telnyx を横断検索中..." -ForegroundColor Yellow
Write-Host "  （ディスク容量によっては数分かかります）" -ForegroundColor Gray

$litellmVenvCount = 0
$telnyxVenvCount = 0

foreach ($scanDir in $ScanDirs) {
    if (-not (Test-Path -LiteralPath $scanDir)) { continue }

    $metadataFiles = Get-ChildItem -Path $scanDir -Recurse -Filter "METADATA" -ErrorAction SilentlyContinue |
        Where-Object { $_.DirectoryName -match "litellm-[\d.]+\.dist-info" }

    foreach ($meta in $metadataFiles) {
        $litellmVenvCount++
        $metaContent = Get-Content $meta.FullName -ErrorAction SilentlyContinue
        $versionLine = $metaContent | Select-String "^Version:" | Select-Object -First 1
        if ($versionLine) {
            $version = $versionLine.ToString().Split(":")[1].Trim()
            $distInfoDir = $meta.DirectoryName
            if (Test-BadLitellmVersion $version) {
                Write-Host "  !! 危険: litellm $version @ $distInfoDir" -ForegroundColor Red
                $found = $true
            } else {
                Write-Host "  OK: litellm $version @ $distInfoDir" -ForegroundColor DarkGreen
            }
        }
    }

    $telnyxMetadataFiles = Get-ChildItem -Path $scanDir -Recurse -Filter "METADATA" -ErrorAction SilentlyContinue |
        Where-Object { $_.DirectoryName -match "telnyx-[\d.]+\.dist-info" }

    foreach ($meta in $telnyxMetadataFiles) {
        $telnyxVenvCount++
        $metaContent = Get-Content $meta.FullName -ErrorAction SilentlyContinue
        $versionLine = $metaContent | Select-String "^Version:" | Select-Object -First 1
        if ($versionLine) {
            $version = $versionLine.ToString().Split(":")[1].Trim()
            $distInfoDir = $meta.DirectoryName
            if (Test-BadTelnyxVersion $version) {
                Write-Host "  !! 危険: telnyx $version @ $distInfoDir" -ForegroundColor Red
                $found = $true
            } else {
                Write-Host "  OK: telnyx $version @ $distInfoDir" -ForegroundColor DarkGreen
            }
        }
    }
}

if ($litellmVenvCount -eq 0) {
    Write-Host "  INFO: スキャン範囲内に litellm は見つかりませんでした" -ForegroundColor Gray
}
if ($telnyxVenvCount -eq 0) {
    Write-Host "  INFO: スキャン範囲内に telnyx は見つかりませんでした" -ForegroundColor Gray
}

# ----------------------------------------------------------
# 3. litellm_init.pth を横断検索
# ----------------------------------------------------------
Write-Host "[3/9] litellm_init.pth を横断検索中..." -ForegroundColor Yellow

$pthFiles = @()
foreach ($scanDir in $ScanDirs) {
    if (-not (Test-Path -LiteralPath $scanDir)) { continue }
    $pthFiles += Get-ChildItem -Path $scanDir -Recurse -Filter "litellm_init.pth" -ErrorAction SilentlyContinue
}

if ($pthFiles.Count -gt 0) {
    foreach ($file in $pthFiles) {
        Write-Host "  !! 危険: $($file.FullName)" -ForegroundColor Red
    }
    $found = $true
} else {
    Write-Host "  OK: litellm_init.pth は見つかりませんでした" -ForegroundColor Green
}

# ----------------------------------------------------------
# 4. 永続化バックドア (sysmon.py)
# ----------------------------------------------------------
Write-Host "[4/9] 永続化バックドア (sysmon.py) を確認中..." -ForegroundColor Yellow

$sysmonPath = Join-OptionalPath -BasePath $env:USERPROFILE -ChildPath ".config\sysmon\sysmon.py"
if ($sysmonPath -and (Test-Path -LiteralPath $sysmonPath)) {
    Write-Host "  !! 危険: $sysmonPath" -ForegroundColor Red
    $found = $true
} else {
    Write-Host "  OK: sysmon.py は見つかりませんでした" -ForegroundColor Green
}

# ----------------------------------------------------------
# 5. telnyx 永続化バックドア (msbuild.exe) - Windows 固有
# ----------------------------------------------------------
Write-Host "[5/9] telnyx 永続化バックドア (msbuild.exe) を確認中..." -ForegroundColor Yellow

$startupFolder = Join-OptionalPath -BasePath $env:APPDATA -ChildPath "Microsoft\Windows\Start Menu\Programs\Startup"
$msbuildExe = if ($startupFolder) { Join-Path $startupFolder "msbuild.exe" } else { $null }
$msbuildLock = if ($startupFolder) { Join-Path $startupFolder "msbuild.exe.lock" } else { $null }

$msbuildFound = $false
if ($msbuildExe -and (Test-Path -LiteralPath $msbuildExe)) {
    Write-Host "  !! 危険: $msbuildExe" -ForegroundColor Red
    $msbuildFound = $true
    $found = $true
}
if ($msbuildLock -and (Test-Path -LiteralPath $msbuildLock)) {
    Write-Host "  !! 危険: $msbuildLock" -ForegroundColor Red
    $msbuildFound = $true
    $found = $true
}

if (-not $msbuildFound) {
    Write-Host "  OK: msbuild.exe は見つかりませんでした" -ForegroundColor Green
}

# ----------------------------------------------------------
# 6. conda 環境のチェック
# ----------------------------------------------------------
Write-Host "[6/9] conda 環境を確認中..." -ForegroundColor Yellow

try {
    $condaInfo = & conda info --envs 2>$null
    if ($condaInfo) {
        $condaLitellmChecked = $false
        $condaTelnyxChecked = $false
        foreach ($line in $condaInfo) {
            if ($line -match "^\s*#" -or [string]::IsNullOrWhiteSpace($line)) { continue }
            $envPath = ($line -split "\s+")[-1]
            if ($envPath -and (Test-Path -LiteralPath $envPath)) {
                $condaMetas = Get-ChildItem -Path $envPath -Recurse -Filter "METADATA" -ErrorAction SilentlyContinue |
                    Where-Object { $_.DirectoryName -match "litellm-[\d.]+\.dist-info" }
                foreach ($meta in $condaMetas) {
                    $condaLitellmChecked = $true
                    $metaContent = Get-Content $meta.FullName -ErrorAction SilentlyContinue
                    $versionLine = $metaContent | Select-String "^Version:" | Select-Object -First 1
                    if ($versionLine) {
                        $version = $versionLine.ToString().Split(":")[1].Trim()
                        if (Test-BadLitellmVersion $version) {
                            Write-Host "  !! 危険: litellm $version @ conda $envPath" -ForegroundColor Red
                            $found = $true
                        } else {
                            Write-Host "  OK: litellm $version @ conda $envPath" -ForegroundColor DarkGreen
                        }
                    }
                }

                $condaTelnyxMetas = Get-ChildItem -Path $envPath -Recurse -Filter "METADATA" -ErrorAction SilentlyContinue |
                    Where-Object { $_.DirectoryName -match "telnyx-[\d.]+\.dist-info" }
                foreach ($meta in $condaTelnyxMetas) {
                    $condaTelnyxChecked = $true
                    $metaContent = Get-Content $meta.FullName -ErrorAction SilentlyContinue
                    $versionLine = $metaContent | Select-String "^Version:" | Select-Object -First 1
                    if ($versionLine) {
                        $version = $versionLine.ToString().Split(":")[1].Trim()
                        if (Test-BadTelnyxVersion $version) {
                            Write-Host "  !! 危険: telnyx $version @ conda $envPath" -ForegroundColor Red
                            $found = $true
                        } else {
                            Write-Host "  OK: telnyx $version @ conda $envPath" -ForegroundColor DarkGreen
                        }
                    }
                }
            }
        }
        if (-not $condaLitellmChecked) {
            Write-Host "  INFO: conda 環境に litellm はありません" -ForegroundColor Gray
        }
        if (-not $condaTelnyxChecked) {
            Write-Host "  INFO: conda 環境に telnyx はありません" -ForegroundColor Gray
        }
    } else {
        Write-Host "  INFO: conda コマンドが利用できません" -ForegroundColor Gray
    }
} catch {
    Write-Host "  INFO: conda コマンドが利用できません" -ForegroundColor Gray
}

# ----------------------------------------------------------
# 7. uv キャッシュ
# ----------------------------------------------------------
Write-Host "[7/9] uv キャッシュ内を検索中..." -ForegroundColor Yellow

$uvCacheBase = Join-OptionalPath -BasePath $env:LOCALAPPDATA -ChildPath "uv\cache"
if ($uvCacheBase -and (Test-Path -LiteralPath $uvCacheBase)) {
    $uvIssue = $false

    $cachedPth = Get-ChildItem -Path $uvCacheBase -Recurse -Filter "litellm_init.pth" -ErrorAction SilentlyContinue
    if ($cachedPth) {
        Write-Host "  !! 危険: uv キャッシュに litellm_init.pth が見つかりました:" -ForegroundColor Red
        foreach ($file in $cachedPth) {
            Write-Host "     $($file.FullName)" -ForegroundColor Red
        }
        $found = $true
        $uvIssue = $true
    }

    $telnyxCacheMetas = Get-ChildItem -Path $uvCacheBase -Recurse -Filter "METADATA" -ErrorAction SilentlyContinue |
        Where-Object { $_.DirectoryName -match "telnyx-[\d.]+\.dist-info" }
    foreach ($meta in $telnyxCacheMetas) {
        $metaContent = Get-Content $meta.FullName -ErrorAction SilentlyContinue
        $versionLine = $metaContent | Select-String "^Version:" | Select-Object -First 1
        if ($versionLine) {
            $version = $versionLine.ToString().Split(":")[1].Trim()
            if (Test-BadTelnyxVersion $version) {
                Write-Host "  !! 危険: uv キャッシュに telnyx $version が見つかりました: $($meta.DirectoryName)" -ForegroundColor Red
                $found = $true
                $uvIssue = $true
            }
        }
    }

    if (-not $uvIssue) {
        Write-Host "  OK: uv キャッシュに問題なし" -ForegroundColor Green
    }
} else {
    Write-Host "  INFO: uv キャッシュディレクトリが見つかりません" -ForegroundColor Gray
}

# ----------------------------------------------------------
# 8. pip キャッシュ
# ----------------------------------------------------------
Write-Host "[8/9] pip キャッシュ内を検索中..." -ForegroundColor Yellow

$pipCacheBase = Join-OptionalPath -BasePath $env:LOCALAPPDATA -ChildPath "pip\Cache"
if ($pipCacheBase -and (Test-Path -LiteralPath $pipCacheBase)) {
    $pipIssue = $false

    $cachedPth = Get-ChildItem -Path $pipCacheBase -Recurse -Filter "litellm_init.pth" -ErrorAction SilentlyContinue
    if ($cachedPth) {
        Write-Host "  !! 危険: pip キャッシュに litellm_init.pth が見つかりました:" -ForegroundColor Red
        foreach ($file in $cachedPth) {
            Write-Host "     $($file.FullName)" -ForegroundColor Red
        }
        $found = $true
        $pipIssue = $true
    }

    $telnyxPipMetas = Get-ChildItem -Path $pipCacheBase -Recurse -Filter "METADATA" -ErrorAction SilentlyContinue |
        Where-Object { $_.DirectoryName -match "telnyx-[\d.]+\.dist-info" }
    foreach ($meta in $telnyxPipMetas) {
        $metaContent = Get-Content $meta.FullName -ErrorAction SilentlyContinue
        $versionLine = $metaContent | Select-String "^Version:" | Select-Object -First 1
        if ($versionLine) {
            $version = $versionLine.ToString().Split(":")[1].Trim()
            if (Test-BadTelnyxVersion $version) {
                Write-Host "  !! 危険: pip キャッシュに telnyx $version が見つかりました: $($meta.DirectoryName)" -ForegroundColor Red
                $found = $true
                $pipIssue = $true
            }
        }
    }

    if (-not $pipIssue) {
        Write-Host "  OK: pip キャッシュに問題なし" -ForegroundColor Green
    }
} else {
    Write-Host "  INFO: pip キャッシュディレクトリが見つかりません" -ForegroundColor Gray
}

# ----------------------------------------------------------
# 9. Docker イメージのチェック
# ----------------------------------------------------------
Write-Host "[9/9] Docker イメージ内の litellm / telnyx を確認中..." -ForegroundColor Yellow

if ($SkipDocker) {
    Write-Host "  INFO: -SkipDocker が指定されたためスキップします" -ForegroundColor Gray
} else {
    try {
        $dockerVersion = & docker version --format "{{.Server.Version}}" 2>$null
        if ($dockerVersion) {
            Write-Host "  ローカルの全 Docker イメージを対象にします（時間がかかる場合があります）" -ForegroundColor Gray
            $images = & docker image ls --format "{{.Repository}}:{{.Tag}} {{.ID}}" 2>$null | Sort-Object -Unique

            if ($images) {
                foreach ($img in $images) {
                    $parts = $img -split "\s+"
                    $imageName = $parts[0]
                    $imageId = $parts[1]
                    $displayName = if ($imageName -eq "<none>:<none>") { $imageId } else { $imageName }

                    Write-Host "  スキャン中: $displayName ($imageId)..." -ForegroundColor Gray

                    $result = Get-DockerShowOutput -ImageRef $imageId -PackageName "litellm"
                    if ($result) {
                        $versionLine = $result | Select-String "^Version:" | Select-Object -First 1
                        $version = if ($versionLine) { $versionLine.ToString().Split(":")[1].Trim() } else { "" }
                        if (Test-BadLitellmVersion $version) {
                            Write-Host "  !! 危険: litellm $version @ Docker イメージ $displayName" -ForegroundColor Red
                            $found = $true
                        } elseif ($version) {
                            Write-Host "  OK: litellm $version @ Docker イメージ $displayName" -ForegroundColor DarkGreen
                        }
                    }

                    $telnyxResult = Get-DockerShowOutput -ImageRef $imageId -PackageName "telnyx"
                    if ($telnyxResult) {
                        $versionLine = $telnyxResult | Select-String "^Version:" | Select-Object -First 1
                        $version = if ($versionLine) { $versionLine.ToString().Split(":")[1].Trim() } else { "" }
                        if (Test-BadTelnyxVersion $version) {
                            Write-Host "  !! 危険: telnyx $version @ Docker イメージ $displayName" -ForegroundColor Red
                            $found = $true
                        } elseif ($version) {
                            Write-Host "  OK: telnyx $version @ Docker イメージ $displayName" -ForegroundColor DarkGreen
                        }
                    }

                    $pthCheck = Get-DockerPthHits -ImageRef $imageId
                    if ($pthCheck) {
                        Write-Host "  !! 危険: litellm_init.pth @ Docker イメージ $displayName" -ForegroundColor Red
                        foreach ($pathValue in $pthCheck) {
                            Write-Host "     $pathValue" -ForegroundColor Red
                        }
                        $found = $true
                    }
                }
            } else {
                Write-Host "  INFO: ローカル Docker イメージはありません" -ForegroundColor Gray
            }
        } else {
            Write-Host "  INFO: Docker が利用できません（未インストールまたは停止中）" -ForegroundColor Gray
        }
    } catch {
        Write-Host "  INFO: Docker が利用できません（未インストールまたは停止中）" -ForegroundColor Gray
    }
}

# ----------------------------------------------------------
# 結果サマリ
# ----------------------------------------------------------
Write-Host ""
Write-Host "=================================================" -ForegroundColor Cyan
Write-Host " 結果"                                                -ForegroundColor Cyan
Write-Host "=================================================" -ForegroundColor Cyan

if ($found) {
    Write-Host ""
    Write-Host "!! 侵害の痕跡が検出されました。以下の対応を直ちに行ってください:" -ForegroundColor Red
    Write-Host ""
    Write-Host "  1. 侵害パッケージをアンインストールする（検出された環境ごとに）"  -ForegroundColor White
    Write-Host "     該当の仮想環境を activate してから:"                           -ForegroundColor Gray
    Write-Host "     pip uninstall litellm / uv pip uninstall litellm"              -ForegroundColor Gray
    Write-Host "     pip uninstall telnyx  / uv pip uninstall telnyx"               -ForegroundColor Gray
    Write-Host "     telnyx を利用継続する場合は telnyx==4.87.0 以前にピン留め"      -ForegroundColor Gray
    Write-Host ""
    Write-Host "  2. キャッシュを削除する"                                          -ForegroundColor White
    Write-Host "     pip cache purge"                                                -ForegroundColor Gray
    Write-Host "     uv cache clean"                                                 -ForegroundColor Gray
    Write-Host ""
    Write-Host "  3. litellm_init.pth を手動で削除する（上記で検出されたパス）"      -ForegroundColor White
    Write-Host ""
    Write-Host "  4. バックドアファイルがあれば削除する"                              -ForegroundColor White
    Write-Host "     del `"$sysmonPath`""                                            -ForegroundColor Gray
    Write-Host "     del `"$msbuildExe`""                                            -ForegroundColor Gray
    Write-Host "     del `"$msbuildLock`""                                           -ForegroundColor Gray
    Write-Host ""
    Write-Host "  5. Docker イメージに問題があれば再ビルドする"                      -ForegroundColor White
    Write-Host "     侵害バージョンを含むイメージは破棄し、安全なバージョンへ更新して" -ForegroundColor Gray
    Write-Host "     リビルドしてください"                                           -ForegroundColor Gray
    Write-Host ""
    Write-Host "  6. このマシン上のすべての認証情報を侵害されたものとして扱う"       -ForegroundColor White
    Write-Host "     SSH鍵、AWSアクセスキー、Azureトークン、GCP ADC、"               -ForegroundColor Gray
    Write-Host "     .env内のAPIキー、Kubernetesコンフィグ等をすべてローテーション"   -ForegroundColor Gray
    Write-Host ""
    exit 1
}

Write-Host ""
Write-Host "OK: 侵害の痕跡は検出されませんでした。" -ForegroundColor Green
Write-Host ""
exit 0
