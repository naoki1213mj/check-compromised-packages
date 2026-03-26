# ============================================================
# LiteLLM サプライチェーン攻撃 チェックスクリプト (Windows / PowerShell)
# 対象: litellm v1.82.7 / v1.82.8 (2026-03-24 公開、TeamPCP による侵害)
# 参考: https://docs.litellm.ai/blog/security-update-march-2026
#       https://futuresearch.ai/blog/litellm-pypi-supply-chain-attack/
#
# 使い方:
#   .\check_litellm_win.ps1                                    # 既定の共通インストール先をスキャン
#   .\check_litellm_win.ps1 -ScanDirs "C:\dev"                 # 特定フォルダ
#   .\check_litellm_win.ps1 -ScanDirs "$env:USERPROFILE","D:\projects"
#   .\check_litellm_win.ps1 -SkipDocker                        # Docker スキャンを省略
# ============================================================

param(
    [string[]]$ScanDirs = @(),
    [switch]$SkipDocker
)

$found = $false
$activeChecked = $false
$BAD_VERSIONS = @("1.82.7", "1.82.8")

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

function Test-BadVersion {
    param([string]$Version)
    return $Version -in $BAD_VERSIONS
}

function Show-InstalledVersion {
    param(
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

        $output = & $commandName @commandArgs show litellm 2>$null
        if ($output) {
            $script:activeChecked = $true
            $versionLine = $output | Select-String "^Version:" | Select-Object -First 1
            $locationLine = $output | Select-String "^Location:" | Select-Object -First 1
            $version = if ($versionLine) { $versionLine.ToString().Split(":")[1].Trim() } else { "" }
            $location = if ($locationLine) { $locationLine.ToString().Split(":", 2)[1].Trim() } else { "unknown" }

            if (Test-BadVersion $version) {
                Write-Host "  !! 危険: litellm $version @ $location [$Label]" -ForegroundColor Red
                $script:found = $true
            } elseif ($version) {
                Write-Host "  OK: litellm $version @ $location [$Label]" -ForegroundColor Green
            }
        }
    } catch {}
}

function Get-DockerShowOutput {
    param([string]$ImageRef)

    $commands = @(
        @("pip", "show", "litellm"),
        @("pip3", "show", "litellm"),
        @("python", "-m", "pip", "show", "litellm"),
        @("python3", "-m", "pip", "show", "litellm")
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
Write-Host "========================================" -ForegroundColor Cyan
Write-Host " LiteLLM 侵害チェック (Windows)"        -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
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
Write-Host "[1/8] アクティブ環境の litellm バージョンを確認中..." -ForegroundColor Yellow

if (Get-Command pip -ErrorAction SilentlyContinue) { Show-InstalledVersion -Label "pip" -CommandParts @("pip") }
if (Get-Command pip3 -ErrorAction SilentlyContinue) { Show-InstalledVersion -Label "pip3" -CommandParts @("pip3") }
if (Get-Command python -ErrorAction SilentlyContinue) { Show-InstalledVersion -Label "python -m pip" -CommandParts @("python", "-m", "pip") }
if (Get-Command py -ErrorAction SilentlyContinue) { Show-InstalledVersion -Label "py -m pip" -CommandParts @("py", "-m", "pip") }
if (Get-Command uv -ErrorAction SilentlyContinue) { Show-InstalledVersion -Label "uv pip" -CommandParts @("uv", "pip") }

if (-not $activeChecked) {
    Write-Host "  INFO: アクティブ環境に litellm はインストールされていません" -ForegroundColor Gray
}

# ----------------------------------------------------------
# 2. 仮想環境を横断して litellm の全インストール箇所を一覧表示
# ----------------------------------------------------------
Write-Host "[2/8] 仮想環境内の litellm を横断検索中..." -ForegroundColor Yellow
Write-Host "  （ディスク容量によっては数分かかります）" -ForegroundColor Gray

$venvCount = 0

foreach ($scanDir in $ScanDirs) {
    if (-not (Test-Path -LiteralPath $scanDir)) { continue }

    $metadataFiles = Get-ChildItem -Path $scanDir -Recurse -Filter "METADATA" -ErrorAction SilentlyContinue |
        Where-Object { $_.DirectoryName -match "litellm-[\d.]+\.dist-info" }

    foreach ($meta in $metadataFiles) {
        $venvCount++
        $metaContent = Get-Content $meta.FullName -ErrorAction SilentlyContinue
        $versionLine = $metaContent | Select-String "^Version:" | Select-Object -First 1
        if ($versionLine) {
            $version = $versionLine.ToString().Split(":")[1].Trim()
            $distInfoDir = $meta.DirectoryName
            if (Test-BadVersion $version) {
                Write-Host "  !! 危険: litellm $version @ $distInfoDir" -ForegroundColor Red
                $found = $true
            } else {
                Write-Host "  OK: litellm $version @ $distInfoDir" -ForegroundColor DarkGreen
            }
        }
    }
}

if ($venvCount -eq 0) {
    Write-Host "  INFO: スキャン範囲内に litellm は見つかりませんでした" -ForegroundColor Gray
}

# ----------------------------------------------------------
# 3. litellm_init.pth を横断検索
# ----------------------------------------------------------
Write-Host "[3/8] litellm_init.pth を横断検索中..." -ForegroundColor Yellow

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
Write-Host "[4/8] 永続化バックドア (sysmon.py) を確認中..." -ForegroundColor Yellow

$sysmonPath = Join-OptionalPath -BasePath $env:USERPROFILE -ChildPath ".config\sysmon\sysmon.py"
if ($sysmonPath -and (Test-Path -LiteralPath $sysmonPath)) {
    Write-Host "  !! 危険: $sysmonPath" -ForegroundColor Red
    $found = $true
} else {
    Write-Host "  OK: sysmon.py は見つかりませんでした" -ForegroundColor Green
}

# ----------------------------------------------------------
# 5. conda 環境のチェック
# ----------------------------------------------------------
Write-Host "[5/8] conda 環境を確認中..." -ForegroundColor Yellow

try {
    $condaInfo = & conda info --envs 2>$null
    if ($condaInfo) {
        $condaChecked = $false
        foreach ($line in $condaInfo) {
            if ($line -match "^\s*#" -or [string]::IsNullOrWhiteSpace($line)) { continue }
            $envPath = ($line -split "\s+")[-1]
            if ($envPath -and (Test-Path -LiteralPath $envPath)) {
                $condaMetas = Get-ChildItem -Path $envPath -Recurse -Filter "METADATA" -ErrorAction SilentlyContinue |
                    Where-Object { $_.DirectoryName -match "litellm-[\d.]+\.dist-info" }
                foreach ($meta in $condaMetas) {
                    $condaChecked = $true
                    $metaContent = Get-Content $meta.FullName -ErrorAction SilentlyContinue
                    $versionLine = $metaContent | Select-String "^Version:" | Select-Object -First 1
                    if ($versionLine) {
                        $version = $versionLine.ToString().Split(":")[1].Trim()
                        if (Test-BadVersion $version) {
                            Write-Host "  !! 危険: litellm $version @ conda $envPath" -ForegroundColor Red
                            $found = $true
                        } else {
                            Write-Host "  OK: litellm $version @ conda $envPath" -ForegroundColor DarkGreen
                        }
                    }
                }
            }
        }
        if (-not $condaChecked) {
            Write-Host "  INFO: conda 環境に litellm はありません" -ForegroundColor Gray
        }
    } else {
        Write-Host "  INFO: conda コマンドが利用できません" -ForegroundColor Gray
    }
} catch {
    Write-Host "  INFO: conda コマンドが利用できません" -ForegroundColor Gray
}

# ----------------------------------------------------------
# 6. uv キャッシュ
# ----------------------------------------------------------
Write-Host "[6/8] uv キャッシュ内を検索中..." -ForegroundColor Yellow

$uvCacheBase = Join-OptionalPath -BasePath $env:LOCALAPPDATA -ChildPath "uv\cache"
if ($uvCacheBase -and (Test-Path -LiteralPath $uvCacheBase)) {
    $cachedPth = Get-ChildItem -Path $uvCacheBase -Recurse -Filter "litellm_init.pth" -ErrorAction SilentlyContinue
    if ($cachedPth) {
        Write-Host "  !! 危険: uv キャッシュに litellm_init.pth が見つかりました:" -ForegroundColor Red
        foreach ($file in $cachedPth) {
            Write-Host "     $($file.FullName)" -ForegroundColor Red
        }
        $found = $true
    } else {
        Write-Host "  OK: uv キャッシュに問題なし" -ForegroundColor Green
    }
} else {
    Write-Host "  INFO: uv キャッシュディレクトリが見つかりません" -ForegroundColor Gray
}

# ----------------------------------------------------------
# 7. pip キャッシュ
# ----------------------------------------------------------
Write-Host "[7/8] pip キャッシュ内を検索中..." -ForegroundColor Yellow

$pipCacheBase = Join-OptionalPath -BasePath $env:LOCALAPPDATA -ChildPath "pip\Cache"
if ($pipCacheBase -and (Test-Path -LiteralPath $pipCacheBase)) {
    $cachedPth = Get-ChildItem -Path $pipCacheBase -Recurse -Filter "litellm_init.pth" -ErrorAction SilentlyContinue
    if ($cachedPth) {
        Write-Host "  !! 危険: pip キャッシュに litellm_init.pth が見つかりました:" -ForegroundColor Red
        foreach ($file in $cachedPth) {
            Write-Host "     $($file.FullName)" -ForegroundColor Red
        }
        $found = $true
    } else {
        Write-Host "  OK: pip キャッシュに問題なし" -ForegroundColor Green
    }
} else {
    Write-Host "  INFO: pip キャッシュディレクトリが見つかりません" -ForegroundColor Gray
}

# ----------------------------------------------------------
# 8. Docker イメージのチェック
# ----------------------------------------------------------
Write-Host "[8/8] Docker イメージ内の litellm を確認中..." -ForegroundColor Yellow

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

                    $result = Get-DockerShowOutput -ImageRef $imageId
                    if ($result) {
                        $versionLine = $result | Select-String "^Version:" | Select-Object -First 1
                        $version = if ($versionLine) { $versionLine.ToString().Split(":")[1].Trim() } else { "" }
                        if (Test-BadVersion $version) {
                            Write-Host "  !! 危険: litellm $version @ Docker イメージ $displayName" -ForegroundColor Red
                            $found = $true
                        } elseif ($version) {
                            Write-Host "  OK: litellm $version @ Docker イメージ $displayName" -ForegroundColor DarkGreen
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
Write-Host "========================================" -ForegroundColor Cyan
Write-Host " 結果"                                    -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

if ($found) {
    Write-Host ""
    Write-Host "!! 侵害の痕跡が検出されました。以下の対応を直ちに行ってください:" -ForegroundColor Red
    Write-Host ""
    Write-Host "  1. litellm をアンインストールする（検出された環境ごとに）"       -ForegroundColor White
    Write-Host "     該当の仮想環境を activate してから:"                           -ForegroundColor Gray
    Write-Host "     pip uninstall litellm / uv pip uninstall litellm"              -ForegroundColor Gray
    Write-Host ""
    Write-Host "  2. キャッシュを削除する"                                          -ForegroundColor White
    Write-Host "     pip cache purge"                                                -ForegroundColor Gray
    Write-Host "     uv cache clean"                                                 -ForegroundColor Gray
    Write-Host ""
    Write-Host "  3. litellm_init.pth を手動で削除する（上記で検出されたパス）"      -ForegroundColor White
    Write-Host ""
    Write-Host "  4. sysmon.py バックドアがあれば削除する"                           -ForegroundColor White
    Write-Host "     del `"$sysmonPath`""                                            -ForegroundColor Gray
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
