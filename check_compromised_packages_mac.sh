#!/bin/bash
# ============================================================
# LiteLLM / Telnyx / axios サプライチェーン攻撃 チェックスクリプト (macOS / Linux)
# 対象: litellm v1.82.7 / v1.82.8 (2026-03-24 公開、TeamPCP による侵害)
#       telnyx  v4.87.1 / v4.87.2 (2026-03-27 公開、TeamPCP による侵害)
#       axios  v1.14.1 / v0.30.4 (2026-03-31 公開、npm アカウント侵害)
# 参考: https://docs.litellm.ai/blog/security-update-march-2026
#       https://futuresearch.ai/blog/litellm-pypi-supply-chain-attack/
#       https://futuresearch.ai/blog/telnyx-compromise/
#       https://blog.flatt.tech/entry/axios_compromise
#
# 使い方:
#   ./check_compromised_packages_mac.sh                     # 既定の共通インストール先をスキャン
#   ./check_compromised_packages_mac.sh /opt/projects       # 特定フォルダだけ
#   ./check_compromised_packages_mac.sh "$HOME" /opt/projects # 複数指定
#   SKIP_DOCKER=1 ./check_compromised_packages_mac.sh       # Docker スキャンを省略
# ============================================================

set -uo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
DARKGREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
GRAY='\033[0;37m'
NC='\033[0m'

FOUND=0
SKIP_DOCKER="${SKIP_DOCKER:-0}"
LITELLM_ACTIVE_CHECKED=0
TELNYX_ACTIVE_CHECKED=0
AXIOS_BACKDOOR_CHECKED=0
SCAN_DIRS=()

add_scan_dir() {
    local dir="$1"
    local existing

    [ -n "$dir" ] || return
    [ -d "$dir" ] || return

    if [ "${#SCAN_DIRS[@]}" -gt 0 ]; then
        for existing in "${SCAN_DIRS[@]}"; do
            [ "$existing" = "$dir" ] && return
        done
    fi

    SCAN_DIRS+=("$dir")
}

build_default_scan_dirs() {
    local os_name
    local candidate
    local candidates=("$HOME")

    os_name="$(uname -s)"
    case "$os_name" in
        Darwin)
            candidates+=(
                "/opt/homebrew"
                "/usr/local"
                "/Library/Python"
                "/Library/Frameworks/Python.framework"
                "/opt/miniconda3"
                "/opt/anaconda3"
            )
            ;;
        Linux)
            candidates+=(
                "/usr/local"
                "/opt"
            )
            ;;
    esac

    for candidate in "${candidates[@]}"; do
        add_scan_dir "$candidate"
    done
}

is_bad_litellm_version() {
    [ "$1" = "1.82.7" ] || [ "$1" = "1.82.8" ]
}

is_bad_telnyx_version() {
    [ "$1" = "4.87.1" ] || [ "$1" = "4.87.2" ]
}

is_bad_axios_version() {
    [ "$1" = "1.14.1" ] || [ "$1" = "0.30.4" ]
}

report_show_output() {
    local pkg="$1"
    local label="$2"
    local output="$3"
    local version
    local location

    [ -n "$output" ] || return

    case "$pkg" in
        litellm) LITELLM_ACTIVE_CHECKED=1 ;;
        telnyx)  TELNYX_ACTIVE_CHECKED=1 ;;
    esac
    version=$(printf '%s\n' "$output" | awk -F': ' '/^Version:/ {print $2; exit}')
    location=$(printf '%s\n' "$output" | awk -F': ' '/^Location:/ {print $2; exit}')
    location="${location:-unknown}"

    local is_bad=false
    case "$pkg" in
        litellm) is_bad_litellm_version "$version" && is_bad=true ;;
        telnyx)  is_bad_telnyx_version "$version" && is_bad=true ;;
    esac

    if [ "$is_bad" = true ]; then
        echo -e "  ${RED}!! 危険: $pkg $version @ $location [$label]${NC}"
        FOUND=1
    elif [ -n "$version" ]; then
        echo -e "  ${GREEN}OK: $pkg $version @ $location [$label]${NC}"
    fi
}

check_show_command() {
    local pkg="$1"
    local label="$2"
    shift 2
    report_show_output "$pkg" "$label" "$("$@" show "$pkg" 2>/dev/null || true)"
}

docker_show_pkg() {
    local image_ref="$1"
    local pkg="$2"
    local output

    output=$(docker run --rm --entrypoint "" "$image_ref" pip show "$pkg" 2>/dev/null || true)
    [ -n "$output" ] || output=$(docker run --rm --entrypoint "" "$image_ref" pip3 show "$pkg" 2>/dev/null || true)
    [ -n "$output" ] || output=$(docker run --rm --entrypoint "" "$image_ref" python -m pip show "$pkg" 2>/dev/null || true)
    [ -n "$output" ] || output=$(docker run --rm --entrypoint "" "$image_ref" python3 -m pip show "$pkg" 2>/dev/null || true)

    printf '%s' "$output"
}

docker_find_pth() {
    local image_ref="$1"
    docker run --rm --entrypoint "" "$image_ref" find / -name "litellm_init.pth" -type f 2>/dev/null || true
}

if [ $# -gt 0 ]; then
    for input_dir in "$@"; do
        add_scan_dir "$input_dir"
    done
else
    build_default_scan_dirs
fi

echo ""
echo -e "${CYAN}=================================================${NC}"
echo -e "${CYAN} LiteLLM / Telnyx / axios 侵害チェック (macOS / Linux)${NC}"
echo -e "${CYAN}=================================================${NC}"
echo ""

if [ "${#SCAN_DIRS[@]}" -eq 0 ]; then
    echo -e "${YELLOW}WARN: 有効なスキャン対象ディレクトリがありません${NC}"
else
    echo -e "${GRAY}スキャン対象: ${SCAN_DIRS[*]}${NC}"
fi
echo ""

# ----------------------------------------------------------
# 1. 現在アクティブな環境の litellm バージョン確認
# ----------------------------------------------------------
echo -e "${YELLOW}[1/14] アクティブ環境の litellm / telnyx バージョンを確認中...${NC}"

command -v pip >/dev/null 2>&1 && check_show_command "litellm" "pip" pip
command -v pip3 >/dev/null 2>&1 && check_show_command "litellm" "pip3" pip3
command -v python >/dev/null 2>&1 && check_show_command "litellm" "python -m pip" python -m pip
command -v python3 >/dev/null 2>&1 && check_show_command "litellm" "python3 -m pip" python3 -m pip
command -v uv >/dev/null 2>&1 && check_show_command "litellm" "uv pip" uv pip

command -v pip >/dev/null 2>&1 && check_show_command "telnyx" "pip" pip
command -v pip3 >/dev/null 2>&1 && check_show_command "telnyx" "pip3" pip3
command -v python >/dev/null 2>&1 && check_show_command "telnyx" "python -m pip" python -m pip
command -v python3 >/dev/null 2>&1 && check_show_command "telnyx" "python3 -m pip" python3 -m pip
command -v uv >/dev/null 2>&1 && check_show_command "telnyx" "uv pip" uv pip

if [ "$LITELLM_ACTIVE_CHECKED" -eq 0 ]; then
    echo -e "  ${GRAY}INFO: アクティブ環境に litellm はインストールされていません${NC}"
fi
if [ "$TELNYX_ACTIVE_CHECKED" -eq 0 ]; then
    echo -e "  ${GRAY}INFO: アクティブ環境に telnyx はインストールされていません${NC}"
fi

# ----------------------------------------------------------
# 2. 仮想環境を横断して litellm の全インストール箇所を一覧表示
# ----------------------------------------------------------
echo -e "${YELLOW}[2/14] 仮想環境内の litellm / telnyx を横断検索中...${NC}"
echo -e "  ${GRAY}（ディスク容量によっては数分かかります）${NC}"

VENV_LITELLM_COUNT=0
VENV_TELNYX_COUNT=0

for scan_dir in "${SCAN_DIRS[@]}"; do
    while IFS= read -r meta_file; do
        VENV_LITELLM_COUNT=$((VENV_LITELLM_COUNT + 1))
        VERSION=$(awk -F': ' '/^Version:/ {print $2; exit}' "$meta_file" 2>/dev/null || true)
        DIST_DIR=$(dirname "$meta_file")
        if is_bad_litellm_version "$VERSION"; then
            echo -e "  ${RED}!! 危険: litellm $VERSION @ $DIST_DIR${NC}"
            FOUND=1
        elif [ -n "$VERSION" ]; then
            echo -e "  ${DARKGREEN}OK: litellm $VERSION @ $DIST_DIR${NC}"
        fi
    done < <(find "$scan_dir" -path "*/litellm-*.dist-info/METADATA" -type f 2>/dev/null)

    while IFS= read -r meta_file; do
        VENV_TELNYX_COUNT=$((VENV_TELNYX_COUNT + 1))
        VERSION=$(awk -F': ' '/^Version:/ {print $2; exit}' "$meta_file" 2>/dev/null || true)
        DIST_DIR=$(dirname "$meta_file")
        if is_bad_telnyx_version "$VERSION"; then
            echo -e "  ${RED}!! 危険: telnyx $VERSION @ $DIST_DIR${NC}"
            FOUND=1
        elif [ -n "$VERSION" ]; then
            echo -e "  ${DARKGREEN}OK: telnyx $VERSION @ $DIST_DIR${NC}"
        fi
    done < <(find "$scan_dir" -path "*/telnyx-*.dist-info/METADATA" -type f 2>/dev/null)
done

if [ "$VENV_LITELLM_COUNT" -eq 0 ]; then
    echo -e "  ${GRAY}INFO: スキャン範囲内に litellm は見つかりませんでした${NC}"
fi
if [ "$VENV_TELNYX_COUNT" -eq 0 ]; then
    echo -e "  ${GRAY}INFO: スキャン範囲内に telnyx は見つかりませんでした${NC}"
fi

# ----------------------------------------------------------
# 3. litellm_init.pth を横断検索
# ----------------------------------------------------------
echo -e "${YELLOW}[3/14] litellm_init.pth を横断検索中...${NC}"

PTH_FOUND=0
for scan_dir in "${SCAN_DIRS[@]}"; do
    while IFS= read -r f; do
        echo -e "  ${RED}!! 危険: $f${NC}"
        PTH_FOUND=1
        FOUND=1
    done < <(find "$scan_dir" -name "litellm_init.pth" -type f 2>/dev/null)
done

if [ "$PTH_FOUND" -eq 0 ]; then
    echo -e "  ${GREEN}OK: litellm_init.pth は見つかりませんでした${NC}"
fi

# ----------------------------------------------------------
# 4. 永続化バックドア (sysmon.py)
# ----------------------------------------------------------
echo -e "${YELLOW}[4/14] 永続化バックドア (sysmon.py) を確認中...${NC}"

SYSMON_PATH="$HOME/.config/sysmon/sysmon.py"
if [ -f "$SYSMON_PATH" ]; then
    echo -e "  ${RED}!! 危険: $SYSMON_PATH${NC}"
    FOUND=1
else
    echo -e "  ${GREEN}OK: sysmon.py は見つかりませんでした${NC}"
fi

# ----------------------------------------------------------
# 5. systemd 永続化サービスの確認（Linux のみ）
# ----------------------------------------------------------
echo -e "${YELLOW}[5/14] systemd バックドアサービスを確認中...${NC}"

SYSTEMD_SERVICE="$HOME/.config/systemd/user/sysmon.service"
if [ -f "$SYSTEMD_SERVICE" ]; then
    echo -e "  ${RED}!! 危険: $SYSTEMD_SERVICE${NC}"
    FOUND=1
else
    echo -e "  ${GREEN}OK: sysmon.service は見つかりませんでした${NC}"
fi

# ----------------------------------------------------------
# 6. conda 環境のチェック
# ----------------------------------------------------------
echo -e "${YELLOW}[6/14] conda 環境を確認中...${NC}"

if command -v conda >/dev/null 2>&1; then
    CONDA_LITELLM_CHECKED=0
    CONDA_TELNYX_CHECKED=0
    while IFS= read -r env_path; do
        [ -d "$env_path" ] || continue
        while IFS= read -r meta_file; do
            CONDA_LITELLM_CHECKED=1
            VERSION=$(awk -F': ' '/^Version:/ {print $2; exit}' "$meta_file" 2>/dev/null || true)
            if is_bad_litellm_version "$VERSION"; then
                echo -e "  ${RED}!! 危険: litellm $VERSION @ conda $env_path${NC}"
                FOUND=1
            elif [ -n "$VERSION" ]; then
                echo -e "  ${DARKGREEN}OK: litellm $VERSION @ conda $env_path${NC}"
            fi
        done < <(find "$env_path" -path "*/litellm-*.dist-info/METADATA" -type f 2>/dev/null)

        while IFS= read -r meta_file; do
            CONDA_TELNYX_CHECKED=1
            VERSION=$(awk -F': ' '/^Version:/ {print $2; exit}' "$meta_file" 2>/dev/null || true)
            if is_bad_telnyx_version "$VERSION"; then
                echo -e "  ${RED}!! 危険: telnyx $VERSION @ conda $env_path${NC}"
                FOUND=1
            elif [ -n "$VERSION" ]; then
                echo -e "  ${DARKGREEN}OK: telnyx $VERSION @ conda $env_path${NC}"
            fi
        done < <(find "$env_path" -path "*/telnyx-*.dist-info/METADATA" -type f 2>/dev/null)
    done < <(conda info --envs 2>/dev/null | awk 'NF && $1 !~ /^#/ {print $NF}')

    if [ "$CONDA_LITELLM_CHECKED" -eq 0 ]; then
        echo -e "  ${GRAY}INFO: conda 環境に litellm はありません${NC}"
    fi
    if [ "$CONDA_TELNYX_CHECKED" -eq 0 ]; then
        echo -e "  ${GRAY}INFO: conda 環境に telnyx はありません${NC}"
    fi
else
    echo -e "  ${GRAY}INFO: conda コマンドが利用できません${NC}"
fi

# ----------------------------------------------------------
# 7. uv キャッシュ
# ----------------------------------------------------------
echo -e "${YELLOW}[7/14] uv キャッシュ内を検索中...${NC}"

UV_CACHE="$HOME/.cache/uv"
[ -d "$UV_CACHE" ] || UV_CACHE="$HOME/Library/Caches/uv"

if [ -d "$UV_CACHE" ]; then
    UV_ISSUE=0

    UV_PTH=$(find "$UV_CACHE" -name "litellm_init.pth" -type f 2>/dev/null || true)
    if [ -n "$UV_PTH" ]; then
        echo -e "  ${RED}!! 危険: uv キャッシュに litellm_init.pth が見つかりました:${NC}"
        printf '%s\n' "$UV_PTH" | while IFS= read -r f; do
            [ -n "$f" ] && echo -e "  ${RED}     $f${NC}"
        done
        FOUND=1
        UV_ISSUE=1
    fi

    while IFS= read -r meta_file; do
        VERSION=$(awk -F': ' '/^Version:/ {print $2; exit}' "$meta_file" 2>/dev/null || true)
        if is_bad_telnyx_version "$VERSION"; then
            echo -e "  ${RED}!! 危険: uv キャッシュに telnyx $VERSION が見つかりました: $(dirname "$meta_file")${NC}"
            FOUND=1
            UV_ISSUE=1
        fi
    done < <(find "$UV_CACHE" -path "*/telnyx-*.dist-info/METADATA" -type f 2>/dev/null)

    if [ "$UV_ISSUE" -eq 0 ]; then
        echo -e "  ${GREEN}OK: uv キャッシュに問題なし${NC}"
    fi
else
    echo -e "  ${GRAY}INFO: uv キャッシュディレクトリが見つかりません${NC}"
fi

# ----------------------------------------------------------
# 8. pip キャッシュ
# ----------------------------------------------------------
echo -e "${YELLOW}[8/14] pip キャッシュ内を検索中...${NC}"

PIP_CACHE_FOUND=0
for cache_dir in "$HOME/.cache/pip" "$HOME/Library/Caches/pip"; do
    [ -d "$cache_dir" ] || continue

    PIP_PTH=$(find "$cache_dir" -name "litellm_init.pth" -type f 2>/dev/null || true)
    if [ -n "$PIP_PTH" ]; then
        echo -e "  ${RED}!! 危険: pip キャッシュに litellm_init.pth が見つかりました:${NC}"
        printf '%s\n' "$PIP_PTH" | while IFS= read -r f; do
            [ -n "$f" ] && echo -e "  ${RED}     $f${NC}"
        done
        PIP_CACHE_FOUND=1
        FOUND=1
    fi

    while IFS= read -r meta_file; do
        VERSION=$(awk -F': ' '/^Version:/ {print $2; exit}' "$meta_file" 2>/dev/null || true)
        if is_bad_telnyx_version "$VERSION"; then
            echo -e "  ${RED}!! 危険: pip キャッシュに telnyx $VERSION が見つかりました: $(dirname "$meta_file")${NC}"
            PIP_CACHE_FOUND=1
            FOUND=1
        fi
    done < <(find "$cache_dir" -path "*/telnyx-*.dist-info/METADATA" -type f 2>/dev/null)
done

if [ "$PIP_CACHE_FOUND" -eq 0 ]; then
    echo -e "  ${GREEN}OK: pip キャッシュに問題なし${NC}"
fi

# ----------------------------------------------------------
# 10. axios バックドアファイルの確認
# ----------------------------------------------------------
echo -e "${YELLOW}[10/14] axios バックドアファイルを確認中...${NC}"

AXIOS_BACKDOOR_FOUND=0
os_name="$(uname -s)"
case "$os_name" in
    Darwin)
        if [ -f "/Library/Caches/com.apple.act.mond" ]; then
            echo -e "  ${RED}!! 危険: /Library/Caches/com.apple.act.mond (axios RAT バイナリ)${NC}"
            AXIOS_BACKDOOR_FOUND=1
            FOUND=1
        fi
        ;;
    Linux)
        if [ -f "/tmp/ld.py" ]; then
            echo -e "  ${RED}!! 危険: /tmp/ld.py (axios Python RAT)${NC}"
            AXIOS_BACKDOOR_FOUND=1
            FOUND=1
        fi
        ;;
esac

if [ "$AXIOS_BACKDOOR_FOUND" -eq 0 ]; then
    echo -e "  ${GREEN}OK: axios バックドアファイルは見つかりませんでした${NC}"
fi

# ----------------------------------------------------------
# 11. node_modules 内の plain-crypto-js を検索
# ----------------------------------------------------------
echo -e "${YELLOW}[11/14] node_modules 内の plain-crypto-js を検索中...${NC}"
echo -e "  ${GRAY}（ディスク容量によっては数分かかります）${NC}"

PLAIN_CRYPTO_FOUND=0
for scan_dir in "${SCAN_DIRS[@]}"; do
    while IFS= read -r crypto_dir; do
        echo -e "  ${RED}!! 危険: plain-crypto-js ディレクトリ検出 (axios 感染の痕跡): $crypto_dir${NC}"
        PLAIN_CRYPTO_FOUND=1
        FOUND=1
    done < <(find "$scan_dir" -type d -name "plain-crypto-js" -path "*/node_modules/*" 2>/dev/null)
done

if [ "$PLAIN_CRYPTO_FOUND" -eq 0 ]; then
    echo -e "  ${GREEN}OK: plain-crypto-js は見つかりませんでした${NC}"
fi

# ----------------------------------------------------------
# 12. node_modules 内の侵害版 axios を検索
# ----------------------------------------------------------
echo -e "${YELLOW}[12/14] node_modules 内の axios バージョンを確認中...${NC}"

AXIOS_VERSION_COUNT=0
for scan_dir in "${SCAN_DIRS[@]}"; do
    while IFS= read -r pkg_json; do
        AXIOS_VERSION_COUNT=$((AXIOS_VERSION_COUNT + 1))
        VERSION=$(grep -o '"version"[[:space:]]*:[[:space:]]*"[^"]*"' "$pkg_json" 2>/dev/null | head -1 | sed 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/')
        PKG_DIR=$(dirname "$pkg_json")
        if is_bad_axios_version "$VERSION"; then
            echo -e "  ${RED}!! 危険: axios $VERSION @ $PKG_DIR${NC}"
            FOUND=1
        elif [ -n "$VERSION" ]; then
            echo -e "  ${DARKGREEN}OK: axios $VERSION @ $PKG_DIR${NC}"
        fi
    done < <(find "$scan_dir" -path "*/node_modules/axios/package.json" -type f 2>/dev/null)
done

if [ "$AXIOS_VERSION_COUNT" -eq 0 ]; then
    echo -e "  ${GRAY}INFO: スキャン範囲内に axios は見つかりませんでした${NC}"
fi

# ----------------------------------------------------------
# 13. lockfile 内の plain-crypto-js を検索
# ----------------------------------------------------------
echo -e "${YELLOW}[13/14] lockfile 内の plain-crypto-js を検索中...${NC}"

LOCKFILE_HIT=0
for scan_dir in "${SCAN_DIRS[@]}"; do
    while IFS= read -r lockfile; do
        echo -e "  ${RED}!! 危険: plain-crypto-js が lockfile に記録されています: $lockfile${NC}"
        LOCKFILE_HIT=1
        FOUND=1
    done < <(find "$scan_dir" \( -name "package-lock.json" -o -name "yarn.lock" -o -name "pnpm-lock.yaml" \) -type f -exec grep -l "plain-crypto-js" {} \; 2>/dev/null)
done

if [ "$LOCKFILE_HIT" -eq 0 ]; then
    echo -e "  ${GREEN}OK: lockfile に plain-crypto-js は見つかりませんでした${NC}"
fi

# ----------------------------------------------------------
# 14. Docker イメージのチェック
# ----------------------------------------------------------
echo -e "${YELLOW}[14/14] Docker イメージ内の litellm / telnyx / axios を確認中...${NC}"

if [ "$SKIP_DOCKER" = "1" ]; then
    echo -e "  ${GRAY}INFO: SKIP_DOCKER=1 が指定されたためスキップします${NC}"
elif command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    DOCKER_IMAGE_COUNT=0
    echo -e "  ${GRAY}ローカルの全 Docker イメージを対象にします（時間がかかる場合があります）${NC}"
    while IFS= read -r image_line; do
        [ -n "$image_line" ] || continue
        DOCKER_IMAGE_COUNT=$((DOCKER_IMAGE_COUNT + 1))
        image_name="${image_line% *}"
        image_id="${image_line##* }"
        display_name="$image_name"
        [ "$display_name" = "<none>:<none>" ] && display_name="$image_id"

        echo -e "  ${GRAY}スキャン中: $display_name ($image_id) ...${NC}"

        DOCKER_OUTPUT="$(docker_show_pkg "$image_id" litellm)"
        if [ -n "$DOCKER_OUTPUT" ]; then
            DOCKER_VERSION=$(printf '%s\n' "$DOCKER_OUTPUT" | awk -F': ' '/^Version:/ {print $2; exit}')
            if is_bad_litellm_version "$DOCKER_VERSION"; then
                echo -e "  ${RED}!! 危険: litellm $DOCKER_VERSION @ Docker イメージ $display_name${NC}"
                FOUND=1
            elif [ -n "$DOCKER_VERSION" ]; then
                echo -e "  ${DARKGREEN}OK: litellm $DOCKER_VERSION @ Docker イメージ $display_name${NC}"
            fi
        fi

        DOCKER_OUTPUT_TELNYX="$(docker_show_pkg "$image_id" telnyx)"
        if [ -n "$DOCKER_OUTPUT_TELNYX" ]; then
            DOCKER_VERSION_TELNYX=$(printf '%s\n' "$DOCKER_OUTPUT_TELNYX" | awk -F': ' '/^Version:/ {print $2; exit}')
            if is_bad_telnyx_version "$DOCKER_VERSION_TELNYX"; then
                echo -e "  ${RED}!! 危険: telnyx $DOCKER_VERSION_TELNYX @ Docker イメージ $display_name${NC}"
                FOUND=1
            elif [ -n "$DOCKER_VERSION_TELNYX" ]; then
                echo -e "  ${DARKGREEN}OK: telnyx $DOCKER_VERSION_TELNYX @ Docker イメージ $display_name${NC}"
            fi
        fi

        PTH_IN_DOCKER="$(docker_find_pth "$image_id")"
        if [ -n "$PTH_IN_DOCKER" ]; then
            echo -e "  ${RED}!! 危険: litellm_init.pth @ Docker イメージ $display_name${NC}"
            printf '%s\n' "$PTH_IN_DOCKER" | while IFS= read -r p; do
                [ -n "$p" ] && echo -e "  ${RED}     $p${NC}"
            done
            FOUND=1
        fi

        # axios check in Docker
        DOCKER_AXIOS_OUTPUT="$(docker run --rm --entrypoint "" "$image_id" cat /app/node_modules/axios/package.json 2>/dev/null || true)"
        if [ -n "$DOCKER_AXIOS_OUTPUT" ]; then
            DOCKER_AXIOS_VERSION=$(printf '%s' "$DOCKER_AXIOS_OUTPUT" | grep -o '"version"[[:space:]]*:[[:space:]]*"[^"]*"' | head -1 | sed 's/.*"\([^"]*\)"$/\1/')
            if is_bad_axios_version "$DOCKER_AXIOS_VERSION"; then
                echo -e "  ${RED}!! 危険: axios $DOCKER_AXIOS_VERSION @ Docker イメージ $display_name${NC}"
                FOUND=1
            elif [ -n "$DOCKER_AXIOS_VERSION" ]; then
                echo -e "  ${DARKGREEN}OK: axios $DOCKER_AXIOS_VERSION @ Docker イメージ $display_name${NC}"
            fi
        fi

        DOCKER_PLAIN_CRYPTO="$(docker run --rm --entrypoint "" "$image_id" find / -type d -name "plain-crypto-js" -path "*/node_modules/*" 2>/dev/null || true)"
        if [ -n "$DOCKER_PLAIN_CRYPTO" ]; then
            echo -e "  ${RED}!! 危険: plain-crypto-js @ Docker イメージ $display_name${NC}"
            printf '%s\n' "$DOCKER_PLAIN_CRYPTO" | while IFS= read -r p; do
                [ -n "$p" ] && echo -e "  ${RED}     $p${NC}"
            done
            FOUND=1
        fi
    done < <(docker image ls --format "{{.Repository}}:{{.Tag}} {{.ID}}" 2>/dev/null | sort -u)

    if [ "$DOCKER_IMAGE_COUNT" -eq 0 ]; then
        echo -e "  ${GRAY}INFO: ローカル Docker イメージはありません${NC}"
    fi
else
    echo -e "  ${GRAY}INFO: Docker が利用できません（未インストールまたは停止中）${NC}"
fi

# ----------------------------------------------------------
# 結果サマリ
# ----------------------------------------------------------
echo ""
echo -e "${CYAN}=================================================${NC}"
echo -e "${CYAN} 結果${NC}"
echo -e "${CYAN}=================================================${NC}"

if [ "$FOUND" -eq 1 ]; then
    echo ""
    echo -e "${RED}!! 侵害の痕跡が検出されました。以下の対応を直ちに行ってください:${NC}"
    echo ""
    echo "  1. 侵害パッケージをアンインストールする（検出された環境ごとに）"
    echo -e "     ${GRAY}該当の仮想環境を activate してから:${NC}"
    echo -e "     ${GRAY}pip uninstall litellm / uv pip uninstall litellm${NC}"
    echo -e "     ${GRAY}pip uninstall telnyx  / uv pip uninstall telnyx${NC}"
    echo -e "     ${GRAY}telnyx を利用継続する場合は telnyx==4.87.0 以前にピン留め${NC}"
    echo ""
    echo "  2. キャッシュを削除する"
    echo -e "     ${GRAY}pip cache purge${NC}"
    echo -e "     ${GRAY}uv cache clean${NC}"
    echo ""
    echo "  3. litellm_init.pth を手動で削除する（上記で検出されたパス）"
    echo ""
    echo "  4. バックドアファイルを削除する"
    echo -e "     ${GRAY}rm -f ~/.config/sysmon/sysmon.py${NC}"
    echo -e "     ${GRAY}rm -f ~/.config/systemd/user/sysmon.service${NC}"
    echo ""
    echo "  5. Docker イメージに問題があれば再ビルドする"
    echo -e "     ${GRAY}侵害バージョンを含むイメージは破棄し、安全なバージョンへ更新して${NC}"
    echo -e "     ${GRAY}リビルドしてください${NC}"
    echo ""
    echo "  6. このマシン上のすべての認証情報を侵害されたものとして扱う"
    echo -e "     ${GRAY}SSH鍵、AWSアクセスキー、Azureトークン、GCP ADC、${NC}"
    echo -e "     ${GRAY}.env内のAPIキー、Kubernetesコンフィグ等をすべてローテーション${NC}"
    echo ""
    echo "  7. axios が検出された場合、安全なバージョンにダウングレードする"
    echo -e "     ${GRAY}npm install axios@1.14.0${NC}"
    echo -e "     ${GRAY}レガシー利用の場合は axios@0.30.3${NC}"
    echo ""
    echo "  8. plain-crypto-js ディレクトリを削除する"
    echo -e "     ${GRAY}find . -type d -name 'plain-crypto-js' -path '*/node_modules/*' -exec rm -rf {} +${NC}"
    echo ""
    echo "  9. axios バックドアファイルを削除する"
    echo -e "     ${GRAY}macOS: rm -f /Library/Caches/com.apple.act.mond${NC}"
    echo -e "     ${GRAY}Linux: rm -f /tmp/ld.py${NC}"
    echo ""
    echo " 10. npm キャッシュをクリアする"
    echo -e "     ${GRAY}npm cache clean --force${NC}"
    echo ""
    exit 1
else
    echo ""
    echo -e "${GREEN}OK: 侵害の痕跡は検出されませんでした。${NC}"
    echo ""
    exit 0
fi
