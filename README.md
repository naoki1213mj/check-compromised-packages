# check-litellm

LiteLLM の 2026 年 3 月のサプライチェーン攻撃に関するローカルチェック用スクリプトです。macOS / Linux 向けの `check_litellm_mac.sh` と、Windows PowerShell 向けの `check_litellm_win.ps1` を含みます。

対象の公開情報:

- LiteLLM 公式アドバイザリ: <https://docs.litellm.ai/blog/security-update-march-2026>
- FutureSearch の分析: <https://futuresearch.ai/blog/litellm-pypi-supply-chain-attack/>

## 何を検査するか

- `litellm==1.82.7` / `litellm==1.82.8` のインストール有無
- `litellm_init.pth` の残存
- `sysmon.py` / `sysmon.service` などの永続化痕跡
- `pip` / `uv` のキャッシュ
- `conda` 環境
- ローカル Docker イメージ

## 使い方

### macOS / Linux

```bash
chmod +x ./check_litellm_mac.sh
./check_litellm_mac.sh
./check_litellm_mac.sh "$HOME" /opt/homebrew /usr/local
SKIP_DOCKER=1 ./check_litellm_mac.sh
```

### Windows PowerShell

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\check_litellm_win.ps1
.\check_litellm_win.ps1 -ScanDirs "$env:USERPROFILE","C:\Program Files\Python311"
.\check_litellm_win.ps1 -SkipDocker
```

## 終了コード

- `0`: 侵害の痕跡なし
- `1`: 侵害の痕跡あり

## デフォルト探索範囲

既定ではユーザーホームだけではなく、OS ごとの代表的な Python / Homebrew / Conda の配置先も追加で見ます。

- macOS: `$HOME`, `/opt/homebrew`, `/usr/local`, `/Library/Python`, `/Library/Frameworks/Python.framework`
- Windows: `%USERPROFILE%`, `%LOCALAPPDATA%\Programs\Python`, `%ProgramFiles%\Python*`, `%ProgramData%\anaconda3` など

必要なら `-ScanDirs` / 位置引数で追加してください。

## 制限

- フォレンジックの完全代替ではありません。
- Docker 全件走査は環境によって時間がかかります。
- コンテナ内に `pip` / `python` / `find` が無い場合、Docker 側の検知は限定的です。
- 侵害時は、検出有無にかかわらず認証情報ローテーションを前提に扱ってください。

## ライセンス

MIT
