# check-litellm

日本語 README（参考訳）です。正本は英語版の [README.md](README.md) です。内容に差異がある場合は英語版を優先してください。

`check-litellm` は、2026 年 3 月 24 日に公表された悪性 LiteLLM PyPI リリース `1.82.7` / `1.82.8` に関連する痕跡をローカル環境で確認するためのスクリプト集です。

- `check_litellm_mac.sh`: macOS / Linux 向け
- `check_litellm_win.ps1`: Windows PowerShell 向け

参考情報:

- LiteLLM 公式セキュリティ更新: <https://docs.litellm.ai/blog/security-update-march-2026>
- FutureSearch の分析: <https://futuresearch.ai/blog/litellm-pypi-supply-chain-attack/>

## 免責事項

このリポジトリは MIT ライセンスで自由に利用できます。

ただし、このツールはあくまで簡易チェック用であり、フォレンジック製品や本格的なインシデントレスポンス基盤ではありません。現物環境の Python 配置、仮想環境、キャッシュ、Docker イメージ構成によっては、見逃しや不完全な結果が起こりえます。無保証で提供されます。

検知が出た場合、または侵害版 LiteLLM を導入した可能性がある場合は、単にパッケージを消すだけでは不十分です。結果を検証したうえで、該当環境の再構築、永続化痕跡の除去、認証情報やトークンのローテーションまで含めて対応してください。

## 検査内容

このスクリプトは、主に次を確認します。

- `litellm==1.82.7` / `litellm==1.82.8` の有無
- `litellm_init.pth`
- `sysmon.py`
- Linux 系での `sysmon.service`
- `pip` / `uv` キャッシュ内の痕跡
- Conda 環境内の LiteLLM
- ローカル Docker イメージ内の LiteLLM 関連痕跡

## 主な機能

- `pip`, `pip3`, `python -m pip`, `python3 -m pip`, `py -m pip`, `uv pip` を使ったアクティブ環境チェック
- `litellm-*.dist-info/METADATA` の再帰検索
- 永続化ファイルやキャッシュ痕跡の検索
- `conda` 利用時の環境横断チェック
- イメージ名に `litellm` を含むかどうかではなく、ローカル Docker イメージ全体を対象にした検査
- 検知時に `exit 1` を返すため、自動化に組み込みやすい

## リポジトリ構成

- `check_litellm_mac.sh`: Bash スクリプト
- `check_litellm_win.ps1`: PowerShell スクリプト
- `README.md`: 英語の正本
- `README.ja.md`: 日本語の参考訳
- `LICENSE`: MIT ライセンス

## 既定の探索対象

明示的にパスを渡さない場合、代表的な Python 関連配置先を既定で探索します。

### macOS

- `$HOME`
- `/opt/homebrew`
- `/usr/local`
- `/Library/Python`
- `/Library/Frameworks/Python.framework`
- `/opt/miniconda3`
- `/opt/anaconda3`

### Linux

- `$HOME`
- `/usr/local`
- `/opt`

### Windows

- `%USERPROFILE%`
- `%LOCALAPPDATA%\Programs\Python`
- `%LOCALAPPDATA%\pypoetry\Cache\virtualenvs`
- `%ProgramFiles%\Python*`
- `%ProgramFiles(x86)%\Python*`
- `%ProgramData%\anaconda3`
- `%ProgramData%\miniconda3`

社内標準イメージやカスタム配置先がある場合は、追加パスを明示的に指定してください。

## 要件

### macOS / Linux

- Bash
- `find`, `awk`, `grep` などの標準ユーティリティ
- 任意: `docker`, `conda`, `uv`

### Windows

- Windows PowerShell または PowerShell 7+
- 任意: `docker`, `conda`, `uv`

## 使い方

### macOS / Linux

```bash
chmod +x ./check_litellm_mac.sh
./check_litellm_mac.sh
./check_litellm_mac.sh "$HOME" /opt/homebrew /usr/local /srv/python
SKIP_DOCKER=1 ./check_litellm_mac.sh
```

### Windows PowerShell

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\check_litellm_win.ps1
.\check_litellm_win.ps1 -ScanDirs "$env:USERPROFILE","C:\Program Files\Python311","D:\Projects"
.\check_litellm_win.ps1 -SkipDocker
```

## 終了コード

- `0`: 既知の痕跡は検出されなかった
- `1`: 疑わしい痕跡を検出した

RMM、Intune、CI、定期点検ジョブなどに組み込むことを想定した戻り値です。

## 運用上の注意

- Docker 全件走査は時間がかかる場合があります。
- コンテナ内に `pip`, `python`, `find` が無い場合、Docker 側の検出は限定的です。
- `OK` の結果は安全性の証明ではありません。このスクリプトが知っている痕跡が見つからなかった、という意味に留まります。
- `!! 危険` の結果は triage の起点であり、追加の確認と対処が必要です。

## 検知時の推奨対応

最低限、次を実施してください。

- 影響環境から LiteLLM を除去する
- 検出された `litellm_init.pth` や永続化痕跡を削除する
- `pip` / `uv` キャッシュを削除する
- 該当 Docker イメージを再ビルドする
- 露出した可能性のある認証情報、トークン、鍵、シークレットをローテーションする

## 制限事項

- 完全なフォレンジック調査の代替ではありません
- すべてのパッケージマネージャや Python 埋め込み形態を網羅しません
- 自動修復は行いません
- すべてのコンテナレイヤ、キャッシュ形式、独自配置を完全に可視化する保証はありません

## ライセンス

MIT
