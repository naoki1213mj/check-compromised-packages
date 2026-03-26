# check-litellm

English README (authoritative): this file  
Japanese README (reference translation): [README.ja.md](README.ja.md)

`check-litellm` provides two local inspection scripts for identifying traces associated with the malicious LiteLLM PyPI releases `1.82.7` and `1.82.8`, which were publicly disclosed on March 24, 2026.

- `check_litellm_mac.sh` for macOS and Linux
- `check_litellm_win.ps1` for Windows PowerShell

References:

- LiteLLM security update: <https://docs.litellm.ai/blog/security-update-march-2026>
- FutureSearch analysis: <https://futuresearch.ai/blog/litellm-pypi-supply-chain-attack/>

## Disclaimer

This project is provided under the MIT License and may be used freely.

That said, this repository is a convenience scanner, not a forensic or incident response platform. It is provided as-is, without warranty of any kind, and it may miss traces or report incomplete results depending on how Python, virtual environments, package caches, or containers are laid out on a specific machine.

If this tool reports suspicious findings, or if you suspect a system installed a compromised LiteLLM release, treat the host as potentially exposed. That means validating the result, removing affected packages and artifacts, rebuilding affected environments, and rotating credentials and tokens as appropriate for your environment.

## What The Scripts Check

The scripts look for the following indicators:

- Installed LiteLLM packages at version `1.82.7` or `1.82.8`
- `litellm_init.pth`
- `sysmon.py`
- `sysmon.service` on Linux-compatible systems
- LiteLLM-related artifacts in `pip` and `uv` caches
- LiteLLM installations inside Conda environments
- LiteLLM traces inside local Docker images

## Feature Summary

- Checks active environments through `pip`, `pip3`, `python -m pip`, `python3 -m pip`, `py -m pip` where available, and `uv pip`
- Recursively scans typical install roots for `litellm-*.dist-info/METADATA`
- Searches for persistence files and cache artifacts
- Inspects Conda environments when `conda` is available
- Scans all local Docker images by image ID instead of only images whose name contains `litellm`
- Returns a non-zero exit code when suspicious artifacts are found

## Repository Contents

- `check_litellm_mac.sh`: Bash script for macOS and Linux
- `check_litellm_win.ps1`: PowerShell script for Windows
- `README.md`: English documentation
- `README.ja.md`: Japanese reference documentation
- `LICENSE`: MIT license

## Default Scan Locations

If you do not provide scan paths, the scripts include common Python-related install roots by default.

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

If your organization installs Python, virtual environments, or package caches elsewhere, pass additional paths explicitly.

## Requirements

### macOS / Linux

- Bash
- Standard shell utilities such as `find`, `awk`, and `grep`
- Optional: `docker`, `conda`, `uv`

### Windows

- Windows PowerShell or PowerShell 7+
- Optional: `docker`, `conda`, `uv`

## Usage

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

## Exit Codes

- `0`: no suspicious LiteLLM artifacts were detected
- `1`: suspicious LiteLLM artifacts were detected

These exit codes are intended to make the scripts usable in RMM tooling, CI checks, Intune workflows, or other automation.

## Operational Notes

- Docker inspection can take time because the scripts scan all local images, not only images with `litellm` in the name.
- Docker checks are best-effort. Detection is limited if a container image does not include `pip`, `python`, or `find`.
- A clean result does not prove a host is safe. It only means this script did not find the indicators it knows how to detect.
- A positive result should be treated as a triage signal and followed by manual validation.

## Recommended Response If Findings Exist

At a minimum:

- Remove affected LiteLLM installs from each impacted environment
- Delete detected `litellm_init.pth` files and persistence artifacts
- Clear `pip` and `uv` caches
- Rebuild affected Docker images
- Rotate credentials, tokens, keys, and other secrets that may have been exposed

## Limitations

- This tool does not replace a full forensic investigation
- It does not inspect every possible package manager or Python embedding pattern
- It does not automatically remediate findings
- It does not guarantee complete visibility into every container layer, cache format, or custom environment layout

## License

MIT
