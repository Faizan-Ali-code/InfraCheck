# InfraChecker

Desktop tool that checks web-facing infrastructure for common security weaknesses and writes the findings to Excel.
Python rebuild of InfraChecker 4.3.8.

**Step-by-step instructions: [`HOW-TO-RUN.txt`](HOW-TO-RUN.txt).**

## Requirements

- Windows with **Python 3.12** installed and on `PATH`.
- Internet access on the first run (packages are installed into a local `.venv` folder: about 100 MB download,
  270 MB on disk).
- A short folder path: at most about **80 characters** (for example `C:\InfraChecker\`). The Qt package has very
  long file names and its install fails on longer paths unless Windows long path support is enabled.

## Run

- GUI: double-click **`run.bat`**. The first run creates `.venv` and installs the packages; later runs start
  immediately.
- Terminal mode: `run.bat --cli [1-7] [--no-proxy | --proxy host:port]`; `run.bat --cli` shows a menu,
  `run.bat --cli 0` prints help.

## Analyses

| # | Analysis | Checks | Inputs |
|---|---|---|---|
| 1 | Header Analysis | security headers, CSP, cookies, banners/versions, HTTP→HTTPS, HTTP/2 | `urls.txt` (+ optional files below) |
| 3 | HTTP Method Analysis | HTTP methods the server allows | `urls.txt` |
| 4 | IP Spoofing Analysis | whether a spoofed client-IP header unlocks a page that is refused without it ([method](#how-ip-spoofing-analysis-decides)) | `urls.txt`, `spoof-ips.txt` (optional) |
| 5 | Error Page Analysis | standard error page in place, no server/technology disclosure | `urls.txt`, IP list (optional) |
| 6 | SSL Labs Analysis | TLS grade and issues from Qualys SSL Labs | `urls.txt` |
| 7 | Exposure Check | hosts/IPs reachable from the internet — run from outside your internal network | `urls.txt`, IP list |

Option 2 (WAF Analysis) is not available in this build.

## Input files (`input data\`)

The tool ships with empty lists and templates; fill in your own data.

| File | Purpose |
|---|---|
| `urls.txt` | one URL or host per line (`https://` is added when missing) |
| `ips list-spoofing-errorpage-exposure.txt` | server IP addresses, one per line (Error Page and Exposure analyses) |
| `spoof-ips.txt` | optional: client addresses IP Spoofing Analysis pretends to be (default: loopback and private addresses) |
| `IP-Ownership.xls`, `CSP-Ownership.xls` | optional: column A IP address, column B owning team (row 1 is the header) |
| `ignored-domains.txt` | optional: hosts always reported as Not Vulnerable in Header Analysis |
| `ignored-banner-grabbing.txt` | optional: banner values to ignore (matched as part of the value) |
| `banner-version-baselines.txt` | `hint\|technology\|minPatchedVersion`: older versions are reported |
| `openai-config.txt` | optional: model and cache settings for banner version lookups |
| `organization-config.txt` | optional: default owner, ACS/3-D Secure host markers, log summary (see the file) |
| `update-config.txt` | where "Check for Updates" reads the latest version (empty = check disabled) |

**Secrets are never stored in files.** Set them as environment variables:

- `OPENAI_API_KEY`: OpenAI key for banner version lookups (optional; without it only the baseline file is used).
- `INFRACHECKER_UPDATE_TOKEN`: only if the version file needs a token.

## How IP Spoofing Analysis decides

Each URL is first requested **without** any client-IP header (the baseline). It is then requested once per header
(`X-Forwarded-For`, `X-Real-IP`, `X-Client-IP`, `Forwarded`, ...) and per address in `spoof-ips.txt`. Redirects are
not followed, so a redirect to a login page counts as refused.

| Baseline | Spoofed request | Result |
|---|---|---|
| page served | any | Not Applicable (already public) |
| refused, redirected or error page | page served | **Vulnerable to IP Spoofing** |
| refused, redirected or error page | different status, page still not served | Review Manually |
| refused, redirected or error page | same status | Not Vulnerable |
| request failed | | Unable to Test |

The tool can only test the URLs you give it, so list the pages that are meant to be restricted (admin consoles,
internal APIs, monitoring endpoints).

## Results

- `results\<Analysis>-Status-<date-time>.xlsx`: one workbook per run (sheet `Result ver 4.3.8`).
  Header Analysis also adds `Header Stats` and `Teamwise Stats` sheets.
- `results\html\...`: saved responses used as evidence (IP Spoofing, Error Pages, Exposure).
- `results\SSL-Lab-Reports\`: SSL Labs report pages.
- `logs\`: one log file per start of the app.

Results describe the scanned systems: keep `results\` and `logs\` private.

## Third-party code

The Content-Security-Policy evaluation is derived from Google's
[csp-evaluator](https://github.com/google/csp-evaluator) 1.1.8 (Apache License 2.0). See
[`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md) for the files involved and the changes made.

## Troubleshooting

- **"Setup failed"** on the first run: install Python 3.12 and tick "Add python.exe to PATH", check internet access,
  and move the folder to a short path such as `C:\InfraChecker\`. Then run again; setup continues where it stopped.
- **A result file is open in Excel**: close it; the tool needs to write to it while the scan runs.
- To start from a clean environment, delete the `.venv` folder and run `run.bat` again.
