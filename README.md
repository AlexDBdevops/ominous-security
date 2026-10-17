# Ominous Security

[![CI](https://github.com/AlexDBdevops/ominous-security/actions/workflows/ci.yml/badge.svg)](https://github.com/AlexDBdevops/ominous-security/actions/workflows/ci.yml)
[![CodeQL](https://github.com/AlexDBdevops/ominous-security/actions/workflows/codeql.yml/badge.svg)](https://github.com/AlexDBdevops/ominous-security/actions/workflows/codeql.yml)

A web tool that analyzes a GitHub repository **before you clone it**: code vulnerabilities, threats the author planted on purpose, and hidden or encrypted scripts, which it decodes without running them. With the local server it then lets you clone it (asking for confirmation if anything is not green) and apply the automatic fixes, showing the diff and a summary of what changed.

**Nothing to install:** https://alexdbdevops.github.io/ominous-security/ (real analysis in your browser; the three examples use simulated data). See [Web version](#web-version). The page is available in English and Spanish (button in the header).

- [Quick start](#quick-start)
- [Configuration](#configuration)
- [Deployment](#deployment)
- [What it analyzes](#what-it-analyzes)
- [Watching your clones](#watching-your-clones)
- [Security of the tool itself](#security-of-the-tool-itself)
- [Command-line scanner](#command-line-scanner)
- [Development and CI/CD](#development-and-cicd)
- [Troubleshooting](#troubleshooting)
- [Limits](#limits)

## Quick start

**With Docker** (recommended: the app runs isolated in a hardened container):

```bash
git clone https://github.com/AlexDBdevops/ominous-security.git
cd ominous-security
scripts/local.sh            # Windows: .\scripts\local.ps1
```

The script builds the image, starts it, waits until it answers and opens http://localhost:8080. Clones go to `~/ominous-clones`. You need Docker with the `docker compose` plugin (Docker Desktop includes it).

**Without Docker** (Node.js 22 or later and git):

```bash
npm ci --omit=dev           # optional: only adds the Anthropic SDK for AI summaries
npm start                   # or: scripts/local.sh node
```

Paste the repo URL (`https://github.com/user/repo`, `/tree/branch` works too) and press **Analyze**.

## Configuration

Everything is configured with environment variables. With Docker, put them in a `.env` file (for example `OMINOUS_PORT=9090`) next to `compose.yaml` (Compose reads it on its own and it is in `.gitignore`), or export them before running the script.

### Script and Docker Compose variables

| Variable | Default | Purpose |
|---|---|---|
| `OMINOUS_PORT` | `8080` | Port on your machine |
| `OMINOUS_CLONES` | `~/ominous-clones` | Folder on your machine where clones end up |
| `OMINOUS_LAN_IP` | detected | Your machine's IP on the local network, only for `scripts/local.sh lan` |

### Application variables

| Variable | Default | Purpose |
|---|---|---|
| `PORT` | `8080` | Port the server listens on |
| `HOST` | `127.0.0.1` | Network interface. In the container it is `0.0.0.0`, and Docker only publishes the port on `127.0.0.1` |
| `CLONE_DIR` | `~/ominous-clones` | Clone folder. Clones can only go inside it |
| `GITHUB_TOKEN` | — | Read-only GitHub token. Raises the API limit from 60 to 5000 requests per hour (metadata, releases and author reputation) |
| `ANTHROPIC_API_KEY` | — | Optional. API key for the AI review and the diff summary. It can also be typed in the **Connect Claude** dialog, or you can use your account through Claude Code (see [Connect Claude](#connect-claude)) |
| `OMINOUS_AI_METHOD` | — | `claude-code` to start already connected with your account through Claude Code. Otherwise the key is used if present |
| `OMINOUS_CLAUDE_BIN` | `claude` | Path to the Claude Code executable |
| `OMINOUS_CLAUDE_MODEL` | Claude Code's | Model for the review with Claude Code (`sonnet`, `opus`…) |
| `OMINOUS_CLAUDE_TIMEOUT` | `600000` | Maximum time for a review with Claude Code, in ms |
| `OMINOUS_MODEL` | `claude-opus-5-5` | Claude model when using an API key |
| `OMINOUS_AI_EFFORT` | `high` | Effort of the AI review (`low`, `medium`, `high`, `xhigh`, `max`): higher is deeper and more expensive |
| `OMINOUS_AI_MAX_CHARS` | `160000` | Maximum characters of the repo sent to Claude per review |
| `ALLOWED_HOSTS` | — | Extra names the app can be opened with (`myserver:8080,192.168.1.20:8080`). If any of them is not this machine, `OMINOUS_TOKEN` becomes mandatory |
| `OMINOUS_TOKEN` | — | Access token (at least 24 characters). Generate one with `openssl rand -hex 24` |
| `ALLOW_ANY_HOST` | — | `1` accepts any host name. Not recommended; also requires a token |
| `ALLOW_ANY_DEST` | — | `1` allows cloning outside `CLONE_DIR`. Only works if the app is not exposed |
| `HISTORY_COMMITS` | `300` | Commits of the history that are reviewed |
| `ANALYSIS_TIMEOUT_MS` | `1200000` | Maximum time for the whole analysis: clone, history, submodules, external tools and code. Earlier phases stop sooner to leave time for the code (up to 6 minutes), and whatever is skipped for time shows up in the coverage as a partial result instead of an error |
| `MAX_REPO_MB` | `1024` | Maximum repo size, as reported by GitHub |
| `MAX_CONCURRENT` | `2` | Simultaneous analyses |
| `RATE_LIMIT` | `30` | Analyses per IP every 10 minutes |
| `OMINOUS_OFFLINE` | — | `1` queries no external service: OSV.dev, deps.dev, EPSS or the npm and PyPI registries (useful in tests or offline) |
| `OMINOUS_EXTERNAL` | — | `0` does not use Gitleaks, Semgrep, Trivy or CodeQL even if installed (see [External tools](#external-tools-optional)) |
| `OMINOUS_GITLEAKS_BIN`, `OMINOUS_SEMGREP_BIN`, `OMINOUS_TRIVY_BIN`, `OMINOUS_CODEQL_BIN` | the one on `PATH` | Path of each external tool |
| `OMINOUS_SEMGREP_CONFIG` | `p/default` | Semgrep rules, comma-separated: registry rulesets (`p/default,p/owasp-top-ten`) or local files and folders, such as a clone of [semgrep-rules](https://github.com/semgrep/semgrep-rules) (so it does not contact semgrep.dev) |
| `OMINOUS_EXTERNAL_TIMEOUT_MS` | `240000` | Maximum time for Gitleaks, Semgrep and Trivy |
| `OMINOUS_CODEQL_TIMEOUT_MS` | `480000` | Maximum time for CodeQL per language |
| `OMINOUS_WATCH` | — | `0` disables [watching your clones](#watching-your-clones) |
| `OMINOUS_WATCH_HOURS` | `24` | How often, in hours, the clones are checked |
| `OMINOUS_WATCH_TIMEOUT_MS` | `600000` | Maximum time for each clone check; whatever there is no time to check is marked as skipped |

## Deployment

### On your machine with Docker

```bash
scripts/local.sh            # build and start
scripts/local.sh full       # the same with Gitleaks, Semgrep, Trivy and CodeQL inside (see below)
scripts/local.sh logs       # show the logs
scripts/local.sh down       # stop
scripts/local.sh rebuild    # rebuild without cache (for example, after updating)
```

`full` uses `Dockerfile.full` and `compose.full.yaml`: the same app on Debian 13 (CodeQL needs glibc; it ships git 2.47.3, already patched) with the four [external tools](#external-tools-optional) installed at fixed versions checked by sha256, and Semgrep installed only from wheels with all their hashes (`docker/semgrep-requirements.txt`, regenerated with `docker/lock-semgrep.py`). It keeps the same hardening with 4 GB of memory and 512 processes, because CodeQL builds a database of the code. The image is much larger than the regular one.

The container (`compose.yaml`) runs as your user, with a read-only file system and no Linux capabilities, cannot escalate privileges and has memory (2 GB), CPU (2) and process (256) limits. It only writes to the clone folder and `/tmp`.

**Isolated network.** The app lives on an internal Docker network with no way out. Its only connection to the outside is a second, minimal container, the gateway (`lib/gateway.js`, no dependencies): it forwards what you open in the browser and acts as the outbound proxy for the app, git, Semgrep and Trivy. It only lets HTTPS (port 443) through to public addresses, checking the IP when connecting: neither your machine, nor your local network, nor the cloud metadata service can be reached, even if a domain resolves to them. Every blocked attempt is logged in `docker compose logs gateway`. The gateway runs as `nobody`, read-only, with no capabilities and 128 MB.

**Analysis in its own container.** The foreign repo is cloned and analyzed in a third container, `scanner` (`lib/scanner.js`): git, the history, submodules, Gitleaks, Semgrep, Trivy, CodeQL and the analyzer. It runs as another user (1001), without your clone folder and without `GITHUB_TOKEN` or `ANTHROPIC_API_KEY`, and only reaches the Internet through its own outbound gateway (`salida-scanner`, the same `lib/gateway.js` with no inbound side). If a repo exploited a bug in git or in one of the tools, it would stay there:

- It builds the clone URL itself from `owner/repo` (always `https://github.com/<owner>/<repo>.git`); it does not accept URLs.
- The app checks everything it gets back before using it (`lib/scanclient.js`): the commit must be a 40-character SHA, the branch cannot look like a git option or leave the normal ref paths, and each finding is copied field by field with bounded sizes. The only thing a compromised scanner could do is lie in the findings.
- It cannot talk to the app: the app only accepts connections from the gateway, which announces the real client IP with the PROXY protocol (`lib/proxyproto.js`), or local ones (the healthcheck). This also makes the per-IP rate limit per IP again instead of shared by everyone.
- It cannot reach the inbound gateway either: it shares no network with it (networks `entrada`, `escaneo` and `escaneo-salida` in `compose.yaml`), and if the PROXY header claimed the connection came from the scanner, the app would close it anyway. If it could, it would get in as if it were your browser and could ask the app to clone into your folder or use your keys.

The app keeps the page, the GitHub queries with your token, the AI review and the final clone into your folder, which only happens when you confirm it. Without Docker (`node server.js`), everything runs in the same process.

To use the published image instead of building it:

```bash
docker run -d --name ominous -p 127.0.0.1:8080:8080 \
  -v "$HOME/ominous-clones:/data" --user "$(id -u):$(id -g)" \
  --read-only --tmpfs /tmp:size=2g --cap-drop ALL --security-opt no-new-privileges \
  ghcr.io/alexdbdevops/ominous-security:latest
```

### On your machine without Docker

`scripts/local.sh node` checks that you have Node.js 22+ and git, installs the optional SDK and starts the server on `127.0.0.1`.

### From your phone, on your local network

```bash
scripts/local.sh lan
```

It detects your IP, generates a token (saved in `.ominous-token`) and gives you a URL like `http://192.168.1.20:8080/?token=…`. Open it on your phone once: the token is stored in a cookie and disappears from the URL. It goes over unencrypted HTTP, so only use it on a trusted network and go back to `scripts/local.sh up` when you are done.

### On a server

If you publish it on the Internet, put it behind an HTTPS proxy and use a token. Example with [Caddy](https://caddyserver.com) on the same server:

```bash
# .env
OMINOUS_TOKEN=<openssl rand -hex 24>
```

```yaml
# compose.override.yaml
services:
  app:
    environment:
      ALLOWED_HOSTS: "ominous.yourdomain.com"
      OMINOUS_TOKEN: ${OMINOUS_TOKEN:?}
```

```
# Caddyfile
ominous.yourdomain.com {
  reverse_proxy 127.0.0.1:8080
}
```

Log in once at `https://ominous.yourdomain.com/?token=<your token>`. Caddy gets the certificate and the cookie is marked `Secure`. Keep in mind that clones are stored on the server's disk, not yours.

### Web version on GitHub Pages

The same page is published on GitHub Pages in its **web** edition: it really analyzes public repos from the visitor's browser, with no server and no AI (see [Web version](#web-version)). It needs no infrastructure or secrets of its own: on every push to `main`, the `pages` job builds `dist/` with `npm run build:site` and publishes it with the official `upload-pages-artifact` and `deploy-pages` actions.

GitHub Pages does not allow custom headers, so the CSP goes in a `<meta>` at the top of the page. It allows each script by its hash, `analyzer.js` from the same origin, and connections only to `api.github.com`, `raw.githubusercontent.com`, `api.osv.dev`, `api.securityscorecards.dev`, `api.deps.dev`, `api.first.org` (EPSS), `registry.npmjs.org`, `pypi.org` and `files.pythonhosted.org`. All of them are read-only queries for public data, and the optional GitHub token only goes to `api.github.com`. A `<meta>` cannot set `frame-ancestors`, so the page hides itself if another site puts it in a frame (against clickjacking). HTTPS and HSTS come from `github.io`.

One-time setup: on GitHub, *Settings > Pages > Build and deployment > Source*: **GitHub Actions**. The URL is `https://alexdbdevops.github.io/ominous-security/` and it shows up in the job summary.

To try it locally: `npm run build:site && npx serve dist`.

## External tools (optional)

On the local server, if these open-source tools are installed, they also run over the temporary clone and their findings are added to those of the built-in rules, each with the tool's own explanation (rule, CWE and links):

| Tool | What it adds | Install |
|---|---|---|
| [Gitleaks](https://github.com/gitleaks/gitleaks) | over a hundred secret rules, also on the downloaded history | `brew install gitleaks` |
| [Semgrep](https://github.com/semgrep/semgrep) | the `p/default` ruleset: hundreds of security rules in more than 30 languages. Downloads the rules from semgrep.dev, with metrics turned off | `pipx install semgrep` |
| [Trivy](https://github.com/aquasecurity/trivy) | secrets and misconfigurations in Dockerfile, Kubernetes, Terraform, CloudFormation and Helm | `brew install trivy` |
| [CodeQL](https://github.com/github/codeql-cli-binaries) | **data flows**: follows each value from where it enters (a request, an argument, a file) to where it does harm (`exec`, SQL, `eval`…), also across functions and files. Uses the `code-scanning` suite (GitHub's default; robustness queries such as rate limits or slow regular expressions drop to low) | the [codeql-action](https://github.com/github/codeql-action/releases) *bundle* (includes the queries) |

None of them runs code from the repo: they only read files. They are launched without a shell, with a time limit and a minimal environment, in parallel. If one is not installed it does not appear; if it fails, it shows as "not reviewed". The regular Docker image does not include them; the full one (`scripts/local.sh full`) ships all four. They are not in the web version because they cannot run in a browser.

**About CodeQL:**

- It only analyzes JavaScript/TypeScript, Python and Ruby. Java, Kotlin, C#, C/C++, Go and Swift usually need the project to be built, and building runs code from the repo (Maven or Gradle plugins, build scripts). That would break the rule of never running anything.
- It is slow: each language takes from half a minute to several minutes, and the *bundle* takes more than 1 GB.
- Each finding shows **the data flow** in its card, step by step, with file and line. If the data is validated or escaped at some step, it may be a false positive.
- Its license allows free use on open-source code and for research. Check its [terms](https://github.com/github/codeql-cli-binaries/blob/main/LICENSE.md) before using it on private code.

**About Semgrep:** the free version also follows data, but only within each function. Its rules are downloaded when used and their license does not allow copying them into another tool, so Ominous does not bundle them: it uses whatever you have installed or downloaded.

## Web version

One branch and one page with three editions. Only one line changes (`const EDITION`) plus the CSP, which `lib/page.js` generates:

| Edition | Where | What it does |
|---|---|---|
| `local` | local server (`npm start`, Docker) | everything: isolated clone, git history, submodules, cloning with fixes and the Claude review (your Pro/Max account or a key) |
| `web` | GitHub Pages | real analysis in the browser, no AI |
| `web-ai` | claude.ai artifact | the same as `web` plus the Claude review using the claude.ai account of whoever opens it |

In the web editions, `public/analyzer.js` (the same analyzer as `lib/`, bundled with `npm run build:web`) runs in a Web Worker:

1. It asks the GitHub API for the repo metadata, the branch commit and the list of files at that commit.
2. It downloads each file from `raw.githubusercontent.com` at that exact commit into the tab's memory. Nothing is written to disk or run.
3. It runs the same rules as the server (the tests check that the findings are identical) and queries OSV.dev, OpenSSF Scorecard, deps.dev, EPSS and the npm and PyPI registries (see [Beyond the repo](#beyond-the-repo)).
4. The analysis has 5 minutes. Around 3 minutes 45 seconds it stops reading files and making queries and returns what it reviewed, marked as incomplete; if it is still stuck at 5 minutes (a file designed to hang analyzers), the page kills the worker. If the browser does not allow a worker, the analysis runs in the page itself with the full time budget and reads at most 1.5 MB of each file.

The web editions only analyze: they do not clone, download the repo or generate patches. Cloning (with the automatic fixes and daily watching) belongs to the local server or the container.

Every finding has a **What is this?** card with no AI: the kind of flaw (with its CWE), why it matters, what to check and, for dependencies, the advisories published on OSV.dev (CVE/GHSA identifiers, summary, fixed version and links).

**Language.** The page starts in the browser's language (English unless it is Spanish) and the **ES / EN** button in the header switches it; the choice is remembered in that browser. It translates the interface and the findings' text: rule titles and descriptions, the **What is this?** cards, the review notes and the coverage. Text that comes from outside (OSV advisories, external tools' messages, the AI review) stays as it arrives.

If GitHub cannot find the repo, the page explains the possible reasons: the account does not exist (misspelled, deleted or suspended) or the repo is not public (misspelled, private, deleted, taken down by GitHub or renamed without a redirect). It also reports a missing branch, an empty repo, a legal or GitHub block, the rate limit and no connection.

Limits of the web version compared with the local server:

- No git history or submodules (marked as not reviewed).
- Without signing in, the GitHub API allows 60 requests per hour per IP. Each analysis uses about 5. Files from `raw.githubusercontent.com` do not count. With an optional GitHub token (fine-grained, no permissions) it goes up to 5000: it is only sent to `api.github.com`, lives in the worker's memory during the analysis and is never stored.
- Up to 3000 files, 2 MB per file and 60 MB in total.
- If a service (OSV.dev, Scorecard, deps.dev, EPSS, npm or PyPI) does not answer the browser, it shows as "not reviewed" instead of failing.

## What it analyzes

The repo is downloaded into a temporary folder with hardened git (no hooks, no submodules, no LFS and no local protocols) and **nothing from it is ever run**. It is deleted at the end.

**Code vulnerabilities.** There are about 115 rules for JS/TS, Python, PHP, Go, Java, Ruby, Rust, C/C++, C#, Swift/Android, shell, Docker, Compose, Kubernetes, Terraform and GitHub Actions. It also looks for secrets from about 20 providers and queries OSV.dev for dependencies with known vulnerabilities: npm (package.json, package-lock, yarn.lock, pnpm-lock.yaml, bun.lock), PyPI (requirements, poetry.lock, uv.lock, pdm.lock, Pipfile.lock), Go (go.mod, go.sum), crates.io (Cargo.lock), RubyGems (Gemfile.lock), Packagist (composer.lock), Maven (pom.xml, build.gradle, gradle.lockfile), NuGet (.csproj, packages.lock.json), Pub (pubspec.lock), Hex (mix.lock) and CRAN (renv.lock). It also detects ML models loaded with pickle (`torch.load` without `weights_only`, `trust_remote_code=True`) and insecure Electron settings. Each finding says whether it **can be fixed** (with the fix) or **not** (with the reason). *Automatic* fixes are applied if you tick the box when cloning. Vulnerabilities in tests, examples or documentation drop to informational; threats do not (people run the examples), except those that are normal noise in test data.

**Deliberate threats:**

- **Install and open:** `postinstall` scripts, `setup.py` and build backends, VS Code tasks that run when you open the folder or the `.code-workspace`, devcontainers (including `initializeCommand`, which runs on your machine, and those that mount your home folder or start privileged), git hooks and files that run by themselves (`conftest.py`, `.pth`, `sitecustomize.py`, `build.rs`, Gradle/Maven, `.envrc`, pre-commit, webpack/jest/eslint configs). Also VS Code settings pointing at executables, and the project's Claude Code hooks and MCP servers.
- **Each kind of project:** Visual Studio/MSBuild build events (like the 2021 Lazarus attack), Xcode *Run Script* phases (XcodeSpy, XCSSET), Unity scripts with `[InitializeOnLoad]` and Godot scripts with `@tool`, CMake and autotools (including the xz backdoor pattern), Composer scripts, `.cargo/config` that swaps the compiler, Maven/Gradle extensions and agents and their wrapper, `.pnpmfile.cjs`, Yarn plugins, Bun `preload`, `.npmrc` with `node-options`, `binding.gyp`, CocoaPods, R `Makevars`, Hatch/Poetry/PDM hooks, Terraform `data "external"` (runs on `plan`) and `ansible.cfg`.
- **AI agents:** besides the instructions, project settings that remove confirmations (`bypassPermissions`, `Bash(*)`, Copilot auto-approval, CVE-2025-53773), that change where your API key goes (`ANTHROPIC_BASE_URL`) or that run scripts (`apiKeyHelper`, `statusLine`). Invisible text in instruction files.
- **Files that run code when opened:** ML models and pickle files (`.pkl`, `.pt`, `.ckpt`, `.joblib`…) that call `os.system` or similar when loaded, Office documents with macros, PDFs with `/Launch` actions or JavaScript on open, SVGs with scripts and Jupyter notebooks (each cell's code is analyzed as Python).
- **Classic malware:** `curl | sh`, reverse shells, miners, credential theft (browser, Discord, wallets, SSH, AWS), exfiltration webhooks, persistence, disabling the antivirus, keyloggers, crypto clippers, fake password dialogs, SSH backdoors, destructive commands and log wiping.
- **Hiding:** Trojan Source (Unicode bidi), invisible characters (including variation selectors and Hangul fillers, the GlassWorm technique), homoglyphs, second stages downloaded and run with `eval` (also from Discord attachments, IPFS or DNS records), code hidden behind hundreds of spaces, binaries disguised as images, **images with an executable or code appended**, steganography libraries and code that runs what it reads from an image.
- **Supply chain:** npm, Cargo, Poetry, uv, Pipfile, Composer and Bundler lockfiles that download from unofficial servers, alternative registries (dependency confusion), dependencies listed as malware in OSV, typosquatting, packages that **install commands named like system tools** (`git`, `npm`, `sudo`…), `yarnPath`, modified Gradle wrappers and the list of dependencies that run scripts on install (according to `package-lock.json`).
- **CI and containers:** workflows that dump all secrets (`toJSON(secrets)`), `pull_request_target`, Actions injection, unpinned third-party actions, self-hosted runners, containers that are privileged, use the host network or processes, have dangerous capabilities, mount `/`, `/etc`, your home folder or the Docker socket, and Dockerfiles running as root. Actions that were compromised (`tj-actions/changed-files`, `reviewdog`) and `ACTIONS_ALLOW_UNSECURE_COMMANDS`.
- **AI agents:** dangerous instructions in `CLAUDE.md`, `AGENTS.md`, `.cursorrules`, Windsurf, Roo, Kiro, Continue, Junie and Amazon Q rules, Copilot prompts, etc.
- **Lures:** READMEs asking you to download a password-protected zip, encrypted ZIPs or ZIPs with executables and double extensions (`invoice.pdf.exe`).
- **Git history:** reviews the lines removed in the last 300 commits looking for secrets and malicious code that was taken out but is still in the repo. If there are more commits, the coverage says so.
- **Git tricks:** submodules with tampered paths or URLs, files that overwrite each other on Windows and macOS because of case, folders posing as `.git`, symlinks to `.git` or that leave the repo through other links, and `.lfsconfig` downloading from another server.
- **Submodules and releases:** analyzes up to 8 submodules at the exact commit the repo pins and warns about binaries published in releases.
- **Reputation:** stars, age of the repo and of the account, license, archived status, new accounts with inflated stars, **renamed or transferred repos (repojacking)** and the project's **OpenSSF Scorecard** score.

**Reverse engineering of hidden scripts.** It peels layers of base64, hex, zlib/gzip/deflate, `String.fromCharCode`, reversed strings, rot13, ascii85/base85, 1- to 4-byte XOR (brute force) and **Fernet (AES) when the key is in the repo**, and analyzes the result again. If the key is not in the repo, it marks it as not decodable.

**Against tricks to come out green.** A file with a NUL byte, several megabytes of padding or the code at column 20,001 is still analyzed (and the trick itself is a finding). Code and configuration are read before data, so inflating the repo with thousands of files hides nothing, and if the limit is reached the result is never green. `dist/` is only treated as minified code if it really looks like it. A file with a binary extension that is actually code is analyzed anyway.

**AI review (optional).** The rules find known patterns; with Claude connected (see [Connect Claude](#connect-claude)) and the **Review with Claude** button, the highest-risk files (those that run on install or open, those with findings, the entry points and the decoded code, up to 40 files and `OMINOUS_AI_MAX_CHARS` characters) are sent to Claude along with the file tree and the rules' findings. Claude looks for what has no signature (new malicious logic, sandbox-evasion techniques, authorization flaws, code that does not match what the project claims to be) and points out possible false positives. Safety rules for this feature:

- Nothing is sent unless you press the button, and the app tells you beforehand how many files and how much text.
- The repo content is marked as untrusted data: if it contains instructions aimed at the AI, that is reported as a threat.
- The AI **can only add findings**. Its "false positives" are shown as an opinion and never lower the verdict; if it finds something serious, cloning requires the confirmation box even if the rules say green (the server checks this too).
- The answer is validated against a strict JSON schema before it is shown.

### Connect Claude

The **Connect Claude** button in the header opens a dialog to choose which account the review uses. When connecting, the app checks the connection and shows a green mark with the method, the account type and the time of the check. The header button changes to **Claude connected**.

| Option | Cost | How it works |
|---|---|---|
| **My Claude account (Pro or Max)** | No extra cost: uses your plan's usage | Uses the Claude Code installed on the machine where the app runs, with your session signed in (run `claude` once to sign in). The app never reads your credentials: it runs `claude -p` with no tools (`--tools ""`), no MCP, in safe mode (no CLAUDE.md, hooks or plugins), without saving the session, in an empty folder and without `ANTHROPIC_API_KEY` in its environment. The repo content goes in through standard input, never as an argument. Not available inside Docker; use `scripts/local.sh node` |
| **Anthropic API key** | Pay per use, separate from Pro or Max | A Pro subscription does not pay for the API: the key is billed at console.anthropic.com. A large review sends about 50,000 tokens; with `claude-opus-5-5` at `high` effort it costs roughly 0.20 to 0.50 USD (estimate). Lower `OMINOUS_AI_EFFORT` or `OMINOUS_AI_MAX_CHARS` to make it cheaper. The key can come from `ANTHROPIC_API_KEY` or be typed in the dialog |
| **Your claude.ai account** (demo only) | No extra cost | When the demo is opened as an artifact on claude.ai, Claude really reviews the example's simulated findings with the account of whoever opens it, after asking for permission |

Dialog security:

- A key typed in the dialog lives only in the server's memory: it is not saved to disk, not written to the log and never sent back to the browser (only its first and last characters).
- If the app is exposed to the network, the key is only accepted over HTTPS (the proxy's `X-Forwarded-Proto: https` header); otherwise, use `ANTHROPIC_API_KEY`.
- The dialog uses the same token, CSRF protection and rate limit as the rest of the API.
- Checking a key queries the model on the API and spends no tokens. Checking Claude Code runs `claude --version` and `claude auth status`, which spend no usage.

**Coverage.** Each analysis shows what was fully reviewed, what partially and what not at all.

**Cloning** (local server only). The button is at the end. If the result is not green it requires ticking the confirmation box, and the server checks it too. The clone is pinned to the exact commit that was analyzed.

- **In a folder you choose** (Chrome and Edge): the browser asks you to pick a folder and creates one inside with the repo's name. The app prepares the clone in its temporary folder (analyzed commit and fixes applied), sends it to the page once and deletes it; the page writes it into your folder with the permission the browser asks you for. It is a full git clone of that branch, with `core.symlinks=false` and `core.filemode=false`: the browser cannot create symlinks or execute permissions, so links end up as text files and git does not see that as changes. The app never writes outside its clone folder.
- **As a .zip** (any browser): the same clone, prepared by the app, downloaded as a zip to unpack wherever you like.
- **In the app's clone folder** (`~/ominous-clones`): with daily watching of its dependencies.

If you apply fixes you will see the diff and a summary of each change, why it is safer and what it could break, and you can undo them with a button. Claude writes the summary if it is connected; in that case, and only then, the diff is sent to Claude.

### Beyond the repo

What is not in the code you download, but affects you all the same:

- **The published package.** `npm install` and `pip install` do not download the repo: they download what the author (or whoever stole their account) uploaded to the registry. If the repo publishes an npm or PyPI package that links back to that same repo, the latest version is downloaded (not installed) and compared with GitHub: different install scripts, `.pth` or `setup.py` files that are not in the repo, and the threat rules over every file that does not match.
- **Vulnerabilities in the project itself.** OSV.dev is queried for the analyzed commit and the project's package (name and version).
- **Indirect dependencies without a lockfile.** If a `package.json` has no `package-lock.json` or `yarn.lock`, only the direct dependencies are known, but `npm install` would also install theirs. [deps.dev](https://deps.dev) resolves the tree you would get today (the highest version that satisfies each range) and everything is checked on OSV.dev. npm only, for now.
- **Is it being exploited?** The CVEs of each finding are cross-checked with the [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) (vulnerabilities already being exploited: raises the severity to at least high) and with [EPSS](https://www.first.org/epss/) (probability of exploitation in the next 30 days). They can only raise the severity, never lower it.
- **Scripts the repo tells you to run.** If the README, a script or the CI says `curl … | sh`, `irm … | iex` or "download and run it", the local server downloads that script **as data, without running it** (HTTPS only, 1 MB at most, never from your local network) and reports what it does: which domains it contacts, whether it verifies checksums or signatures, whether it asks for `sudo`, whether it touches your PATH, your profile or the registry, whether it schedules itself to start on its own, whether it deletes folders with dangerous paths, whether it obfuscates code, whether it reads credentials or sends data out. If it does something malicious, the finding goes up to critical; otherwise it goes down, because it is still unverified third-party code but not an attack. It is requested with curl's User-Agent, the way someone following the instructions would; a server could serve something else later, and the finding keeps the sha256 of what was reviewed. The web version does not download them (the browser cannot request arbitrary domains) and the coverage says so.

### False-positive review

The rules look for dangerous shapes of code, and those shapes also appear in harmless code. Before the verdict is decided, each finding is reviewed with its surroundings, and if its severity changes the description says why. Nothing disappears:

- **Test data.** A `curl evil.sh | sh` or a `stratum+tcp://` inside a string in a test, with nothing nearby that runs it (`exec`, `subprocess`, `eval`…), is data: it drops to low. If something runs it, it does not drop.
- **Third-party code** copied into the repo (`vendor/`, `third_party/`, `*.min.js`, Yarn in `.yarn/releases`): shape patterns (`eval(unescape())`, very long lines, arrays of numbers) drop; what is malicious by content (miners, credential theft, reverse shells) does not.
- **Example payloads whose destination is a placeholder.** A reverse shell or a PowerShell download cradle pointing at something that cannot belong to anyone (`ATTACKER_IP`, `<ip>`, names reserved for examples such as `.example` or `example.com`, loopback or documentation IPs) drops to low. Registered domains (`evil.com`, `interact.sh`…) do not count, because their owner can change; neither do private IPs, nor a line where a connection goes to a variable.
- **Documentation instructions** versus scripts that run by themselves, and the real content of the remote script (see above).
- **Typosquatting.** A package with a name similar to a popular one that has existed for years (date of the first version on deps.dev) is not a typosquat.
- **Development, documentation-site or example dependencies:** their vulnerabilities drop one level because they do not reach whoever uses the project. A **malicious** package never drops: `npm install` installs development dependencies too.
- **Documentation, private or local IPs**, mixed alphabets in translation files, code examples inside `.md` files and public Algolia DocSearch keys.
- **Comments**, according to each file's language: in JavaScript `#field = …` is a private field and `* 2; …` continues a multiplication, so those lines are not taken as comments. Neither is a line that may close a multi-line string (a JS template, a Python `"""` or a previous line ending in `\`).
- **Example paths** (`~/.ssh/id_ed25519` in a placeholder or in API documentation) and **text** that mentions a technique (the registry's `Run` key in a translation), only if the file runs no commands and sends no data.

**Who does it affect?** The tool protects whoever clones the repo, not the author. Each finding says when it would affect you: *when opening the repo*, *when installing*, *when running it*, *if you copy the command*, *only when deploying it*, *only its docs site* or *only the author*. The last three drop to low or informational: keys the author left in the repo are their problem (you only care if you use the project with that value), their CI runs on their servers, Kubernetes or Helm only matter if you deploy it, and a flaw in their documentation site affects whoever visits it. On the page, the "What affects you" filter hides them (saying how many there are) and "All" shows them; it combines with the type filters (vulnerabilities or threats) and whether they can be fixed, and findings from the same rule are grouped in a collapsible block.

It has been checked against more than 40 real, well-known repos (Express, lodash, axios, requests, Flask, ripgrep, rustup, nvm…) and against trap repos with planted malware; the tests check both things: that harmless code drops and that what really runs does not.

## Watching your clones

On the local server, every repo you clone from the app is recorded with the advisories its dependencies already had. At startup and then every 24 hours (`OMINOUS_WATCH_HOURS`), or with the **Check now** button, its dependency files are read again and queried on OSV.dev, and any vulnerability published after the clone shows up in the **Watching your clones** section, once and flagged if it is already being exploited. The check runs in a separate thread, so it does not slow the app down, and it stops after 10 minutes (`OMINOUS_WATCH_TIMEOUT_MS`): repos there was no time to check show up as skipped and keep their previous findings.

Only the clone's dependency files are read (no `node_modules` and no links leaving `CLONE_DIR`); nothing is run. The list lives in `CLONE_DIR/.ominous/watch.json`, readable only by your user, and only package names and versions are sent to OSV.dev, as in the analysis. `OMINOUS_WATCH=0` disables it.

### Data that updates itself

Dependency advisories do not go stale: they are queried on OSV.dev in every analysis. What does age lives in `data/`:

| File | What it is | Source |
|---|---|---|
| `data/kev.json` | CVEs being exploited | CISA KEV catalog |
| `data/popular.json` | most downloaded npm and PyPI packages: typosquatting targets and legitimate names that are not flagged | [npm-high-impact](https://github.com/wooorm/npm-high-impact) and [top-pypi-packages](https://github.com/hugovk/top-pypi-packages) |

Every Monday, the `update-data.yml` workflow runs `npm run update:data`, validates what it downloaded, regenerates `public/analyzer.js`, runs lint and tests and, if anything changed, opens a PR for you to review and dispatches CI and CodeQL on it (a PR opened by `github.token` does not trigger workflows on its own). It never touches `main` directly. So that it can open the PR, enable once *Settings > Actions > General > Allow GitHub Actions to create and approve pull requests*. Locally: `npm run update:data`.

## Security of the tool itself

- **Network:** by default it only listens on `127.0.0.1` and rejects any `Host` that is not this machine (protection against DNS rebinding) and any POST with a foreign `Origin` (CSRF). Requests must be JSON and 64 KB at most.
- **Exposure:** if it is opened to other names (`ALLOWED_HOSTS`/`ALLOW_ANY_HOST`) it does not start without `OMINOUS_TOKEN`. The token is compared in constant time and stored in an `HttpOnly`, `SameSite=Strict` cookie (and `Secure` behind HTTPS).
- **Disk:** clones can only go inside `CLONE_DIR`, even with symlinks in between (checked before creating any folder). This prevents cloning into folders that run by themselves, such as `~/.vim/pack/*/start` or `~/.config/autostart`. Automatic fixes do not write through linked folders.
- **Cloning:** only the analyzed branch (`--single-branch`), no submodules and nothing written to disk until the analyzed commit is pinned (`--no-checkout`), so not a single file from another branch or a later commit arrives. At startup it checks your git version and warns if it has the 2025 clone bugs (CVE-2025-48384).
- **External tools:** Gitleaks uses its own configuration and ignore list (not the analyzed repo's) and Semgrep ignores `nosemgrep` comments, so the author cannot silence their own findings.
- **Abuse:** limits on analyses per IP, simultaneous analyses and repo size. Each analysis runs in a separate thread with a time limit, so a file designed to hang analyzers (ReDoS) cannot freeze the app; the expressions are tested against lines crafted to hang them, and the earlier phases (history, submodules, tools) have a total time budget.
- **Browser:** strict `Content-Security-Policy` (the page's only script is allowed by its SHA-256 hash, computed at startup, and nothing is loaded from third parties: the fonts live in `public/fonts`), `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy: no-referrer`, `Cross-Origin-Opener-Policy` and `Permissions-Policy`.
- **Processes:** strictly validated URLs, git without a shell and hardened, and internal errors that expose no details. With Docker, the foreign repo is only touched in the `scanner` container (without your clones or your keys) and the app validates what it returns; remote scripts are only downloaded from public addresses on port 443, also after a redirect.
- **Project:** CI with CodeQL, self-scan, `npm audit`, Trivy on the image and Dependabot, using only official GitHub actions pinned by SHA (with the version in a comment; Dependabot updates them) and `persist-credentials: false` on every checkout. `main` only accepts changes through pull requests with the CI checks green.

## Command-line scanner

Analyzes a local folder without a server, for example in other projects' CI:

```bash
node bin/ominous-scan.js <folder> [--exclude path1,folder/] [--fail-on red|yellow|never] \
     [--json report.json] [--sarif ominous.sarif] [--codequality gl-code-quality-report.json]
scripts/local.sh scan ~/projects/something   # the same, inside the container, offline and read-only
```

It exits with 0 if the verdict does not reach `--fail-on` (`red` by default), with 1 if it does and with 2 on error. `--sarif` produces GitHub code scanning's format and `--codequality` GitLab's.

In GitHub Actions:

```yaml
- run: |
    docker run --rm -v "$PWD:/src:ro" --entrypoint ominous-scan \
      ghcr.io/alexdbdevops/ominous-security:latest /src --fail-on red
```

## Development and CI/CD

```bash
npm run lint        # syntax, 'use strict', JSON and invisible or bidi characters
npm test            # tests with node --test (Node 22+)
npm run scan:self   # the tool analyzes itself
npm run build:web   # regenerates public/analyzer.js after changing lib/ or web/
```

The tests generate their trap repos in a temporary folder on every run (`test/helpers/fixtures.js`). That way the repo contains no files that VS Code, pytest or Claude Code could run when opening it.

Changes reach `main` only through pull requests: a ruleset blocks direct pushes, force pushes and deletion, and requires the `lint`, `bundle`, `test (22)`, `test (24)`, `self-scan`, `audit`, `package`, `docker` and `analyze` checks. Commit messages and pull requests are written in English.

`.github/workflows/ci.yml` runs on every push to `main` and every pull request:

| Job | What it does |
|---|---|
| `lint` | `npm run lint` |
| `bundle` | `public/analyzer.js` up to date with `lib/` and `web/` |
| `test` | tests on Node 22 and 24; on 22 with coverage (job summary) and JUnit |
| `self-scan` | the tool analyzes itself; in public repos the findings show up in *Security > Code scanning* |
| `audit` | `npm audit` |
| `docker` | image with a smoke test and a Trivy scan; from `main` and tags it is published to `ghcr.io/alexdbdevops/ominous-security` |
| `package` | zip of the code as an artifact |
| `pages` | web version on GitHub Pages (only on `main`) |
| `release` | GitHub release when a `vX.Y.Z` tag matching `package.json` is pushed |

`codeql.yml` runs CodeQL every week and on every PR, `update-data.yml` refreshes the [aging data](#data-that-updates-itself) every week through a PR, and Dependabot watches npm, the actions and the base image: one grouped PR per ecosystem and only versions published for at least 7 days (14 for npm major versions).

To publish a version, bump the version in `package.json` in a PR and, once merged, run `git tag v1.0.1 && git push --tags`.

The self-scan excludes `lib/rules.js`, `lib/decoder.js`, `lib/extra.js`, `lib/i18n-en.json` (the same texts in English), the page, `public/analyzer.js` (the same rules, bundled) and this README: they contain the signatures it looks for, like an antivirus signature database.

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `Host no permitido` / `Host not allowed` (403) | You open the app with a name or port other than the configured one. Use `http://localhost:<OMINOUS_PORT>` or add the name to `ALLOWED_HOSTS` |
| It does not start: `no tiene token` | You set `ALLOWED_HOSTS` with an external name. Define `OMINOUS_TOKEN` (24+ characters) |
| `Falta el token de acceso` (401) | Open `/?token=<your token>` once to store the cookie |
| `Permission denied` when cloning with Docker | The clone folder is not owned by your user. Run `sudo chown -R "$(id -u):$(id -g)" ~/ominous-clones` |
| `El destino tiene que estar dentro de…` | The destination field only takes a folder name, inside `CLONE_DIR` |
| Reputation, Releases or Scorecard in grey | The GitHub API hit its limit (define `GITHUB_TOKEN`) or the project has no published Scorecard |
| `Dependencias (OSV.dev): no se pudo consultar` | No connection to api.osv.dev, or `OMINOUS_OFFLINE=1` |
| Web version: GitHub rate limit reached | 60 requests per hour per IP without signing in. Wait until the time shown, put a token in "GitHub token (optional)" or use the local server with `GITHUB_TOKEN` |
| Web version: cannot connect to GitHub inside claude.ai | The artifact viewer may block external connections. Open the published site or the local server |
| `No se encuentra Claude Code` when connecting | Install it on the same machine as the app (`npm install -g @anthropic-ai/claude-code`) or set its path with `OMINOUS_CLAUDE_BIN`. It is not available inside Docker |
| `Claude Code está instalado pero sin sesión` | Run `claude` in a terminal and sign in with your Pro or Max account |
| `la clave solo se puede escribir desde este mismo equipo o a través de HTTPS` | The app is exposed without HTTPS. Put the key in `ANTHROPIC_API_KEY` or publish the app behind a TLS proxy |
| Port 8080 is taken | `OMINOUS_PORT=9090 scripts/local.sh` |
| CodeQL: `sin revisar: Python: … autobuild.sh` | Old CodeQL versions do not work with Python 3.13. Update the CodeQL *bundle* or put a Python 3.12 `python3` earlier on `PATH` |
| CodeQL does not show up in the coverage | It is not on `PATH` or the repo has no JavaScript/TypeScript, Python or Ruby. Set its path with `OMINOUS_CODEQL_BIN` |
| `Paquete publicado en npm: no se pudo comparar` | No connection to the registry, or the package is larger than 25 MB |
| Watching says the folder no longer exists | You moved or deleted the clone. Press **Stop watching** |

Server-side messages (the API errors above) are in Spanish; the page shows its own text in the language you pick.

## Limits

It is static analysis by patterns (and by data flows if you have CodeQL): it greatly reduces the risk, but it is not a guarantee. A determined attacker can dodge specific rules or download the real payload at run time from a server (that is flagged, but what it will download cannot be seen). It reads the content of up to 8000 files (code and configuration first); code is read in full up to 8 MB and, if larger, the beginning and the end. Release binaries and Git LFS files are not downloaded.

## Layout

```
server.js            HTTP server, GitHub metadata, final clone, token and limits
lib/pipeline.js      analysis of one repo: clone, history, submodules, tools and analyzer
lib/scanner.js       isolated analysis container (Docker): runs lib/pipeline.js away from the app
lib/scanclient.js    the app asks the scanner for the analysis and checks everything it returns
lib/proxyproto.js    inbound to the app only from the gateway, with the real IP (PROXY protocol)
lib/gitsafe.js       hardened git, git version check and cleanup of temporary leftovers
lib/gateway.js       network gateway: inbound to the app and HTTPS-only outbound proxy to public addresses (no inbound for the scanner's)
lib/remote.js        downloads, as data, the remote scripts the repo tells you to run
lib/review.js        false-positive review and who each finding affects
lib/comments.js      which lines are comments according to the language (JS and TS with @babel/parser)
lib/netcache.js      cache for OSV, EPSS and deps.dev
lib/tarpack.js       packs the prepared clone to write it into the folder you choose
lib/i18n.js          English text for rules, cards, review notes and coverage (the page's language button)
bin/ominous-scan.js  command-line scanner (JSON, SARIF, Code Quality)
lib/analyzer.js      repo walk, structural checks, verdict, automatic fixes
lib/rules.js         vulnerability and threat rules
lib/decoder.js       reverse engineering of encoded or encrypted payloads
lib/deps.js          dependencies (OSV.dev), typosquatting, CISA KEV and EPSS
lib/depsdev.js       indirect npm dependencies without a lockfile (deps.dev)
lib/beyond.js        published npm or PyPI package and the project's own advisories
lib/watch.js         watching of cloned repos
lib/extra.js         auto-run files, AI agents, lockfiles, lures, ZIP, images, homoglyphs
lib/surfaces.js      what runs when building or opening each kind of project, pickle, Office, git tricks
lib/history.js       git history
lib/external.js      Gitleaks, Semgrep, Trivy and CodeQL if installed (optional)
lib/summary.js       summary of the fixes' diff (Claude or local)
lib/ai.js            AI review: file selection, prompt, schema and validation
lib/connection.js    connection to Claude: API key or Claude Code with your account
lib/worker.js        analysis thread with a time limit
lib/explain.js       "What is this?" cards for each rule (CWE, why it matters, what to check)
lib/github.js        GitHub URL, metadata, renames, releases and Scorecard (server and web)
web/                 web version: download from GitHub (github.js), worker (entry.js) and Node shims
public/index.html    interface (local, web and web-ai editions)
public/analyzer.js   analyzer bundled for the browser (generated, do not edit)
public/fonts/        self-hosted fonts (OFL)
Dockerfile           image (unprivileged user, tini, healthcheck)
Dockerfile.full      full image: the same plus Gitleaks, Semgrep, Trivy and CodeQL pinned by sha256
docker/              pinned Semgrep versions (semgrep-requirements.txt) and the script that generates them
compose.yaml         hardened local deployment; compose.lan.yaml opens it to your network with a token; compose.full.yaml uses the full image
scripts/local.sh     build and start locally (local.ps1 on Windows)
scripts/build-site.js web version for GitHub Pages (dist/ with the CSP in a meta)
scripts/build-web.js generates public/analyzer.js with esbuild
scripts/update-data.js refreshes data/ (KEV and popular packages)
data/                aging data, refreshed every week by update-data.yml
lib/page.js          interface and CSP of each edition
test/                tests with node --test; test/gold: labeled set (npm run gold)
```

## License

[MIT](LICENSE)
