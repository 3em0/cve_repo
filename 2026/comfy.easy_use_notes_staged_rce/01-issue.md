# Upstream report text — yolain/ComfyUI-Easy-Use

**渠道定档(2026-09-24 探测,2026-09-27 复核)**

| 探测项 | 结果 | 依据 |
|---|---|---|
| 专用漏洞报告模板(`.github/ISSUE_TEMPLATE/` 下含 security/vuln 的表单) | **无**(目录 404) | `gh api repos/yolain/ComfyUI-Easy-Use/contents/.github/ISSUE_TEMPLATE` → 404 |
| advisory 表单(GitHub 私密漏洞报告 PVR) | **未启用**(`{"enabled":false}`) | `api.github.com/repos/yolain/ComfyUI-Easy-Use/private-vulnerability-reporting` |
| SECURITY.md(根目录 / .github/ / docs/) | **无**(三路径 404) | 同上 contents API |
| 普通 issue 模板(bug_report 等) | **无**(与专用模板同一目录,404) | 同上 |
| 仓库状态 | 未归档,has_issues=true,最后推送 2026-09-21 | `api.github.com/repos/yolain/ComfyUI-Easy-Use` |

**命中档位:第 4 档(无政策、无模板、无 advisory 入口)→ 采用通用 issue 结构**(Summary / Affected version /
Steps to reproduce / Expected / Actual / Impact / Suggested fix / Additional context)。
公开 issue 是当前唯一可用渠道,本 issue 即披露行为;文末 Disclosure note 已写明这一点并建议维护者启用 PVR。

> 公开性核查:2026-09-17 与 2026-09-24 两轮(仓库内 issues/PR 与全局搜索)未发现该精确链的任何先前报告;
> 仓库 0 个已发布 security advisory。相邻的 Save Text 任意写(#1031,已由 #1032 修复)是独立写原语,与本链无关。
> 版本口径:最新 release **v1.4.1**(2026-09-04),已实测受影响;当前 main `8730ffd14044ee9392db3b192646266576bc67df`
> (2026-09-21)逐行复核后端行号未变、v2 bundle 重建后构造仍在。

---

## Issue 标题(建议)

Stored XSS via `easyuse.notes` model metadata chains to custom-node initializer overwrite and
immediate code execution via `/easyuse/reboot`

## Issue 正文(英文,逐段可粘贴)

### Summary

A stored XSS in the ComfyUI-Easy-Use v2 model info dialog lets a malicious model file execute
attacker-controlled script in the ComfyUI web page. From the page's same-origin position, the
extension's own save route can overwrite an installed custom node's `__init__.py`, and a second
extension route (`GET /easyuse/reboot`) restarts the ComfyUI process on demand — so the overwritten
initializer is imported and executed in the same session, without waiting for a natural restart.
Overall: a stored XSS chaining to arbitrary code execution with the ComfyUI process's privileges,
requiring one normal user interaction. Verified affected: release v1.4.1 (2026-09-04) and current
main `8730ffd14044ee9392db3b192646266576bc67df` (2026-09-21).
CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H = 7.8 (High).

**Validation level of this report:** the chain has now been reproduced end to end against the real
product stack (real ComfyUI server process, real browser session through the product's own UI, real
`os.execv` self-restart), with benign sentinels only — see "PoC" and the note at the end.

### Affected version

- Component: `yolain/ComfyUI-Easy-Use`, audited snapshot `450b1ce4ce43b2280521c87f5fa388a898fb2ad2`
  (2026-09-07); release v1.4.1 ships the same vulnerable bundle and backend lines; re-verified at
  main `8730ffd14044ee9392db3b192646266576bc67df`.
- Host: ComfyUI `387f98aa2822f684b8597959a52a467d88cc4806` during validation (ComfyUI core plays a
  by-design platform role only — see Additional context).
- Default configuration is affected: the v2 web UI is the default (`__init__.py:76`,
  `web_default_version = 'v2'`); no non-default setting is required.

### Steps to reproduce

1. Attacker crafts a metadata-only `.safetensors` (187 bytes is enough; a 1-element F32 tensor plus
   header JSON) whose `__metadata__["easyuse.notes"]` contains an HTML fragment such as an `<img>`
   with an `onerror` handler; during validation the handler only set DOM attributes as a canary and
   drove the chain below. `__metadata__` is plain JSON and never goes through pickle loading, so
   safetensors/pickle trust settings have no effect on this path.
2. The victim places the file in a models directory (e.g. `models/loras/`) and opens the model's
   info dialog via the node context menu "💎 View Lora Info..." — a normal user action.
3. The dialog fetches `GET /easyuse/metadata/loras/<name>`, which returns the model file's
   `__metadata__` verbatim (`py/routes.py:204-258`, `web.json_response(meta)` at line 258; no
   sanitization).
4. The dialog then performs a Civitai `model-versions/by-hash` lookup for the model's recorded
   SHA-256 (`this.hash` = `easyuse.sha256`). When that request returns 200, the success handler calls
   `parseNote()`, which renders the notes with only `o.replaceAll("\n","<br>")` and passes the result
   as the `innerHTML` of a `span` element (shipped v2 bundle `web_version/v2/assets/extensions-DcWKQGos.js`
   at the audited snapshot; same constructs at `extensions-ClLljgcb.js` offsets 133,663 / 135,116 /
   135,158 / 135,471 / 136,041 at current main). The notes fragment is parsed as HTML and the
   handler executes in the page origin.
   - The gate is reachable for real published models (the file's real SHA-256 matches a Civitai
     model), or — for an attacker who can write into the model directory — via a `<model>.sha256`
     sidecar, which the handler trusts verbatim without comparing it to the real file hash
     (routes.py:248-251); a `<model>.txt` sidecar can carry the notes themselves (routes.py:243-246).
5. Running with the page's same-origin authority, the script then:
   1. `POST /upload/image` with `type=input` — ComfyUI core stores the uploaded bytes without
      media/extension checks (by-design platform behavior), staging a `.py` file;
   2. `POST /easyuse/save/custom_nodes/<installed-package>/__init__.py`
      (`py/routes.py:260-285`) — `save_preview` resolves the destination via
      `folder_paths.get_full_path(type, name)` (line 277), keeps the *uploaded* file's extension via
      `os.path.splitext` (lines 278-279), and copies over the existing file with `shutil.copyfile`
      (line 281). There is no folder-category allowlist and no restriction to preview images; no
      path traversal is involved — the target simply has to exist, and `custom_nodes` is a
      registered model category in ComfyUI core;
   3. `GET /easyuse/reboot` (`py/routes.py:53-60`) — the route calls
      `os.execv(sys.executable, [sys.executable] + sys.argv)` (line 60) with no confirmation and no
      CSRF boundary, replacing the running process on demand.
6. When ComfyUI re-imports custom nodes, the overwritten initializer's module body executes with the
   ComfyUI process's privileges (ComfyUI core `nodes.load_custom_node`, `exec_module`).

**Reproduction evidence (2026-09-27, real product stack, benign sentinels only):**
ComfyUI `387f98aa` + ComfyUI-Easy-Use `450b1ce4` started as a real server process
(`main.py --cpu --listen 127.0.0.1 --port 8188`); a real (headed) Chromium session opened a workflow
containing an Easy-Use loader node with the crafted lora and clicked the product's own
"View Lora Info..." context-menu entry; the Civitai by-hash request was answered by a local
test responder (the stand-in prescribed for offline validation; nothing in the page or product was
modified). Observed: DOM milestone chain `XSS_RAN → UPLOAD_200 → COPY_200 → REBOOTING`;
`custom_nodes/ComfyUI-Easy-Use/__init__.py` overwritten (sha256 `a893f051…` → `35eae873…`); the
product restarted itself via `os.execv` (second startup banner in the server log); the overwritten
initializer executed on import and wrote an inert canary file. The benign-control artifact
(identical construction, prose notes) fired only its control handler and changed nothing. 14/14
extraction-level checks had already passed in two byte-identical offline runs (2026-09-24). No
weaponized payload exists; the staged initializer body was an inert sentinel writing a marker file.

### Expected

`easyuse.notes` is displayed as text; the save route only writes preview images it is supposed to
write; the reboot route is not callable without confirmation.

### Actual

The notes value is parsed as HTML in the page origin; the save route overwrites any existing file in
any registered model folder category (including `custom_nodes` package files) while preserving the
uploaded file's extension; the reboot route replaces the process on demand — so the three
independent defects compose into same-session code execution after one normal user interaction.

### Impact

- Confidentiality: high — script runs with the user's session in the ComfyUI origin and reaches the
  local API; the initializer replacement leads to arbitrary code execution with the ComfyUI
  process's privileges.
- Integrity: high — arbitrary overwrite of an installed custom node's initializer through the
  extension's own save route.
- Availability: high — `/easyuse/reboot` lets the script kill and restart the ComfyUI process at
  will, independent of any code execution.
- Everyone running ComfyUI with ComfyUI-Easy-Use installed is affected when opening the info dialog
  of a model file from an untrusted source — the normal way models are shared in this ecosystem.
  Authenticated deployments do not help: the same-origin script inherits the current user's session.

### Suggested fix

1. Render `easyuse.notes` and any metadata-derived strings as text (`textContent`) or through a
   strict HTML-sanitizing allowlist that rejects event handlers and active content, in the v2 bundle
   source, then rebuild — the fix must cover the `parseNote` path, not just the direct dialog fields.
2. Restrict `POST /easyuse/save/{name}` to its preview-image role: allowlist the folder categories it
   may write, reject non-image extensions, re-verify canonical containment of the resolved target
   before `shutil.copyfile`, and refuse to overwrite files that are not the selected model's preview
   image.
3. Put `/easyuse/reboot` behind a POST with a same-origin token/confirmation instead of an
   unauthenticated GET.
4. Treat the `.sha256` sidecar as a cache only — validate its format and compare it against the real
   file hash before use; give the `.txt` notes sidecar the same provenance scrutiny.

### Additional context

- Two ComfyUI-core behaviors appear in the chain — the upload endpoint stores files without
  media/extension checks, and custom-node packages are imported at startup — but both are by-design
  platform behavior; the three defects that make the chain work (the unescaped notes sink, the
  no-allowlist extension-preserving save route, and the unauthenticated reboot route) are all in this
  extension. (Platform observation for Comfy-Org, out of scope here: `/upload/image` currently acts
  as an arbitrary byte stager because it performs no media/extension checks.)
- Preconditions, stated plainly: Easy-Use installed with default settings; one normal user
  interaction (opening the model info dialog); the Civitai by-hash request succeeding for the
  recorded hash (real published model, or attacker-writable `.sha256` sidecar borrowing a published
  hash); and the browser allowing the request to civitai.com (a strict reverse-proxy CSP with
  `connect-src` limited to `'self'` would prevent the sink from being reached).
- This report covers exactly one root: the v2 `easyuse.notes` sink chain. The same-repo v1 workflow
  metadata sink is a separate finding and should be tracked separately.
- No exploit code accompanies this report; all validation used benign sentinels (DOM-attribute
  canary, inert initializer body, marker file), and no weaponized payload will be published.

---

**Disclosure note**

As of 2026-09-24 this repository has GitHub private vulnerability reporting disabled and no
SECURITY.md, so a public issue is the only reporting channel available; this issue is therefore the
disclosure. Please consider enabling private vulnerability reporting (repo Settings → Code security)
for future reports. Publicity check: no prior report of this exact chain was found in this
repository's issues/PRs or globally (searched 2026-09-17, re-run 2026-09-24; the repository has no
published security advisories). The already-fixed Save Text write issue (#1031, fixed by #1032) is a
different, independent write primitive. No exploit bundle accompanies this report; all validation
used benign sentinels, and no weaponized payload will be published.

---

## 回填清单(issue 提交后)

- [ ] `gh api "repos/yolain/ComfyUI-Easy-Use/issues?state=all&per_page=10&sort=created&direction=desc"` 匹配作者/标题/日期 → 记录 number、author、created_at、state
- [ ] 检查标题是否带入复制残渣(多余反引号/代码栅栏字符)
- [ ] 将 `<NUM>` 回填到 `03-vuldb-submission.md` 的 Timeline(Vendor notified + Public disclosure)与 `link`
- [ ] 03 文件头部占位警告改为确认行(含 issue 元数据)
- [ ] 维护者回应后按需更新 Timeline "Patch released"

## 附:advisory 表单逐格映射(备用——本仓 PVR 未启用,外部报告者无法直接提交;供维护者启用 PVR 后或自建 advisory 时使用)

| 表单字段 | 填入内容 |
|---|---|
| Title | Stored XSS in the v2 model info dialog (easyuse.notes metadata) can stage code execution via initializer overwrite and /easyuse/reboot |
| Affected repository | `yolain/ComfyUI-Easy-Use` |
| Ecosystem | `Other`(git clone / ComfyUI-Manager 安装,无 PyPI 发布物) |
| Package name | `ComfyUI-Easy-Use` |
| Affected versions | `<= 1.4.1`(v1.4.1 tag 实测受影响;commit 级表述见 Description) |
| Patched versions | `[pending — 修复发布后回填 tag]` |
| Severity | AV:L / AC:L / PR:N / UI:R / S:U / C:H / I:H / A:H → 7.8 High(自动计算) |
| CWEs | 主:CWE-79;升级结果 CWE-94 只写进 Description |
| Credits | `[用户 GitHub 用户名]`,Credit type: `Finder` |
| Description | 复用上方 Issue 正文(Summary / Affected version / Steps / Impact 四节);Disclosure note 换为 advisory 语境:"Reported publicly via issue <NUM> on 2026-09-24; this advisory tracks the fix…" |

**CVE 编号协调**:若维护者发布 advisory 并由 GitHub(CNA)分配 CVE,优先沿用 GHSA 的 CVE,
VulDB 的 `reqcve` 决策须复核,避免双重编号(见 03 文件)。
