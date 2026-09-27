# Vulnerability Report — pythongosssss/ComfyUI-Custom-Scripts

- **渠道**：GitHub 私密漏洞报告 / Draft Security Advisory（仓库已开启 Private Vulnerability Reporting）
- **入口**：https://github.com/pythongosssss/ComfyUI-Custom-Scripts/security/advisories/new
- **报送状态：尚未报送（首报）**。2026-09-27 用本机两个账号（`3em0`、`Galaxync`）分别查 `GET /repos/pythongosssss/ComfyUI-Custom-Scripts/security-advisories`，**两次都返回 `[]`** —— 该仓库当前不存在任何由本机账号提交的 advisory，也没有可追加评论的既有单。本文件是**首报文本**。
  > 更正说明：早先 `02-issue-draft.md` 里"已提交私密报告 GHSA-m683-c3pr-q43f"的说法**无法核实且已被证伪**（见下方探测结论表），本文件与 `02-cve-report-en.md`、`03-vuldb-submission-v2.md` 均已剔除该编号。
- **影响范围**：`main @ 609f3afaa74b2f88ef9ce8d939626065e3247469`
- **公开性**：仓库无 `SECURITY.md`、无 issue 模板、无 releases/tags，PVR 已开启 —— 因此按仓库能力走**私密渠道**首报，不发公开 issue。
- **本稿的技术基线**：链路已在**真实产品栈**上端到端跑通（真实 ComfyUI 进程 + 真实 Chromium + 真实重启），到重启后的模块执行为止。此前语料里的验证只到"提取式 harness 里写文件为止"，**没有主张代码执行**。

---

## 探测结论（2026-09-27 复核，全部来自本地克隆的 `origin/main` 树，不依赖 GitHub HTTP API）

| 探测项 | 方式 | 结果 |
|---|---|---|
| `SECURITY.md`（根 / `.github/` / `docs/`） | `git ls-tree -r origin/main` 全树检索 | **不存在** |
| `.github/ISSUE_TEMPLATE/` | 同上 | **不存在**（`.github/` 下只有 `workflows/publish.yml`） |
| `CONTRIBUTING.md` / `CODE_OF_CONDUCT.md` / `security.txt` | 同上 | **不存在** |
| 安全专用漏洞报告模板 / 漏洞报告模板 | 全树检索 `security|issue_template|contributing|code_of_conduct` | **零命中** |
| releases / tags | `git ls-tree` + 本地 tag 列表 | **0 个**（版本口径只能用 "up to main commit"） |
| `private-vulnerability-reporting` | 2026-09-27 实测 `gh api repos/pythongosssss/ComfyUI-Custom-Scripts/private-vulnerability-reporting` | **已开启**：`{"enabled":true}`，私密渠道可用 |
| 是否已有本机账号报送过的 advisory | 2026-09-27 `GET repos/…/security-advisories`，分别以 `3em0` 与 `Galaxync` 两个账号查询（报告人可见未公开单） | **两次均为 `[]`** —— 从未报送过，本稿是首报 |
| `origin/main` HEAD | `git rev-parse origin/main` | `609f3afaa74b2f88ef9ce8d939626065e3247469`，**与钉定 commit 零漂移**，即当前 main 仍未修复 |
| 最后一笔提交 | `git log -1 origin/main` | `2026-02-12 03:31:29 -0800 Update workflowImage.js` |

**定档**：第 2 档 —— **advisory 表单形态**。依据：无任何专用模板、无 issue 模板、无政策文件，而 PVR 可用。因此 `01` 按 GitHub 私密报告 / Draft Advisory 的字段组织，**不发公开 issue**（公开会构成提前披露）。

**硬性要求**：仓库没有任何书面政策，因此没有仓库自定的标题前缀、时限或 PGP 要求。本项目自设 90 天协调披露窗口（在 advisory 正文中声明），并遵守"未修复前不公开"。

---

## Title（与 `02-cve-report-en.md` 的 Title 逐字一致）

```
Stored XSS via a safetensors modelspec.description in the "View Lora info..." dialog chains to arbitrary custom-node initializer overwrite and code execution at the next ComfyUI start
```

## Describe the vulnerability（必填）

### Root cause

```
Repository: pythongosssss/ComfyUI-Custom-Scripts @ 609f3afaa74b2f88ef9ce8d939626065e3247469

Two defects in this node pack form one chain. ComfyUI core is only the host process
and is not being reported as vulnerable.

1. Unescaped metadata rendering (CWE-79) -- web/js/modelInfo.js:190, LoraInfoDialog.addInfo()

     $el("div", {
       parent: this.content,
       innerHTML: info?.description ?? this.metadata["modelspec.description"] ?? "[No description provided]",
       ...
     });

   `this.metadata` is the model file's safetensors `__metadata__` map, fetched from the
   pack's own route and returned verbatim:
     py/model_info.py:8-23   get_metadata() -- plain json.loads of the header, __metadata__ as-is
     py/model_info.py:62-115 GET /pysssss/metadata/{type}/{name} -- returns that map as JSON
   `info` is the civitai lookup (web/js/modelInfo.js:196-206); when it cannot resolve,
   the `??` fallback renders the FILE's own metadata -- the branch reported here.
   Sibling sinks in the same dialog family that must be fixed together:
     web/js/common/modelInfoDialog.js:116  innerHTML: pre          (pysssss.notes preview)
     web/js/modelInfo.js:292               innerHTML: info.description  (civitai description)
     web/js/autocompleter.js:159           innerHTML: info.description  (civitai description)
   The page carries no Content-Security-Policy, no Trusted Types default policy and no
   DOMPurify, so nothing downstream blunts the assignment.

2. Extension-preserving overwrite of a file outside the route's role (write primitive)
   -- py/better_combos.py:27-53, POST /pysssss/save/{name}

     dir        = get_directory_by_type(body.get("type","output"))   # source dir (e.g. temp)
     filepath   = os.path.join(dir, normpath(subfolder), body.get("filename",""))
     ...commonpath(dir, abspath(filepath)) != dir -> 400              # guards the SOURCE only
     image_path = folder_paths.get_full_path(type, name)              # type/name from the URL
     image_path = os.path.splitext(image_path)[0] + os.path.splitext(filepath)[1]   # extension
                                                                      # taken from the UPLOAD
     shutil.copyfile(filepath, image_path)

   Nothing constrains the DESTINATION. With type=custom_nodes and
   name=<pack>/__init__.py, folder_paths.get_full_path resolves an installed node
   pack's initializer (folder_paths.py:45 registers custom_nodes; :441-458 resolves it)
   and the route swaps its extension for whatever the uploaded file had. The pack has
   no authentication on this route.

   Custom node packages are imported and executed at start-up
   (nodes.py:2246 load_custom_node -> :2266 module_spec.loader.exec_module), so the
   overwritten initializer runs as Python at the next ComfyUI start.

The attacker's entire capability is one .safetensors file: `__metadata__` is by
construction an inert map of JSON strings, and it never passes through pickle loading,
so safetensors/pickle trust settings do not apply. The carrier that was validated is
3,988 bytes in total (an 8-byte header length, a 3,976-byte JSON header carrying a
3,547-character description, and a 4-byte 1x1 float32 tensor); the prose-description
control built by the same script is 484 bytes.
```

### Steps to reproduce

```
Validated on the real product stack: ComfyUI 387f98aa + ComfyUI-Custom-Scripts 609f3afa,
one real `python main.py --listen 127.0.0.1 --port 8188 --cpu`, one real Chromium driven
by Playwright through the real frontend (real workflow-PNG drop onto the canvas, real
right-click on the LoraLoader node, real click on the pack's own "View Lora info..."
menu entry). Benign sentinels only: the staged initializer records that it ran and
registers no node.

 1. Build a metadata-only LoRA: a valid safetensors header whose
    __metadata__["modelspec.description"] is
      <img src=x onerror="...same-origin JS..."><iframe srcdoc="...">
    Place it in models/loras/.
 2. Launch ComfyUI and open a workflow that uses that LoRA.
 3. Right-click the Load LoRA node and choose "View Lora info...".
    -> the description string is assigned to innerHTML; the injected <img> is created in
       the page, its inline handler compiles (typeof img.onerror === "function") and runs.
       Observed: window token "A:200" and "B:200" (both vectors executed).
 4. The injected script, from the page's own origin, does the escalation itself:
      POST /upload/image            (multipart, filename staged_init.py, type=temp)
      POST /pysssss/save/custom_nodes/<pack>/__init__.py
           body {"type":"temp","subfolder":"","filename":"staged_init.py"}
    Both were observed as page-originated requests in the browser's own network log, both
    answered HTTP 200. The installed pack's __init__.py was then byte-identical to the
    attacker's staged file (sha256 7cf4c613...).
 5. Restart ComfyUI (real stop, real start; pid changed 1681 -> 1954).
    -> the overwritten initializer is imported and executed. It wrote its marker with
       pid 1954 and the token baked into the staged file.
```

### Impact

```
- Arbitrary Python execution with the ComfyUI process's privileges, at the next start,
  triggered by nothing more than opening the model-info dialog of a downloaded model.
- Integrity: arbitrary overwrite of any installed custom node package's initializer
  through the pack's own unauthenticated route.
- Confidentiality: the injected script runs same-origin with the ComfyUI web session and
  can use the whole local ComfyUI HTTP API as the user.
- Availability: the dialog, the session and the loading process can be disrupted at will.
- Reach: any install with this node pack (one of the most widely installed ComfyUI node
  packs) plus one malicious model file placed in models/loras/.
```

## Affected versions（必填）

```
all versions; no tagged releases exist (verified 2026-09-27: 0 tags, 0 releases)
main @ 609f3afaa74b2f88ef9ce8d939626065e3247469 (== current origin/main HEAD, zero drift) -- reproduced
last commit on main: 2026-02-12
```

## 建议回填到 advisory 的字段（提交/编辑 advisory 时填）

- Severity: `High`
- CVSS v3.1: `CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H` = `7.8`
  - `AV:L`：载体是受害者下载并放进 `models/loras/` 的模型文件本身；`UI:R`：受害者要打开该模型的 info 对话框。
  - `S:U`：漏洞组件的安全权限域就是 ComfyUI 进程（前端同源脚本 + 该包自己的 HTTP 路由同属一个进程）；代码执行落在同一域内。
- CWE: `Cross Site Scripting`（主）。链上的写原语与执行终点分别对应 CWE-434 与 CWE-94，如需多选一并加上。
- Patched versions: `[none yet]`
- Credits / Acknowledgement: `[署名方式待定]` —— 这是会随公告公开的字段，**由你决定**填什么（真名 / GitHub 账号 / 匿名），本稿不擅自代填。
- CVE ID: 需要就点 `Request CVE ID`，由 GitHub 作为 CNA 分配；**不要在报告里预先写 CVE 编号**。

## 提交后待办

- [ ] 填 Credits 署名（`[署名方式待定]` → 你的署名方式），其余字段可直接复制
- [ ] **首次报送**：打开 https://github.com/pythongosssss/ComfyUI-Custom-Scripts/security/advisories/new ，把下方 `Title` / `Describe the vulnerability` / `Affected versions` 逐段贴入（本机账号此前从未报送过，不存在可追加的既有单）
- [ ] 截图见同目录 `02-cve-report-en.md` 的截图清单（真实终端窗口 + 真实浏览器，均已采集完）
- [ ] 与维护者确认修复版本后再回填 "Patched versions"，并同步 `03-vuldb-submission-v2.md` 的 Timeline 与 `link`
- [ ] 未经维护者同意不公开、不写博客、不发社交平台
- [ ] **不要**为这个根发公开 issue：PVR 已开启，公开 issue 即提前披露
