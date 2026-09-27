# VulDB Vulnerability Submission（v2 — 更正版，勿覆盖同目录 v1）

提交地址：https://vuldb.com/en/vuln/add
提交政策：https://vuldb.com/?kb.submission ｜ 审核说明：https://vuldb.com/?kb.moderation

> **为什么有 v2**：同目录 `03-vuldb-submission.md` 是 2026-09-24 冻结的旧稿，按"不覆盖既有文件"的规矩原样保留。相对旧稿，本稿两处更正 + 一处升级：
> 1. **`Class` 更正为纯 CWE 描述文本**（旧稿写成 `Cross Site Scripting (CWE-79)`，带数字 ID，不符合 VulDB 口径）；
> 2. **`desc` 的 Validation 段升级**：旧稿写"仅提取式 harness 验证、未跑真实栈/真实重启"，本稿改为真实产品栈全链路复现的结果；
> 3. **`link` 与 Timeline 的 pending 状态同步**到当前披露进度。
>
> 表单字段名对照：`vendor` / `product` / `version` / `class` / `desc` / `link` / `reqcve`
> 报告一旦提交**无法编辑**，提交前请逐字段核对。
> 对应本地根：`comfy.custom_scripts_modelspec_staged_rce`（索引 confirmed 段 #13）
> 披露渠道：**PVR 已开启 → 走 GitHub 私密漏洞报告，无公开 issue**。截至 2026-09-27 **尚未报送**（`3em0` 与 `Galaxync` 两个账号查 `GET repos/…/security-advisories` 均为 `[]`），因此暂无任何公开 advisory URL 可填 `link`。

---

**Vendor** (`vendor`)
```
pythongosssss
```

**Product** (`product`)
```
ComfyUI-Custom-Scripts
```

**Version** (`version`)
```
up to main commit 609f3afaa74b2f88ef9ce8d939626065e3247469 (last commit 2026-02-12)
```

**Class** (`class`)
```
Cross Site Scripting
```

**Description** (`desc`)
```
A vulnerability was found in ComfyUI-Custom-Scripts up to main commit 609f3afaa74b2f88ef9ce8d939626065e3247469 and classified as high 7.8. Affected is the "View Lora info..." model info dialog component. The manipulation of the argument modelspec.description (the safetensors __metadata__ map of a model file) leads to cross-site scripting that escalates to code execution on the ComfyUI host. The attack is launched locally: the victim places an attacker-supplied .safetensors model in a models directory and opens the model's info dialog from the node's right-click menu. No privileges and no configuration changes are required.

Technical Details
- Affected file/function (verified at the current origin/main HEAD, which is exactly the audited commit 609f3afaa74b2f88ef9ce8d939626065e3247469):
  web/js/modelInfo.js:190 (LoraInfoDialog.addInfo()) passes info?.description ?? this.metadata["modelspec.description"] as the innerHTML of a $el("div", ...) without escaping; the metadata is served verbatim by py/model_info.py:62-115 (GET /pysssss/metadata/{type}/{name}, reading the header with a plain json.loads). Sibling unescaped sinks in the same dialog family: web/js/common/modelInfoDialog.js:116, web/js/modelInfo.js:292, web/js/autocompleter.js:159.
  The escalation stage uses the pack's own unauthenticated write route py/better_combos.py:27-53 (save_preview(), POST /pysssss/save/{name}): it copies a previously uploaded file over folder_paths.get_full_path(type, name) while taking the DESTINATION's extension from the UPLOADED file via os.path.splitext (lines 46-47) before shutil.copyfile (line 49). The commonpath guard on line 42 constrains the source path only, never the destination. With type=custom_nodes and name=<installed-pack>/__init__.py, any installed custom node package's initializer is overwritten. ComfyUI imports custom node packages at start-up (nodes.py:2246 load_custom_node -> :2266 module_spec.loader.exec_module), so the replaced initializer is executed as Python at the next start.
- Vulnerable parameter: modelspec.description (and the sibling description / notes fields) of a .safetensors model file's __metadata__
- Attack vector: Local
- Privileges required: None
- Trigger condition: default configuration. __metadata__ is plain JSON and never passes through pickle loading, so safetensors/pickle trust settings do not apply; a small metadata-only file is sufficient. Opening the info dialog runs the injected script; the staged write happens in the same-origin session; the code executes at the next ComfyUI start.
- Origin of the weakness: original code of the node pack. ComfyUI core is only the host process (its upload endpoint stores files without an extension check and its node loader imports custom nodes - both by design) and is not reported as vulnerable.
- Validation: full chain reproduced end to end on the REAL product stack - ComfyUI 387f98aa + ComfyUI-Custom-Scripts 609f3afa, a real `python main.py --listen 127.0.0.1 --port 8188 --cpu`, and a real headless Chromium driven through the real frontend (real workflow-PNG drop onto the canvas, real right-click, real click on the pack's own menu entry). The page's own injected script performed the escalation: the browser's network log shows page-originated POST /upload/image -> 200 and POST /pysssss/save/custom_nodes/<pack>/__init__.py -> 200. The victim package's initializer was then byte-identical to the staged file, and after a real restart (process stopped and started again, pid changed) the overwritten initializer was imported and executed, writing a marker that carried the restarted process's own pid. Negative control: a carrier whose only difference is a prose description produced no markup and no write. Benign sentinels only; no weaponized payload is included.

Impact
- Confidentiality: High (same-origin script access to the user's web session and the full local ComfyUI HTTP API; the staged initializer gives code execution with the process's privileges)
- Integrity: High (arbitrary overwrite of an installed custom node package's initializer, confirmed by file hash)
- Availability: High (the UI session and, at restart, the loading process can be disrupted at will)

CVSS v3.1
Score: 7.8 (High)
Vector: CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H

Timeline
- Discovered: 2026-09-18
- Full end-to-end reproduction on the real product stack: 2026-09-27
- Vendor notified: [pending - not yet reported; GitHub private vulnerability reporting is enabled upstream]
- Patch released: [pending]
- Public disclosure: [pending - maintainer decision]

Countermeasure
Render the metadata-derived strings as text (textContent) or through an HTML-sanitizing renderer in web/js/modelInfo.js and web/js/common/modelInfoDialog.js (sinks at modelInfo.js:190, modelInfo.js:292, modelInfoDialog.js:116 and autocompleter.js:159), and restrict POST /pysssss/save/{name} to its preview-image role: allow-list image extensions for the destination instead of inheriting the uploaded file's extension, and refuse to write outside the model directories the route exists to serve. Until a fix is released, only open model-info dialogs for model files from trusted sources.
```

**Advisory / Exploit** (`link`)
```
[pending — 见下方说明]
```
> 该根走私密渠道（PVR 已启用），advisory 在维护者处理前不公开，因此没有可填的公开 URL。两条提交路径：
> ① 等 advisory 公开（或维护者发补丁）后提交 VulDB，`link` 填公开 advisory URL，Timeline 回填真实日期（推荐）；
> ② 若私密通知后即提交 VulDB，`link` 填源码永久链接（公开可访问、无需登录）：
> https://github.com/pythongosssss/ComfyUI-Custom-Scripts/blob/609f3afaa74b2f88ef9ce8d939626065e3247469/web/js/modelInfo.js#L190

**Request CVE** (`reqcve`)
```
[ ] No  /  [x] Yes
```

---

## 本稿自检（对应内置 vuldb-submission 规范 §5）

- [x] Product / Version 精确无歧义 —— 仓库无 releases/tags（2026-09-27 复核：0 tag、0 release），Version 用 "up to main commit" + 最后提交日期；钉定 commit 即当前 `origin/main` HEAD（零漂移）
- [x] Class 与 CWE 描述文本一致 —— 取内置映射 `Cross Site Scripting`（CWE-79），**不带数字 ID**（v1 的 `(CWE-79)` 已更正）
- [x] Description 为英文，含技术细节、CIA 影响、CVSS、Timeline 与 Countermeasure
- [x] CVSS 向量与分数自洽 —— `CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H` = 7.8 (High)，严重性写作 `high 7.8`
- [x] Timeline 只写真实发生的日期，未发生的环节写 `[pending]`
- [x] Advisory / Exploit —— 尚未报送，无公开 URL；已给出两条回填路径与永久链接备选
- [x] 上游报送状态如实陈述 —— 未声称已通知厂商（早先 v1 的 `GHSA-m683-c3pr-q43f` 已核实为**不存在**，本稿已剔除）
- [x] 无 IP / 主机名 / 凭据 / 私人路径（全部为环回地址与仓库内相对路径）
- [x] 未在 VulDB 重复提交同一漏洞 —— 公开性检索零命中，该仓库 0 advisories
- [x] 证据等级口径 —— 本次为真实产品栈端到端（真实进程 + 真实浏览器 + 真实重启），只把终点不可逆效果替换为惰性 marker；desc 的 Validation 段已按此粒度如实陈述

## 提交前提示（非表单字段）

1. **建议提交时机**：先按 `01-issue.md` 走 PVR **首报**（尚未报送），等维护者回应、补丁或 advisory 公开后再提交 VulDB（此时 `link` 有公开 URL、Timeline 齐全）。若决定不等，用 `link` 备选的永久源码链接，并在 Timeline 里如实写 "not yet reported to the vendor"。
2. **公开 issue 红线**：PVR 已启用，写公开 issue 即提前披露——**不要**为这个根发公开 issue。
3. payload 纪律：本稿只含机制描述与良性 sentinel（内联处理器的 DOM token + 惰性 initializer），无可执行武器化 payload；完整复现件保留在同目录 `poc/` 与 `screenshots/`。
4. **兄弟根分离**：同一根键下涉及的其他仓库**不在本稿披露范围**——`willmiao/ComfyUI-Lora-Manager` 的姊妹链（索引 #16）、`yolain/ComfyUI-Easy-Use` 同族根（索引 #14）须单独打包单独披露。ComfyUI core（`Comfy-Org/ComfyUI`）在本链中仅扮演 by-design 的平台角色，不作为缺陷主体、不单独开包；desc 中已注明此边界，避免维护者把修复责任推给平台。
5. **披露对象选择**：三个未转义 sink 与写原语全部在本仓内，故只报本仓一个包；修复建议全部落在本仓内。
6. `desc` 与 `link` 以外的字段一旦提交不可修改；`link` 回填需在提交时一次填准。
