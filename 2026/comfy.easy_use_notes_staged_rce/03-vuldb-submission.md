# VulDB Vulnerability Submission

提交地址：https://vuldb.com/en/vuln/add
提交政策：https://vuldb.com/?kb.submission ｜ 审核说明：https://vuldb.com/?kb.moderation

> 表单字段名对照：`vendor` / `product` / `version` / `class` / `desc` / `link` / `reqcve`
> 报告一旦提交**无法编辑**，提交前请逐字段核对。
> 对应本地根：`comfy.easy_use_notes_staged_rce`（索引 confirmed 段 #14，MB 流，`reports/comfy_wave4_media_scan.md` Finding 1；复核封顶 `D2_real_loader`）
> 披露渠道：**PVR 未启用 + 无 SECURITY.md → 公开 issue 是唯一渠道**。Timeline 日期与 `link` 待 issue 实际提交后回填 `<NUM>`（见提交前提示第 2 条）。
> 复现等级更新（2026-09-27）：**真实产品栈端到端复现完成**（真实服务进程 + 真实浏览器 + 真实 os.execv 自重启，判 PASS，仅哨兵件），证据见 `02-cve-report-en.md` PoC 与 `poc/live/evidence/result.json`；本稿 desc 的 Validation 已同步。

---

**Vendor** (`vendor`)
```
yolain
```

**Product** (`product`)
```
ComfyUI-Easy-Use
```

**Version** (`version`)
```
up to main commit 8730ffd14044ee9392db3b192646266576bc67df (release v1.4.1, 2026-09-04)
```

**Class** (`class`)
```
Cross Site Scripting (CWE-79)
```

**Description** (`desc`)
```
A vulnerability was found in ComfyUI-Easy-Use up to main commit 8730ffd14044ee9392db3b192646266576bc67df (release v1.4.1, 2026-09-04) and classified as high 7.8. Affected is the v2 model info dialog rendering component. The manipulation of the argument easyuse.notes (safetensors __metadata__ of a model file) leads to cross-site scripting which can stage arbitrary code execution on the ComfyUI host. The attack is launched locally: the victim has to place an attacker-supplied .safetensors model (or model-directory sidecar files) in a models directory and open the model's info dialog in the web UI; the notes rendering additionally requires the dialog's Civitai by-hash lookup to return 200 for the model's recorded SHA-256, which an attacker-controlled .sha256 sidecar borrowing a published hash can satisfy.

Technical Details
- Affected file/function (all re-measured at the current main commit 8730ffd14044ee9392db3b192646266576bc67df on 2026-09-24; audited commit 450b1ce4ce43b2280521c87f5fa388a898fb2ad2 of 2026-09-07):
  In the shipped v2 production bundle web_version/v2/assets/extensions-ClLljgcb.js, the model info dialog reads this.metadata["easyuse.notes"] (byte offset 133,663), fetches /easyuse/metadata/<type>/<name>, and its parseNote method renders the notes with only o.replaceAll("\n","<br>") (offset 135,116) before passing the result as innerHTML of a span element (offset 135,158), without HTML escaping; parseNote is invoked from the success handler of a Civitai model-versions/by-hash request (fetch at offset 135,471, parseNote.call(this) at offset 136,041). The audited snapshot shipped the same constructs in extensions-DcWKQGos.js at offsets 130,182 / 130,489; that bundle is what release v1.4.1 ships.
  The backend returns the metadata verbatim: py/routes.py:204-258 (load_metadata(), route GET /easyuse/metadata/{name}) returns the model file's __metadata__ JSON without sanitization (json_response at line 258); a same-name .sha256 sidecar is trusted as the model hash without comparison to the real file's SHA-256 (lines 248-251), and a same-name .txt sidecar feeds easyuse.notes directly (lines 243-246).
  The escalation uses py/routes.py:260-285 (save_preview(), route POST /easyuse/save/{name}): it copies a previously uploaded file over folder_paths.get_full_path(type, name) while preserving the uploaded file's extension via os.path.splitext (lines 277-279) in shutil.copyfile (line 281); there is no folder-category allowlist, so an installed custom node's __init__.py is a reachable copy target without any path traversal. py/routes.py:53-60 (reboot(), route GET /easyuse/reboot) calls os.execv(sys.executable, ...) (line 60) with no confirmation or CSRF boundary, restarting the process on demand so the overwritten initializer is imported immediately rather than at the next natural start; ComfyUI core imports custom-node initializers at startup.
- Vulnerable parameter: easyuse.notes (with the sidecar-fed easyuse.sha256) of a .safetensors model file's __metadata__ / model directory
- Attack vector: Local
- Privileges required: None
- Trigger condition: default configuration (the v2 web UI is the default, __init__.py line 76). __metadata__ is plain JSON and never passes through pickle loading, so safetensors/pickle trust settings do not apply, and a 187-byte metadata-only file is sufficient. One normal user interaction (opening the model info dialog) is required; the notes sink additionally requires the Civitai by-hash lookup to succeed for the recorded hash (real published model, or attacker-writable .sha256 sidecar borrowing a published hash) and browser connectivity to civitai.com.
- Origin of the weakness: original code of the extension. No prior advisory or public report of this exact chain exists (in-repo and global searches on 2026-09-17 and 2026-09-24; the repository has 0 published security advisories). The already-fixed Save Text arbitrary-write issue (#1031, fixed by #1032) is a different, independent write primitive.
- Validation: two independent rounds, benign sentinels only. 2026-09-24: extraction-based harness driving the verbatim production code (metadata route, shipped v2 bundle's parseNote executed as-is in a browser, real upload handler and save route, real custom-node loader), 14/14 checks in two byte-identical offline runs. 2026-09-27: real product-stack end-to-end reproduction — a real ComfyUI server process (ComfyUI 387f98aa), a real browser session through the product's own View Lora Info menu on the default v2 web root, and a real os.execv self-restart; the milestone chain XSS_RAN/UPLOAD_200/COPY_200/REBOOTING was observed, the installed initializer was overwritten (sha256 before/after recorded) and its replacement body executed during the product's own custom-node import after the self-restart, writing an inert marker file; negative control clean. The dialog's Civitai by-hash request was answered by a local responder (the offline stand-in prescribed for this gate); no weaponized payload exists.

Impact
- Confidentiality: High (same-origin script access to the user's web session and the local API; the staged initializer replacement leads to arbitrary code execution with the ComfyUI process's privileges)
- Integrity: High (arbitrary overwrite of an installed custom node's initializer via the extension's save route)
- Availability: High (the GET /easyuse/reboot route lets the script kill and restart the ComfyUI process at will, independent of any code execution)

CVSS v3.1
Score: 7.8 (High)
Vector: CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H

Timeline
- Discovered: 2026-09-17
- Vendor notified: [pending — public issue <NUM> to be opened (pack finalized 2026-09-27); the repository has private vulnerability reporting disabled and no SECURITY.md, so the public issue is the notification channel]
- Patch released: [pending]
- Public disclosure: [pending — the public issue itself, upon posting]

Countermeasure
Render easyuse.notes and any metadata-derived strings as text (textContent) or through a strict HTML-sanitizing allowlist in the v2 bundle source and rebuild; restrict POST /easyuse/save/{name} to its preview-image role (folder-category allowlist, image-extension allowlist, canonical containment re-check before shutil.copyfile); put GET /easyuse/reboot behind a POST with a same-origin token; treat the .sha256 sidecar as a cache only and compare it against the real file hash before use. Until a fix is released, only open model-info dialogs on model files from trusted sources.
```

**Advisory / Exploit** (`link`)
```
[pending — 公开 issue 提交后回填：https://github.com/yolain/ComfyUI-Easy-Use/issues/<NUM>]
```
> 备份 link（源码永久链接，公开可访问、无需登录，issue 因故查不到时用）：
> https://github.com/yolain/ComfyUI-Easy-Use/blob/8730ffd14044ee9392db3b192646266576bc67df/py/routes.py#L260-L285
> （前端 sink 在压缩单文件 bundle 内无法按行锚定：`web_version/v2/assets/extensions-ClLljgcb.js` @ `8730ffd1`，offsets 135,116 / 135,158，desc 已引）

**Request CVE** (`reqcve`)
```
[ ] No  /  [x] Yes
```

---

## 本稿自检（对应内置 vuldb-submission 规范 §5）

- [x] Product / Version 精确无歧义 —— 最新 release v1.4.1（2026-09-04，实测 tag 受影响）；Version 用 "up to main commit" + 当前 main HEAD（2026-09-24 复核实测）
- [x] Class 与 CWE 描述文本一致 —— 取内置映射 `Cross Site Scripting`（CWE-79）；升级链（CWE-94 代码执行）在 Technical Details / Impact 中如实描述，等级字段只进 CVSS
- [x] Description 为英文，含技术细节与 CIA 影响
- [x] CVSS 向量与分数自洽 —— `CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H` = 7.8 (High)；UI:R 对应"打开模型信息弹窗"这一次正常交互
- [x] Advisory / Exploit —— 公开 issue 未发前无 URL，`<NUM>` 占位 + 永久链接备份已给出；回填需在提交时一次填准
- [x] 已完成负责任披露路径 —— PVR 未启用、无 SECURITY.md，公开 issue 即唯一渠道即披露行为；正文含披露注记并建议启用 PVR；无提前公开的 gist/payload
- [x] 无 IP / 主机名 / 凭据 / 私人路径
- [x] 未在 VulDB 重复提交同一漏洞 —— 公开性检索 2026-09-17（原扫描）+ 2026-09-24（披露日复跑）零命中，0 advisories
- [x] 证据等级口径 —— 两轮独立验证:2026-09-24 提取式复核(14/14 双跑字节一致,封顶 D2)+ 2026-09-27 真实产品栈端到端复现(真实服务进程/真实浏览器/真实 os.execv 自重启,判 PASS,哨兵件,Civitai by-hash 用本地 responder 兜底);desc 的 Validation 已按此粒度如实陈述,未虚报、未混用两轮环境
- [x] 触发条件如实完整 —— desc 写明 Civitai by-hash 成功分支这一前提（真实发布模型 SHA 或攻击者可控 .sha256 sidecar），未夸大为"无前提 RCE"

## 提交前提示（非表单字段）

1. **渠道状态（2026-09-24 实测）**：`yolain/ComfyUI-Easy-Use` PVR **未启用**；无 `SECURITY.md`（三路径 404）；**无 issue 模板**（直接列 `.github/ISSUE_TEMPLATE/` → 404，community profile API 未依赖）；releases v1.4.1 / v1.4.0 / v1.3.6；`.github/workflows/` 仅 `publish.yml`，**无 stale-bot 自动关闭风险**。仓库未归档，has_issues=true，最后推送 2026-09-21，2,761 stars，570 open issues（活跃但积压大）。
2. **提交顺序**：先用 `01-issue.md` 发公开 issue（这一步是披露行为本身）→ 回填 `<NUM>` 到本稿 Timeline（Vendor notified + Public disclosure）与 `link` → 再提交 VulDB。`desc`/`version`/`class` 等字段提交后不可改，`link` 必须提交时一次填准。若用户尚未发 issue，**不要**先提交 VulDB。
3. **reqcve=Yes 理由**：本根为全新协调发现（非 n-day）；因 PVR 未启用无法走 GHSA 要 CVE，VulDB 的 CVE 预留是当前可行路径。**但若维护者随后发布 advisory 并由 GitHub 分配 CVE**（见 02 文件"Advisory 表单逐格映射"一节），提交 VulDB 前须复核本决策——优先沿用 GHSA 的 CVE，避免双重编号。
4. **公开性状态**：精确链（metadata XSS + `/easyuse/save` category confusion + `/easyuse/reboot`）未在公开渠道找到（2026-09-17 与 2026-09-24 两轮检索）；相邻 #1031（Save Text 任意写）已修，本稿已注明其独立性，避免维护者当作重复。**不要联系 Comfy-Org 上游**——本根不涉及上游已修复问题，n-day 框架不适用。
5. **兄弟根分离**：`comfy.easyuse_v1_workflow_metadata_xss`（同仓 v1 工作流元数据 XSS，独立根）**不在本稿范围**，须单独打包单独披露；`comfy.custom_scripts_modelspec_staged_rce`（#13，已有独立包）与 `comfy.lora_manager_frequency_staged_rce`（#16）同理。本 issue/VulDB 行只覆盖索引 #14。
6. **ComfyUI core 定位**（索引 #14 另列 `Comfy-Org/ComfyUI`·c）：core 在链中仅扮演 by-design 平台角色（`/upload/image` 不过滤媒体/扩展名，server.py:397 `image_upload`，已在当前 master `1568e6cf` 结构复核；启动时导入自定义节点包），三个可修缺陷（未转义 sink、无 allowlist 的 save 路由、裸 GET reboot）全部在本仓，desc 已注明此边界，防止把修复责任推给平台。core 不为此根单独开包；若日后要单报 `/upload/image` 任意字节暂存问题，那是另一份披露。
7. payload 纪律：issue 与 VulDB 稿只含机制描述与良性 sentinel（DOM 属性 canary、惰性 initializer body、execv recorder），无可执行 payload；PoC 与 14 项检查的动态案卷保留在本地（`repro/easy_use_notes/`）。
8. **HEAD 复核摘要（2026-09-24，披露日）**：HEAD 已从审计钉定 `450b1ce4`（2026-09-07）前移至 `8730ffd1`（2026-09-21）——后端行号全部未变；v2 bundle 重建为 `extensions-ClLljgcb.js`，构造逐字复核仍在（新 offsets 133,663 / 135,116 / 135,158 / 135,471 / 136,041，`parseNote` 仍在 Civitai by-hash 成功分支内调用）；v1.4.1 tag 实测受影响（routes.py 同构 + 随包即审计钉定 bundle）。若 VulDB 实际提交日晚于 09-24 数日，提交前把 bundle 文件名与 offsets 再跑一遍（`gh api repos/yolain/ComfyUI-Easy-Use/contents/web_version/v2/assets?ref=<HEAD>`）。
