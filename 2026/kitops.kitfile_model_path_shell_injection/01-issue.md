# 01 — advisory 填写稿:kitops-ml/kitops `kit dev start` llamafile 模型路径命令注入(POSIX)

**对应本地根**:`kitops.kitfile_model_path_shell_injection`(seq 125;本地 e2e 素材包 `e2e_numbered_except_134_llamacpp/125_kitops.kitfile_model_path_shell_injection`,waveE-2 端到端验证 PASS;2026-09-27/28 在同一台 W11 主机按原协议真实复现,双跑 PASS、源码树摘要自校验一致、真实终端截图 14 张)

**advisory 状态(2026-09-28 探测)**:**未提交** —— 本稿为 PVR 提交前的逐字段填写稿;表单入口 `https://github.com/kitops-ml/kitops/security/advisories/new`。

## 通道判定(2026-09-28 实测)

- **PVR 已启用**(`api.github.com/repos/kitops-ml/kitops/private-vulnerability-reporting` → `{"enabled": true}`)→ **走私密漏洞报告**(`https://github.com/kitops-ml/kitops/security/advisories/new`),**不写公开 issue**。公开 issue 会构成提前披露。
- `SECURITY.md`:根目录存在(HTTP 200)。核心要求:漏洞一律走 GitHub Security Advisories 渠道;**禁止公开 issue / PR / discussion**;维护者承诺 5 个工作日内回应;Supported Versions 仅 latest。
- **issue 模板探测(硬性关卡,直接列目录)**:`.github/ISSUE_TEMPLATE` 目录存在但**内容为空**(contents API 返回空),无任何可用模板。community profile API 未依赖(已知对目录式模板返回 null 的盲区)。本稿英文正文因此为自由结构,供 advisory 的 description 字段使用。
- releases:latest **v1.15.0**(2026-06-25)→ 版本口径 **"up to v1.15.0"**;`sh -c` sink 在 v1.15.0 tag 与 main 上均存在(raw 文件核对,2026-09-27)。
- `.github/workflows/`:7 个工作流(build-devmode / build-docs / pr / test-container-entrypoints / platform-release / next-container-build / kubeflow-components-test),**无 stale 类工作流** → 无 stale-bot 自动关闭风险。
- 仓库状态:未归档,has_issues=true,最后推送 **2026-09-21**(维护活跃,回应预期正常)。
- **HEAD 复核**:当前 main HEAD = `d04583d6d2b6a6f48b1070f10bea637dc9c3b74a`,与验证钉定 commit `b6762849b23a599c834e5f14eda5cebcef40b640` 不同(仓库正常前进);下文行号(`llm-harness.go:90/102`、`dev.go:77`)按钉定 commit 实测,sink 在 main 上仍然存在 → "up to v1.15.0(含 main)" 口径成立。
- 公开性:issues/PR 搜索(`llamafile injection`、`sh -c llamafile`、`command injection`)仅命中词面撞车的无关 PR(#1098 lora-adapter、#559 dev 切换 llamafile);security-advisories 计数 **0**。**新发现,n-day 框架不适用。**

## Advisory 标题(建议)

OS command injection in the llamafile dev harness via ModelKit file names (`kit dev start`, POSIX)

## Advisory 表单逐字段填写(2026-09-28,按 GitHub New security advisory 表单)

**Affected products**

| 表单字段 | 填写值 | 说明 |
|---|---|---|
| Ecosystem | `Other` | 发行形态是预编译 CLI 二进制(release assets:darwin/linux/windows 的 tarballs/zips + SBOM),不经 PyPI/npm 分发;Go module `github.com/kitops-ml/kitops` 虽存在,但用户消费的是二进制。若维护者倾向按源码生态归类,可改选 `Go` + package `github.com/kitops-ml/kitops` |
| Package name | `kitops` | 仓库名即 CLI 名(`kit`) |
| Affected versions | `up to v1.15.0 (verified on source commit b6762849b23a599c834e5f14eda5cebcef40b640; the vulnerable "sh -c" sink is also present on main d04583d6d2b6a6f48b1070f10bea637dc9c3b74a as of 2026-09-27)` | 钉定 commit 实测 + main 代码核对;全版本范围未逐一枚举,报告里如实写 |
| Patched versions | 留空,或 `none yet` | 报告时无补丁;维护者出修复后再补 |

**Severity**

- 选 **High**;Vector string 填:`CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H`(**= 7.8**,可点 Calculator 复核)
- 口径说明:AV:L —— ModelKit 需落在本地盘且受害者对其运行 `kit dev start`;若维护者把 registry 投递(`kit pull` 物化此类文件名)定为网络可达,可改 **AV:N** —— 该前提我们**未经实测**,讨论时需注明

**Weaknesses**(CWE 搜索框逐个加)

- `CWE-78` — Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection'):主缺陷(`sh -c` 字符串拼接 sink)
- 可选再加 `CWE-77` — Improper Neutralization of Special Elements used in a Command ('Command Injection'):父类;若表单只允许少数几个 CWE,保留 CWE-78 即可

**Description**:贴入下方 "Advisory 正文"(已按表单 description 框的四段模板 Summary / Details / PoC / Impact 组织,markdown 格式)。

**CVE**:勾选请求 CVE 分配(与 VulDB 稿 `reqcve=Yes` 口径一致)。

**Credits**:填你的署名 `[placeholder — 你的名字/GitHub 账号]`,角色 finder。

**Publishing**:advisory 保持私密直至维护者响应(SECURITY.md 承诺 5 个工作日初审);补丁发布或协商到期后再决定公开时点(公开时点同时回填 VulDB 稿 Timeline)。

## Advisory 正文(英文,按表单 description 框的四段模板组织)

### Summary

An OS command injection vulnerability in the `kit dev start` command of KitOps allows a malicious ModelKit to run attacker-controlled commands with the victim's privileges. The resolved model file path inside a ModelKit is interpolated unquoted into a shell command string and executed through a real POSIX shell; because the payload is carried entirely by the directory and file names inside the ModelKit — ordinary data that ships with the artifact — running the documented try-out command on a shared ModelKit is the only interaction required; no privileges or configuration changes are needed. The product reports success while the injected command has already run. Classified CVSS v3.1 7.8 High (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H).

### Details

Affected: KitOps up to v1.15.0, verified on source commit `b6762849b23a599c834e5f14eda5cebcef40b640`; the vulnerable construction is also present on main `d04583d6d2b6a6f48b1070f10bea637dc9c3b74a` as of 2026-09-27 (code inspection). Platforms: Linux and macOS (the POSIX branch). The Windows branch of the same function builds an argv directly and is not affected. Line numbers below are measured at the pinned commit.

1. Shell-string sink. `pkg/lib/harness/llm-harness.go:102` (harness `Start`) launches llamafile through a real shell:

```go
cmd = exec.Command("sh", "-c",
    fmt.Sprintf("./llamafile --server --model %s --host %s --port %d --path %s --gpu AUTO --nobrowser --unsecure",
        modelPath, harness.Host, harness.Port, uiHome),
)
```

`modelPath` is the resolved model file path inside the ModelKit: the Kitfile's `model.path` plus the names of the directories and the `*.gguf` file beneath it. There is no quoting, no escaping and no argv boundary, so `/bin/sh` re-tokenises the attacker's file names into multiple commands.

2. Containment-only validation. `pkg/cmd/dev/dev.go:77` runs the path through `filesystem.VerifySubpath(contextDir, kitfile.Model.Path)`, which answers "is this still inside the context directory?" — a question about the file system that says nothing about shell metacharacters. A path whose every component is a legal POSIX filename containing no `/` passes on its own terms. `findModelFile` then walks the model directory for the single `*.gguf`; its suffix filter constrains the last five characters only. Nothing re-examines the value when its role changes from "file to open" to "text in a command line".

Two behaviors appear in the chain but are by-design and are not claimed as defects here: the harness binary (llamafile) is downloaded by the product itself on first use (`pkg/lib/harness/llm_download.go`, from `https://jozu.ml/downloads/`), and the harness is started asynchronously (`cmd.Start()`). Neither changes the injection.

What we did **not** verify: whether `kit pull` / `kit unpack` materialise such file names out of a remote ModelKit's layers. The on-disk ModelKit directory shape — what those commands are documented to produce — is sufficient to trigger.

Suggested fix: build an argv instead of a string, exactly as the Windows branch of the same function already does (`llm-harness.go:90`: `exec.Command("./llamafile.exe", "--server", "--model", modelPath, ...)`); no file name can become a command through `execve` argv boundaries. Defence in depth: reject resolved model paths whose components contain shell metacharacters or control characters (natural home: beside `VerifySubpath` in `dev.go`), and consider refusing such names when ModelKits are materialised (`kit unpack` / `kit pull`). Also make the dev server's success message reflect the harness's actual state (readiness check) — in our runs the product reported success while the model load had failed on the truncated argument.

### PoC

Reproduction uses benign sentinels only — the injected command is an inert marker write (`printf PWNED_BY_W11_KITOPS_KITFILE > /out/pwned_by_w11_kitops_kitfile`), so nothing weaponized is included.

1. Build three ModelKit directories with a deterministic script (`example/build_artifact.py` in the accompanying reproduction package): `evil_kit` (attack), `benign_kit` (control A: identical Kitfile shape, ordinary `models/model.gguf`), `nogguf_kit` (control B: no `.gguf` anywhere). Each Kitfile is ordinary (`model.path: models`); the payload lives entirely in directory/file names (`models/;printf PWNED_BY_W11_KITOPS_KITFILE >/out/pwned_by_w11_kitops_kitfile;x/…;x.gguf`), every component a legal POSIX filename containing no `/`, and the attack kit's model file is byte-identical to the benign one (sha256 `282aad56…`).
2. Negative control A — `kit dev start /artifact/benign_kit --port 18081`: "Development server started" on the ordinary model; `/out` remains empty.
3. Negative control B — `kit dev start /artifact/nogguf_kit --port 18082`: `[ERROR] Failed to start dev server: could not find model file in /artifact/nogguf_kit/models`, exit code 1 — `findModelFile` fails before the harness is built; no marker.
4. Trigger — `kit dev start /artifact/evil_kit --port 18083`: the product prints `Development server started at http://127.0.0.1:18083` and exits 0, while `/out/pwned_by_w11_kitops_kitfile` now exists containing `PWNED_BY_W11_KITOPS_KITFILE`. The harness log records `sh: 1: x.gguf: not found` — the tail of the attacker's file name executed as a third command by `/bin/sh`; the harness log of the original validation run additionally recorded llamafile starting with the truncated argument (`failed to open /artifact/evil_kit/models/: Is a directory`), showing all three parsed commands end-to-end.

Validation boundary, stated honestly: the chain was validated in a containerized harness — KitOps built from the pinned source (the source-tree digest is recomputed inside the container at run time and matches the recorded value `eee5ffd3…`), the product's own CLI driven as a real child process with no glue code, three cases including both negative controls, offline runs (`--network none`) repeated twice with byte-identical results, and the same signature re-verified with real-terminal captures on 2026-09-27/28. Registry delivery (`kit pull` / `kit unpack` materialising such names) was **not** exercised; the Windows branch was **not** executed; in the most recent runs the llamafile binary downloaded by the product exited without producing log output — the marker is written by the shell's **second** command and is strictly downstream of the string KitOps itself built, so the injection does not depend on llamafile working.

### Impact

- What kind of vulnerability: OS command injection (CWE-78) via shell-string construction from artifact-controlled file names.
- Who is impacted: any KitOps user who runs `kit dev start` on a ModelKit obtained from an untrusted source — the documented way to try a shared model. Typical targets are developer workstations and CI runners, with that user's credentials, registry tokens and source trees in reach. Default configuration, no privileges, a single interaction.
- Confidentiality: High — arbitrary command execution with the victim user's privileges. Integrity: High — arbitrary command execution (demonstrated with an inert marker write; a weaponized payload has the same reach). Availability: High — the host can be disrupted at will.
- Disclosure status: being reported privately via GitHub private vulnerability reporting (this advisory, unpublished). No public issue, gist, or exploit exists.

---

## 回填清单(advisory 提交后)

- [ ] 记录 advisory 提交日期与 GHSA 编号 → 回填本文件顶部"advisory 状态"行,并同步 `03-vuldb-submission.md` Timeline "Vendor notified"
- [ ] Credits 占位符替换为实际署名
- [ ] 维护者发布 advisory / 补丁后:回填 Timeline "Public disclosure" + "Patch released",把公开 URL 填入 VulDB 稿 `link`;advisory 表单 Patched versions 字段同步补上修复版本号
- [ ] VulDB 提交时机决策:与上游披露时点协调,未公开前不提前提交(见 03 文件)
