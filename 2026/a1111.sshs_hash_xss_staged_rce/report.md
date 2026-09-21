# AUTOMATIC1111 Stable Diffusion WebUI：LoRA 元数据 XSS 链接扩展安装并在重启后执行代码

## 漏洞概览

| 项目 | 内容 |
|---|---|
| 添加日期 | 2026-09-20 |
| 受影响组件 | AUTOMATIC1111/stable-diffusion-webui |
| 验证版本 | v1.10.1，提交 `82a973c04367123ae98bd9abdf80d9eda9b910e2` |
| 漏洞类型 | 存储型 XSS；同源扩展安装链；重启后进程内代码执行 |
| CWE | CWE-79：Improper Neutralization of Input During Web Page Generation；CWE-94：Improper Control of Generation of Code |
| 严重性 | 高（依赖恶意模型包投递；默认本地启动配置下完成端到端验证） |
| 验证状态 | E2 产品端到端验证通过，负控干净，双次运行结果一致 |

## 漏洞描述

AUTOMATIC1111 从 safetensors 元数据读取 `sshs_model_hash`，将其作为 LoRA 的模型哈希使用，但没有进行十六进制、长度或字符集校验。该值随后被追加到 Extra Networks 卡片的 `search_terms`，并在 `modules/ui_extra_networks.py:312-320` 中以未转义 HTML 插入页面。

攻击者可以在模型包中携带恶意 `sshs_model_hash`，受害者只需启动 WebUI 并访问页面，脚本即在 WebUI 同源上下文执行。验证载荷进一步驱动 A1111 自己的扩展安装控件，安装攻击者指定的 git 扩展，执行其中的 `install.py`，再触发产品重启；第二阶段脚本在新进程加载扩展时被导入执行。

## 受影响代码路径

1. `modules/sd_models.py:285-309` 原样读取 safetensors `__metadata__`。
2. `extensions-builtin/Lora/network.py:50-57` 将 `sshs_model_hash` 传入 `set_hash()`，没有格式校验。
3. `extensions-builtin/Lora/ui_extra_networks_lora.py:27-29` 将完整哈希加入 `search_terms`。
4. `modules/ui_extra_networks.py:312-320` 将 `search_terms` 插入 `<span>` 模板时未执行 HTML 转义。
5. XSS 使用同源权限驱动 `modules/ui_extensions.py:603-604` 的扩展安装控件。
6. `modules/ui_extensions.py:344-394` 将攻击者指定的扩展 clone 到 `extensions/`，并由 `modules/launch_utils.py:228-237` 执行 `install.py`。
7. `modules/ui_extensions.py:26-56` / `modules/restart.py` 触发产品自身重启。
8. 新进程通过 `modules/scripts.py:load_scripts()` 导入扩展中的第二阶段脚本。

根因是模型元数据在从“不透明字符串”转换为 HTML 时没有重新校验和转义；之后的扩展安装和重启功能虽是产品自身的合法功能，但被同源 XSS 越权驱动。

## 利用条件与安全边界

- 攻击者需要提供一个 LoRA 模型包，并使受害者将其解压或 clone 到 `models/Lora/`。
- 本次模型目录是一个 git checkout，因为 A1111 的扩展安装器使用 git clone；这是 Hugging Face 模型仓库的常见分发形态。
- 受害者启动 WebUI 并访问 Extra Networks 页面；无需点击恶意卡片。
- 默认本地启动模式下，完整两阶段链路可达。使用 `--listen`、`--share` 或 `--server-name` 且未启用不安全扩展访问时，后续扩展安装阶段可能被 A1111 配置阻断，但 XSS 本身仍可执行。
- 这不是无前置条件的网络 RCE；模型包投递是必要前提。本报告不将扩展安装器本身作为独立漏洞主张。

## 复现步骤

### 环境

- 产品镜像：`mbe2e/prod:a1111-82a973c0-browser`
- 验证镜像：`mbe2e/v/a1111.sshs_hash_xss_staged_rce:r1`
- 运行网络：Docker `--network none`
- 产品提交：`82a973c04367123ae98bd9abdf80d9eda9b910e2`
- 浏览器与 WebUI 位于同一仅含 loopback 的网络命名空间

### 操作

1. 进入 `reproduction/exp/`。
2. 在拥有 Docker daemon 的验证主机上执行 `./run.sh`。
3. 脚本构建正负控模型工件和验证镜像，并执行两次完整产品生命周期。
4. 正控通过 `evil.safetensors` 的 `sshs_model_hash` 触发页面脚本；负控使用同样的扩展载荷，但将哈希替换为 64 个 `b`。
5. 检查 `reproduction/exp/result.json`、`reproduction/exp/SHA256SUMS`、browser trace 和两次运行日志。

### 预期结果

- 负控无 DOM 标记、无扩展目录、两个 canary 均不存在。
- 正控依次出现 `XSS_RAN`、`INSTALL_CLICKED`、`RESTART_CLICKED`，并完成扩展安装和产品重启。
- 第一阶段 `install.py` 写入 `/out/pwned_by_a1111_sshs_stage1`。
- 产品重启后，第二阶段脚本写入 `/out/pwned_by_a1111_sshs_stage2`。

## 验证结果

来自已保存的 `result.json`：

```text
verdict: PASS
achieved_grade: E2_product_e2e
xss_executed_in_origin: true
stage1_host_exec: true
stage2_after_restart_import: true
product_restarted_itself: true
negative_control_clean: true
```

Canary 内容分别为：

```text
stage1: MBE2E-CANARY-a1111-sshs-stage1-v1
stage2: MBE2E-CANARY-a1111-sshs-stage2-v1
```

两次完整运行结果字节一致，单次构建和双次运行总耗时约 253 秒。

## 影响边界

验证证明恶意模型元数据可以在同源页面执行 JavaScript，并在默认本地启动模式下借助现有扩展功能完成第一阶段宿主代码执行和第二阶段重启后导入执行。复现未证明宿主文件持久化、网络外传、凭据访问或权限提升；canary 仅写入隔离容器。

## 修复建议

- 对 `sshs_model_hash` 及所有模型元数据实施严格格式校验和长度限制；不符合预期的值应被拒绝或安全编码。
- 在所有 HTML、属性和 JavaScript 模板边界使用上下文相关转义，优先避免字符串拼接并使用 `textContent`。
- 不要让模型内容获得扩展安装、扩展目录写入或重启 UI 的同源操作权限；高风险操作应要求明确用户确认和独立授权。
- 对 `install_extension_from_url`、`install.py` 执行和扩展重启增加权限隔离、来源校验及审计。
- 增加真实产品端到端回归测试，覆盖恶意 safetensors 元数据、Extra Networks 渲染、扩展安装和重启后的脚本导入。

## 复现材料

完整复现环境原样保存在 [`reproduction/`](reproduction/)：

- Dockerfile、配置、入口脚本和固定源码验证环境
- 正负控 safetensors、元数据、git 扩展和两阶段载荷
- `exp/run.sh`、Playwright 驱动、browser trace、容器日志和产品日志
- 两次运行结果、SHA-256 校验和及原始中英文验证报告

