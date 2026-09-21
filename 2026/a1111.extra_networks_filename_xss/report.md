# AUTOMATIC1111 Stable Diffusion WebUI：恶意 LoRA 文件名导致存储型 XSS

## 漏洞概览

| 项目 | 内容 |
|---|---|
| 受影响组件 | AUTOMATIC1111/stable-diffusion-webui |
| 验证版本 | v1.10.1，提交 `82a973c04367123ae98bd9abdf80d9eda9b910e2` |
| 漏洞类型 | 存储型跨站脚本（Stored XSS） |
| CWE | CWE-79：Improper Neutralization of Input During Web Page Generation |
| 影响平台 | Linux、macOS，以及在 Unix 环境解包的模型包 |
| 复现结果 | 产品页面执行攻击者控制的 JavaScript，并向同源 API 发起请求 |
| 验证状态 | 已完成端到端验证，负控和正控结果可重复 |

## 漏洞描述

攻击者只需要控制共享模型包中一个 LoRA 文件的文件名，即可在文件名中嵌入 HTML/JavaScript。WebUI 的 Extra Networks 页面将该文件名插入卡片 HTML 时未进行 HTML 转义，导致受害者打开页面时触发脚本。

该问题属于存储型 XSS：恶意内容先被持久化在模型目录中，随后由 WebUI 扫描并渲染。脚本运行在 WebUI 的同源页面上下文中，因此可执行受当前用户会话权限允许的同源操作。

## 受影响代码路径

1. `shared.walk_files` 扫描 LoRA 目录并取得文件名。
2. `modules/ui_extra_networks.py:273` 将 `item["filename"]` 插入 `btn_copy_path_tpl`，没有调用 `html.escape`。
3. `html/extra-networks-copy-path-button.html:3` 将文件名放入 `data-clipboard-text` 属性。
4. `javascript/extraNetworks.js` 使用卡片 `innerHTML` 渲染内容，浏览器解析并执行注入的事件处理器。

同一文件名还会经 `search_terms_from_path(filename)` 进入 `search_terms`，在 `modules/ui_extra_networks.py:312-320` 存在第二个未转义插值点。相比之下，同一页面中的 `sort_keys` 和 `description` 已进行 HTML 转义。

## 利用条件

- 攻击者能够将一个模型包、LoRA 文件或其解包结果放入 WebUI 可扫描的模型目录。
- 受害者启动 WebUI 并访问 Extra Networks 页面；无需点击恶意卡片。
- 文件系统允许该文件名包含引号和 HTML 特殊字符。Windows 原生文件名限制会阻止本报告中的具体载荷，但 Unix 上解包的归档仍需防护。

## 复现步骤

### 环境

- 产品镜像：`mbe2e/prod:a1111-82a973c0-browser`
- 漏洞验证镜像：`mbe2e/v/a1111.extra_networks_filename_xss:r1`
- 运行网络：Docker `--network none`
- 源码树摘要：`efbfdbe81a316f2e0758da403e8bb3e24dcd85c560bf369943372df936244905`

### 操作

1. 进入 `reproduction/exp/`。
2. 在拥有 Docker daemon 的验证主机上执行 `./run.sh`。
3. 脚本会构建官方 safetensors writer 生成的工件、构建验证镜像，并执行两次隔离运行。
4. 检查 `reproduction/exp/result.json` 及 `reproduction/exp/logs/run1/` 中的证据。

恶意文件名使用以下载荷：

```html
x"><img src=x onerror='var s=String.fromCharCode(47);fetch(s+"sdapi"+s+"v1"+s+"refresh-checkpoints",{method:"POST"}).then(r=>document.documentElement.dataset.mbe2e="W"+r.status)'>.safetensors
```

### 预期结果

- 负控 `benign_lora.safetensors`：`dom_markers` 为空。
- 正控恶意文件名：`dom_markers` 为 `[`"W200"`]`。
- `privileged_same_origin_api_effect` 为 `true`。
- 两次运行的 `result.json` 完全一致。

## 影响与边界

本验证证明了同源存储型 XSS 及其向 WebUI API 发起请求的能力，不主张操作系统级代码执行。A1111 自定义代码脚本受 `--allow-code` 控制，本次复现未启用该选项。

文件名路径分量存在 255 字节限制，因此更长的持久化状态修改载荷无法直接放入文件名。本次演示的是 WebUI 接受的无请求体同源 POST。具体影响取决于受害者权限、WebUI 配置和暴露的同源接口。

## 修复建议

- 在所有 HTML、属性和 JavaScript 模板边界统一使用上下文相关的转义函数；至少对 `filename` 在插值前执行 HTML 转义。
- 避免通过字符串拼接生成 HTML，优先使用 DOM API 和 `textContent` / 属性赋值。
- 对模型文件名进行显示层和文件系统层的独立校验，不能将文件名当作可信 HTML。
- 增加包含引号、尖括号、事件属性和非 ASCII 字符的回归测试，并分别覆盖两个未转义汇点。
- 对模型目录来源和归档解包过程进行信任边界控制。

## 复现材料

完整复现环境原样保存在 [`reproduction/`](reproduction/)：

- Dockerfile、入口脚本和配置文件
- 正负控 safetensors 工件及构建脚本
- `exp/run.sh`、驱动脚本和确定性校验结果
- 两次运行日志、Playwright browser trace、容器输出和 SHA-256 校验文件
- 原始中英文验证记录 `report.zh.md` 和 `report.en.md`

