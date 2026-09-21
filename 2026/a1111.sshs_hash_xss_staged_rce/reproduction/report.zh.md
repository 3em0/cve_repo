# a1111.sshs_hash_xss_staged_rce —— 端到端验证

**产品**：AUTOMATIC1111/stable-diffusion-webui **v1.10.1**，
`82a973c04367123ae98bd9abdf80d9eda9b910e2`（容器内自校验）。
**主机**：`.37` · **镜像**：`mbe2e/v/a1111.sshs_hash_xss_staged_rce:r1`
（基于 `mbe2e/prod:a1111-82a973c0-browser`）· **运行期网络**：`--network none`
（Chromium 与 WebUI 共用同一个只有 loopback 的网络命名空间）。

## 攻击者的全部能力

一个 LoRA 包，受害者把它解压——或者 `git clone`（这正是所有 Hugging Face 模型
仓库的获取方式）——进 `models/Lora/`：

```
mbe2e_lora/
    evil.safetensors          合法 safetensors；__metadata__.sshs_model_hash 携带载荷
    install.py                第一阶段
    scripts/mbe2e_stage2.py   第二阶段
    .git/                     这个包本身就是一个 git 检出
```

## 受害者的一次普通操作

启动 WebUI，打开 `http://127.0.0.1:7860/`。仅此而已。
所有 extra-networks 页面的 HTML 由 `interface.load` 生成
（`modules/ui_extra_networks.py:788`），所以 LoRA 卡片——连同载荷——在用户
点任何东西之前就已经进了 DOM。

## 链路

1. **元数据被原样读出**。`modules/sd_models.py:285-309` `read_metadata_from_safetensors`
   拷贝每个 `__metadata__` 项；不以 `{` 开头的值原样返回。
2. **一个字符串变成「模型哈希」**。`extensions-builtin/Lora/network.py:50-57`
   `set_hash(metadata.get('sshs_model_hash') or …)` —— 没有十六进制校验、没有
   长度校验、没有字符集校验。哈希「应该是什么样」全靠假设。
3. **被放上卡片**。`extensions-builtin/Lora/ui_extra_networks_lora.py:27-29`
   把完整哈希追加进 `search_terms`。
4. **未转义地插值**。`modules/ui_extra_networks.py:312-320`

   ```python
   search_term_template = "<span class='hidden {class}'>{search_term}</span>"
   ```

   同一张卡片上的**兄弟字段全部转义**：`sort_keys`（:306）用 `html.escape`，
   `description`（:328）用 `html.escape`。唯独 `search_term` 没有。
   放在 `hidden` span 里没有任何安全效果：被解析的事件处理器内容照样执行。
5. **同源脚本执行**，随后驱动产品自己的隐藏安装控件
   （`modules/ui_extensions.py:603-604`）—— 正是 A1111 自己的
   `javascript/extensions.js:47-55` 用于扩展索引安装的那一对控件。
6. **第一阶段 —— 宿主代码执行**。`modules/ui_extensions.py:344-394`
   `install_extension_from_url` 把攻击者指定的路径 git clone 进 `extensions/`，
   然后 `modules/launch_utils.py:228-237` 用 Python 子进程运行该包的 `install.py`。
   canary：`/out/pwned_by_a1111_sshs_stage1`。
7. **产品自己重启自己**。同一段脚本按下「Apply and restart UI」→
   `modules/ui_extensions.py:26-56` → `modules/restart.py` `restart_program()` →
   `os._exit(0)`；`webui.sh` 因为导出了 `SD_WEBUI_RESTART` 而重新拉起进程。
   **这一步没有人参与**——这正是启动器用 `webui.sh` 而不是 `launch.py` 的原因。
8. **第二阶段 —— 跨过 import 边界**。新进程里 `modules/scripts.py` `load_scripts()`
   import `extensions/mbe2e_lora/scripts/mbe2e_stage2.py`。
   canary：`/out/pwned_by_a1111_sshs_stage2`。

DATA→CONTROL 的跨越发生在第 2→4 步：safetensors 解析器正确地把它当作不透明字符串
返回，下游在用途变成「HTML」时**没有重新校验**。第 5–8 步则是产品自己的、有文档的
功能被「持有同源权限的人」正常使用。

## 负控

`models/Lora_neg/mbe2e_lora/` 与正样本完全相同——同样的 `install.py`、同样的
`scripts/mbe2e_stage2.py`、同样的 `.git`——只有 `sshs_model_hash` 换成 64 个 `b`。
它在**自己独立的一次产品生命周期里先跑**。预期：没有 DOM 标记、没有
`extensions/mbe2e_lora` 目录、两个 canary 都不出现。

## 证据

`exp/result.json`（两次运行字节一致）、`exp/browser_trace.zip`（Playwright 追踪，
含截图与 DOM 快照）、`exp/logs/`。


## 实测结果（两次运行字节一致，`rerun_identical=1`）

Playwright 从活页面上读到的 DOM 里程碑，按顺序：

```
XSS_RAN -> INSTALL_CLICKED -> INSTALL_UNCONFIRMED -> RESTART_CLICKED
```

```
product_restarted_itself : true （同一份产品日志里出现两次 "Running on local URL"）
stage1                   : /out/pwned_by_a1111_sshs_stage1 = MBE2E-CANARY-a1111-sshs-stage1-v1
stage2                   : /out/pwned_by_a1111_sshs_stage2 = MBE2E-CANARY-a1111-sshs-stage2-v1
extensions_dir_final     : ["mbe2e_lora", "put extensions here.txt"]
negative_control_clean   : true （无 DOM 标记、无扩展目录、两个 canary 都没落）
source_tree_sha256       : efbfdbe81a316f2e0758da403e8bb3e24dcd85c560bf369943372df936244905
```

单条成本：在共享产品镜像之上，构建 + 两次完整运行共 **253 秒**。

### `INSTALL_UNCONFIRMED` 是一个真实发现，不是脚手架噪声

载荷原先要等 A1111 自己的「Installed into ...」确认消息才按重启键，而这条消息
永远没来——但扩展其实已经被 clone，`install.py` 也已经执行完了。原因在
`modules/ui_extensions.py`：`install_extension_from_index` 先调用
`install_extension_from_url`（clone + `run_extension_installer`），之后才调用
`refresh_available_extensions_from_data`；在没有加载过扩展索引时后者会抛异常，
Gradio 调用因此中断、界面什么也不显示——**但 clone 与代码执行不会被回滚**。
安装器的副作用比产生它的那次调用活得更久。现在载荷改为在有界超时后继续，
这也正是真实攻击者会做的。

### 那些必须做对、但并不显然的地方

- A1111 的 safetensors 元数据缓存与 `available_networks` 字典都以
  `os.path.basename(filename)` 为键（`extensions-builtin/Lora/networks.py`），
  所以负控包如果也叫 `evil.safetensors`，正样本阶段会被悄悄喂回良性元数据。
  因此两个包使用不同的文件名。
- 同一个容器里跑两次产品生命周期必须有硬屏障：第二阶段必须等到 7860 端口
  彻底没人监听才能启动，否则它会安静地在跟上一个进程说话。

## 验证边界 —— 没有证明的东西

- **扩展安装器本身是有文档的可执行功能**，我们不对它提出任何 CVE 式主张。
  新的根因是：**模型元数据**在未经同意的情况下取得了同源浏览器权限。
- **第一阶段的可达性取决于启动方式**。`modules/shared_cmd_options.py:17-18`
  在使用 `--share`/`--listen`/`--server-name` 且未加
  `--enable-insecure-extension-access` 时会关闭扩展访问。默认的本地启动
  （也就是本次使用的、以及绝大多数人使用的方式）保持开启。在 `--listen` 下
  XSS 仍然执行，只是第 1、2 阶段被挡住。
- **这个包是一个 git 检出**。A1111 的安装器用 clone，所以载荷包必须可被 clone。
  这正是 `git clone https://huggingface.co/...` 得到的模型目录的常态，但纯 zip
  分发且不含 `.git` 的包需要另一种第二阶段。
- 使用了 `--skip-load-model-at-start`：本轮没有 checkpoint，而这条根因与 checkpoint
  加载无关；该参数只是去掉一次无意义的启动期下载尝试。
- 两个 canary 都是容器内惰性文件写。不持久化到宿主、不发网络包、不访问凭据。
