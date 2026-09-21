# a1111.safetensors_yaml_target —— 端到端验证

**产品**：AUTOMATIC1111/stable-diffusion-webui，发行版 **v1.10.1**，commit
`82a973c04367123ae98bd9abdf80d9eda9b910e2`（容器内用 `git rev-parse HEAD` 自校验）。
**主机**：`.37` · **镜像**：`mbe2e/v/a1111.safetensors_yaml_target:r1`
（基于 `mbe2e/prod:a1111-82a973c0`）· **运行期网络**：`--network none`。

## 攻击者只能做一件事

发布一个模型包，受害者把它解压进 `models/Stable-diffusion/`：

```
mbe2e_pack/
    model.safetensors   696 字节，由 safetensors.torch.save_file 正常写出
    model.yaml          同基名 sidecar 配置
    hubconf.py          普通文件，受害者机器上没有任何东西会直接 import 它
```

我们不在受害者机器上跑任何 Python，不 import、不打桩、不 monkeypatch。产品自己的
`safe.py` RestrictedUnpickler、torch 的 `weights_only` 默认值、真实的 safetensors
解析器**全部在线**。

## 受害者做的一次普通操作

启动 WebUI，然后选中这个 checkpoint。选择动作走产品自己的公开 API，
和任何模型管理器做的事完全一样：

```
GET  /sdapi/v1/sd-models
POST /sdapi/v1/options   {"sd_model_checkpoint": "<title>"}
```

## 信任委托链

| 步 | 代码位置 | 这个字段此刻被当作什么 |
|---|---|---|
| 1 | `modules/sd_models.py:332-347` | 真实 safetensors 解析器读 checkpoint |
| 2 | `modules/sd_models_config.py:117-136` | `<basename>.yaml` **仅因为路径名相同**就被优先采用，没有任何其他关系被验证 |
| 3 | `modules/sd_models.py:809` | `OmegaConf.load()` —— 还是普通数据 |
| 4 | `modules/sd_models.py:599-602` | `repair_config()` 注入 `model.params.use_ema=False` |
| 5 | `modules/sd_models.py:766-775` | `instantiate_from_config`：`constructor = get_obj_from_str(config["target"])`，然后 `constructor(**params)` |
| 6 | `modules/sd_models.py:778-783` | `get_obj_from_str`：`importlib.import_module()` + `getattr` —— **字符串此刻成了模块名** |
| 7 | `torch/hub.py` `_load_local` → `_import_module` | `spec.loader.exec_module()` 执行模型包自带的 `hubconf.py` —— **攻击者代码以 WebUI 进程身份运行** |

第 5–6 步就是 DATA→CONTROL 的跨越：加载器当作「配置」读出来的一个 YAML 字符串，
在用途改变时没有被重新校验，直接成为要 import 的模块名和要调用的可调用对象。

## 为什么已公开的 PoC 在真实产品里跑不通

包括本项目 `submission/01_A1111_yaml_RCE/` 在内的公开写法都是：

```yaml
model:
  target: subprocess.run
  params:
    args: ["touch", "/tmp/pwned_by_a1111_yaml"]
```

并且直接手工调用 `instantiate_from_config` 来「验证」。**这个 gadget 在真实产品路径上
是失败的**：`repair_config()`（`sd_models.py:599-602`）在 `OmegaConf.load` 与
`instantiate_from_config` 之间执行，会加上 `model.params.use_ema = False`；
`subprocess.run` 把这个未知关键字转给 `Popen`，抛 `TypeError`。
这条根因的任何 gadget 都必须能吞掉 `**kwargs`。

这正是「代码切片」会掩盖的东西：被抠出来的函数体，和它在产品里的行为不一样。

本次使用的 gadget `torch.hub.load(..., source="local")` 接受 `**kwargs` 并转发给
entry point；它就是 A1111 自己钉死的 `torch==2.1.2`，不需要网络；`repo_or_dir`
是**相对 WebUI 工作目录**的路径，而 `webui.sh` 永远把工作目录设为仓库根，
所以攻击者不需要猜测绝对安装路径。

## 负控

`mbe2e_neg/` 与 `mbe2e_pack/` 逐字节相同，只有一个字符串不同：
`model.target: torch.nn.Identity`。同样的 `hubconf.py` 载荷文件也在目录里。
它**先**被选中。预期：产品日志出现
`Creating model from config: models/Stable-diffusion/mbe2e_neg/model.yaml`
（证明 sidecar 确实被读了），但不产生 canary 文件。

## 结果

见 `exp/result.json`（两次独立容器运行字节一致）与 `exp/SHA256SUMS`。

## 验证边界 —— 没有证明的东西

- **投递是假设的**。受害者必须自己拿到并解压这个包。A1111 核心没有「下载任意
  checkpoint 包」的端点，所以这**不是**对默认实例的未授权网络 RCE。
- **这个包是三个文件，不是一个**。`hubconf.py` 是载荷载体。契约允许「模型目录」
  作为起点，而在 Hugging Face 仓库里把 `.py` 和权重放在一起也是常态；但要做成
  单文件版本，需要另一个能吞 `**kwargs` 的 gadget。
- 使用了 `--skip-load-model-at-start`，使整轮运行中**唯一**一次 checkpoint 加载
  就是受害者 API 调用引发的那次。不加这个参数，同样的事会在启动时发生；
  这个开关只是消除「canary 是什么时候落的」这一歧义。
- canary 是一次文件写。无持久化、无网络、无凭据访问。
- **上游可用性**：A1111 v1.10.1 为拿 `ldm` 包而 clone 的
  `Stability-AI/stablediffusion`，截至 2026-09-20 返回 HTTP 404，因此今天已经无法
  从零 `launch.py` 引导这个发行版。钉死的那个 revision 是从 Software Heritage
  取回并内置进镜像的。这不影响污点链，但意味着镜像无法仅凭上游复现。
