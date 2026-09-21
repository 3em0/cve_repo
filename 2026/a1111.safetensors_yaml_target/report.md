# AUTOMATIC1111 Stable Diffusion WebUI：恶意 YAML 配置触发模型加载阶段代码执行

## 漏洞概览

| 项目 | 内容 |
|---|---|
| 受影响组件 | AUTOMATIC1111/stable-diffusion-webui |
| 验证版本 | v1.10.1，提交 `82a973c04367123ae98bd9abdf80d9eda9b910e2` |
| 漏洞类型 | 不可信模型配置导致进程内代码执行 |
| CWE | CWE-94：Improper Control of Generation of Code |
| 严重性 | 高（需要攻击者先将模型包投递并解压到模型目录） |
| 影响平台 | 运行 A1111 的 Linux/Unix 环境 |
| 验证结果 | 产品真实 API 选中恶意 checkpoint 后写入 canary 文件 |
| 验证状态 | 已完成端到端验证，负控、正控和两次独立运行结果已保存 |

## 漏洞描述

AUTOMATIC1111 在加载 checkpoint 时，会优先读取与模型同基名的 YAML sidecar。该 YAML 中的 `model.target` 最初被当作配置数据读取，但随后被传入 `instantiate_from_config`，最终由 `get_obj_from_str` 作为 Python 模块和对象路径导入。

攻击者只需提供一个包含 `model.safetensors`、同基名 `model.yaml` 和 `hubconf.py` 的模型目录。受害者在 WebUI 中选择该 checkpoint 后，A1111 会通过自身的模型加载路径调用 `torch.hub.load(..., source="local")`，执行模型目录中的 `hubconf.py`，代码以 WebUI 进程身份运行。

## 受影响代码路径

1. `modules/sd_models.py:332-347` 使用真实 safetensors 解析器读取 checkpoint。
2. `modules/sd_models_config.py:117-136` 因同基名关系优先采用 `<basename>.yaml`，未验证权重与配置的可信关联。
3. `modules/sd_models.py:809` 通过 `OmegaConf.load()` 读取 YAML。
4. `modules/sd_models.py:599-602` 的 `repair_config()` 注入 `model.params.use_ema=False`。
5. `modules/sd_models.py:766-775` 调用 `instantiate_from_config`，将 `target` 解析为构造器。
6. `modules/sd_models.py:778-783` 使用 `importlib.import_module()` 和 `getattr()` 将配置字符串转为可执行对象。
7. `torch.hub._load_local` / `_import_module` 加载并执行模型目录中的 `hubconf.py`。

这里的关键跨越是 DATA→CONTROL：配置中的字符串在用途改变后没有重新进行安全校验，最终成为模块名和可调用对象。

## 利用条件与限制

- 攻击者必须能让受害者获得并解压模型包到 `models/Stable-diffusion/` 等可扫描目录。
- 受害者需要在 WebUI 中选中恶意 checkpoint；本次复现通过公开 API 完成选择。
- 这不是默认实例上的未授权网络 RCE。A1111 核心没有下载任意 checkpoint 包的端点，模型投递是本漏洞的前置条件。
- 本次使用三个文件：`model.safetensors`、同基名 `model.yaml` 和 `hubconf.py`。权重文件本身由官方 safetensors writer 正常生成。
- `repair_config()` 会额外注入 `use_ema=False`，因此任意 gadget 必须能够接受额外关键字参数；简单的 `subprocess.run` PoC 在真实产品路径中会失败。

## 复现步骤

### 环境

- 产品镜像：`mbe2e/prod:a1111-82a973c0`
- 验证镜像：`mbe2e/v/a1111.safetensors_yaml_target:r1`
- 运行网络：Docker `--network none`
- 产品提交：`82a973c04367123ae98bd9abdf80d9eda9b910e2`

### 操作

1. 进入 `reproduction/exp/`。
2. 在拥有 Docker daemon 的验证主机上执行 `./run.sh`。
3. 脚本构建模型工件和验证镜像，然后启动两次隔离容器。
4. 测试先通过 `GET /sdapi/v1/sd-models` 列出模型，再通过 `POST /sdapi/v1/options` 选择负控和正控 checkpoint。
5. 检查 `reproduction/exp/result.json`、`reproduction/exp/SHA256SUMS` 及 `exp/logs/run1/`、`exp/logs/run2/`。

### 预期结果

- 负控 `mbe2e_neg/model.safetensors`：sidecar 被读取，但 `/out/pwned_by_a1111_yaml_target` 不存在。
- 正控 `mbe2e_pack/model.safetensors`：sidecar 被读取，canary 文件生成。
- 两次运行的结果字节一致。

## 验证结果

来自已保存的 `result.json`：

```text
verdict: E2_product_e2e
negative canary: absent
positive canary: present
positive canary content: MBE2E-CANARY-a1111-yaml-target-v1
select_negative: HTTP 200
select_positive: HTTP 200
negative_sidecar_was_read: true
positive_sidecar_was_read: true
```

## 影响边界

本验证证明攻击者代码可在真实 A1111 模型加载流程中以 WebUI 进程身份执行，并能写入文件。复现未证明持久化、网络访问、凭据窃取或操作系统级权限提升。使用 `--skip-load-model-at-start` 只是为了确保唯一一次 checkpoint 加载由受害者 API 选择触发；不使用该选项时，启动阶段也可能触发同样的路径。

验证镜像内置了产品依赖和固定源码快照；由于上游依赖在当前时间已不可直接从零引导，这不改变已验证的污点链和复现证据。

## 修复建议

- 不要将模型目录中的 YAML sidecar 视为可信配置；对配置文件来源、权限和模型关联关系进行验证。
- 对 `model.target` 等可影响导入或实例化的字段实施严格 allowlist，禁止任意模块路径和任意 callable。
- 避免从不可信模型目录加载或执行 `hubconf.py`、Python 模块及其他代码文件。
- 在模型加载前校验 safetensors、YAML 和附属 Python 文件的完整性，优先使用签名或可信仓库元数据。
- 增加真实产品路径的回归测试，确保覆盖 `repair_config()`、`instantiate_from_config()` 和 `torch.hub` 的完整调用链，而不仅是孤立函数测试。

## 复现材料

完整复现环境原样保存在 [`reproduction/`](reproduction/)：

- Dockerfile、入口脚本和固定测试工件
- `model.safetensors`、`model.yaml`、`hubconf.py` 的正负控样本
- `exp/run.sh`、驱动脚本、运行日志和容器输出
- 两次运行的结果、SHA-256 校验和及原始中英文验证报告

