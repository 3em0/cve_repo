# CVE Research Reports

本仓库用于整理开源项目安全审计、漏洞复现和 CVE 相关研究报告。

## 目录结构

报告按首次记录或维护年份归档，年份目录下保留项目目录及对应的截图资源：

```text
2025/
├── kanboard/
├── phpwcms/
├── preshop/
├── zentaopms/
└── dists/

2026/
├── DjangoBlog/
├── dj-rest-auth/
├── Langchain-Chatchat/
├── horcorp/
├── skypilot/
├── dists/
└── *.md
```

## 报告索引

### 2025

- `kanboard`：Phar 漏洞研究
- `phpwcms`：文件处理和 Phar 相关漏洞研究
- `preshop`：`CVE-2025-25691`、`CVE-2025-25692`
- `zentaopms`：Phar 绕过漏洞研究

### 2026

- `DjangoBlog`：13 个安全问题及汇总报告
- `dj-rest-auth`：JWT、CSRF、权限和限流相关问题
- `Langchain-Chatchat`：文件标识、文件覆盖和访问控制问题
- `horcorp`：文件上传功能研究
- `skypilot`：用户 ID 哈希碰撞导致的账户接管
- `a1111.extra_networks_filename_xss`：恶意 LoRA 文件名导致存储型 XSS（含完整 Docker 复现环境）
- `a1111.safetensors_yaml_target`：恶意 YAML sidecar 在模型加载阶段触发进程内代码执行（含完整 Docker 复现环境）
- `a1111.sshs_hash_xss_staged_rce`：LoRA 元数据 XSS 链接扩展安装与重启后代码执行（添加日期：2026-09-20，含完整 Docker 复现环境）
- 独立报告：Cookiecutter Django、`ekzhu/datasketch`

## 说明

- `dists/` 保存报告中引用的截图和演示材料。
- 报告中的相对图片链接以各年份目录为基准，移动文件时请保持项目目录结构。
- 报告仅用于授权环境中的安全研究、复现与修复验证。
