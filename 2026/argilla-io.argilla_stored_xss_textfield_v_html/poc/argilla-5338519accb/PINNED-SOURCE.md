# Pinned Source — argilla-io/argilla @ 5338519accb13ae422f8bf9c0642651c249c49af

- Commit: `5338519accb13ae422f8bf9c0642651c249c49af`（`develop` 分支头部，2025-08-05，"Update README.md"）
- 获取方式：codeload tarball `https://codeload.github.com/argilla-io/argilla/tar.gz/5338519accb13ae422f8bf9c0642651c249c49af`
- tarball sha256：见 `../poc/tarball-sha256.txt`（`7c765604cc095f7b07b9f0f0f8314603c88cac112b897bcb95eb397c31de99f2`）

## 本目录包含的核对文件（相对仓库根）

| 文件 | 作用 |
|---|---|
| `argilla-frontend/components/features/annotation/container/fields/text-field/TextField.vue` | **漏洞 sink**：模板 19-23 行三分支渲染，第 22 行 `v-html`（已核对与用户描述一致） |
| `argilla-frontend/components/features/annotation/container/fields/text-field/useTextFieldViewModel.ts` | 证明 `fieldText` 原样透传（仅搜索高亮逻辑） |
| `argilla-frontend/components/features/annotation/container/fields/sandbox/Sandbox.vue` | 成对 HTML 分支的渲染器（无 `sandbox` 属性的 srcdoc iframe） |
| `argilla-frontend/components/base/base-render-markdown/MarkdownRenderer.vue` | Markdown 分支渲染器 |
| `argilla-server/src/argilla_server/api/handlers/v1/datasets/records_bulk.py` | `POST /datasets/{id}/records/bulk` 端点（`DatasetPolicy.create_records` 授权） |
| `argilla-server/src/argilla_server/api/policies/v1/dataset_policy.py` | 记录创建权限：owner 或 workspace admin |

## 关键核对结论

1. **漏洞行核对**：钉定 commit 的 `TextField.vue` 19-23 行与报告描述逐行一致；
   `isHTML` 仅匹配成对标签 `/<([A-Za-z][A-Za-z0-9]*)\b[^>]*>(.*?)<\/\1>/`，`<img src=x onerror=...>` 不匹配 → 落入 `v-else` 的 `v-html`。
2. **与 release 一致**：该文件与 tag `v2.8.0`（commit `78cb5183f`）下的同名文件 **`diff` 逐字节一致（IDENTICAL）**，因此复现环境（PyPI `argilla-server==2.8.0`，内含 v2.8.0 前端构建）与钉定 commit 的缺陷代码完全相同。
3. **HEAD 状态**：2026-10-06 探测，`main` HEAD 与 `develop` HEAD 均仍包含同一 `v-html` 分支。
