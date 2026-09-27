# VulDB Vulnerability Submission

提交地址:https://vuldb.com/en/vuln/add
提交政策:https://vuldb.com/?kb.submission ｜ 审核说明:https://vuldb.com/?kb.moderation

> 提交后**无法编辑**,提交前逐字段核对。`desc` 为英文;`link` 需公开可访问 URL,advisory 发布后回填。

**Vendor**
```
kitops-ml
```

**Product**
```
KitOps
```

**Version**
```
up to v1.15.0
```

**Class**
```
OS Command Injection
```

**Description**
```
A vulnerability was found in KitOps up to v1.15.0 and classified as high 7.8.
Affected is the llamafile dev harness component (pkg/lib/harness/llm-harness.go)
of the `kit dev start` command. The manipulation of the argument modelPath
(the resolved model file path inside a ModelKit) leads to os command injection.
The attack is local: the crafted ModelKit must be on local disk and the victim
must run `kit dev start` against it, which is the documented way to try a
shared model. User interaction is required.

Technical Details
- Affected file/function: pkg/lib/harness/llm-harness.go / harness Start
  (exec.Command("sh", "-c", fmt.Sprintf("./llamafile --server --model %s ...",
  modelPath, ...)) at line 102)
- Vulnerable parameter: resolved model file path (Kitfile model.path plus the
  directory/file names beneath it); payload carried entirely by file names,
  no executable content
- Attack vector: Local (the POSIX branch; the Windows branch at line 90 builds
  an argv and is not affected)
- Privileges required: None
- Trigger condition: the victim runs `kit dev start` on a ModelKit whose
  directory/file names contain shell metacharacters; the existing
  filesystem.VerifySubpath containment check (pkg/cmd/dev/dev.go:77) passes
  because the path never leaves the context directory, and /bin/sh
  re-tokenises the path into multiple commands

Impact
- Confidentiality: High (arbitrary command execution with the victim user's
  credentials, registry tokens and source trees in reach)
- Integrity: High (arbitrary command execution; verified by an injected
  command writing a marker file while the product reports success)
- Availability: High (arbitrary command execution)

CVSS v3.1
Score: 7.8 (High)
Vector: CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H

Timeline
- Discovered: 2026-09-20
- Vendor notified: [pending]
- Patch released: [pending]
- Public disclosure: [pending — coordinated disclosure with the maintainer]

Countermeasure
Remove the shell at pkg/lib/harness/llm-harness.go:102 and build an argv
directly (the Windows branch of the same function already does this);
additionally reject resolved model paths containing shell metacharacters.
```

**Advisory / Exploit**
```
[待发布:GitHub 私密 advisory 发布后回填其公开 URL]
```

**Request CVE**
```
[ ] No  /  [x] Yes
```
