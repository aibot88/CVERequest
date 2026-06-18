---
title: "onedev issue3: Detector MCP/TOD issue time tracking 读取泄露"
description: "onedev has a missing authorization vulnerability: Detector MCP/TOD issue time tracking 读取泄露. 未确认到当前版本存在该读取泄露。"
tags:
  - onedev
  - 漏洞报告
  - 越权
  - 访问控制
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

onedev has a missing authorization vulnerability: Detector MCP/TOD issue time tracking 读取泄露. 未确认到当前版本存在该读取泄露。

- Attack precondition: 当前代码中没有报告所称的 `McpHelperResource / /mcp-helper` 路径；对应实现是 `/tod`。
- Security impact: 未确认到当前版本存在该读取泄露。

### 1.2 Exploit path

detector 声称 `IssueHelper.getSummary` 未移除 time fields，但当前代码已经移除。

### 1.3 Key code evidence

1. `TodResource.java`

Evidence location: https://code.onedev.io/onedev/server/TodResource.java#L124
2. `server-core/src/main/java/io/onedev/server/ai/IssueHelper.java`

Evidence location: https://code.onedev.io/onedev/server/server-core/src/main/java/io/onedev/server/ai/IssueHelper.java#L43

```text
   40          summary.put("reference", issue.getReference().toString(currentProject));
   41          summary.remove("submitterId");
   42          summary.put("submitter", issue.getSubmitter().getName());
   43          summary.put("Project", issue.getProject().getPath());
   44          summary.remove("lastActivity");
   45          for (var it = summary.entrySet().iterator(); it.hasNext();) {
   46              var entry = it.next();
```


## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

无需针对当前代码修复；可补回归测试防止 helper 重新暴露 time fields。

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/onedev/issue3.html
