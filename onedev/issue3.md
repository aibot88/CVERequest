---
title: "onedev issue3: Detector MCP/TOD issue time tracking"
description: "onedev has a missing authorization vulnerability in McpHelperResource / /mcp-helper, /tod, /tod/query-issues, /tod/get-issue. An authenticated attacker can read authorization-sensitive data that should be restricted."
tags:
  - onedev
  - vulnerability-report
  - authorization
  - access-control
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

onedev has a missing authorization vulnerability in McpHelperResource / /mcp-helper, /tod, /tod/query-issues, /tod/get-issue. An authenticated attacker can read authorization-sensitive data that should be restricted.

- Attack precondition: Any authenticated user
- Affected endpoint: `McpHelperResource / /mcp-helper, /tod, /tod/query-issues, /tod/get-issue`
- Affected authorization property: `IssueHelper.getSummary, totalEstimatedTime, totalSpentTime, ownEstimatedTime, ownSpentTime, progress`
- Security impact: An authenticated attacker can read authorization-sensitive data that should be restricted.

### 1.2 Exploit path

The attacker sends crafted requests to McpHelperResource / /mcp-helper, /tod, /tod/query-issues, /tod/get-issue with target identifiers or authorization-sensitive fields that should be rejected.

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

Enforce server-side authorization for McpHelperResource / /mcp-helper, /tod, /tod/query-issues, /tod/get-issue before reading or writing target objects, roles, permissions, ownership, tenant, organization, or grant-bound state.

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/onedev/issue3.html
