---
title: "surveyking issue4: Workflow Approval Field Permission Bypass"
description: "surveyking has a missing authorization vulnerability: Workflow Approval Field Permission Bypass. 绕过字段级编辑权限，修改答卷中本不允许当前审批节点修改的字段。"
tags:
  - surveyking
  - 漏洞报告
  - 越权
  - 访问控制
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

surveyking has a missing authorization vulnerability: Workflow Approval Field Permission Bypass. 绕过字段级编辑权限，修改答卷中本不允许当前审批节点修改的字段。

- Attack precondition: 用户能触发有效流程任务；至少知道有效 `taskId/processInstanceId/activityId/answerId`。
- Security impact: 绕过字段级编辑权限，修改答卷中本不允许当前审批节点修改的字段。

### 1.2 Exploit path

调用 `POST /api/workflow/approvalTask`，在 `request.answer` 中携带当前节点非 editable 的 questionId。

### 1.3 Key code evidence

1. `FlowApi.java`

Evidence location: FlowApi.java#L75
2. `AbstractTaskHandler.java`

Evidence location: AbstractTaskHandler.java#L118
3. `FieldPermissionType.java`

Evidence location: FieldPermissionType.java
4. `AnswerServiceImpl.java`

Evidence location: AnswerServiceImpl.java#L230

## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

在 `updateTaskAnswer` 中只接受 `fieldPermission == editable` 的字段，并校验当前用户是任务 assignee/candidate。

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/surveyking/issue4.html
