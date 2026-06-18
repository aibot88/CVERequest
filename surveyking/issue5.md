---
title: "surveyking issue5: Answer Project Scope Authorization Bypass"
description: "surveyking has a missing authorization vulnerability: Answer Project Scope Authorization Bypass. 跨项目读取、导出、修改、删除答卷数据。"
tags:
  - surveyking
  - 漏洞报告
  - 越权
  - 访问控制
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

surveyking has a missing authorization vulnerability: Answer Project Scope Authorization Bypass. 跨项目读取、导出、修改、删除答卷数据。

- Attack precondition: 拥有 `answer:*` 对应功能权限的用户；默认/配置角色可能授予这些功能权限。
- Security impact: 跨项目读取、导出、修改、删除答卷数据。

### 1.2 Exploit path

调用 `/api/answer/list|get|update|delete|download`，传入他人项目 `projectId` 或答案 `id`。

### 1.3 Key code evidence

1. `AnswerApi.java`

Evidence location: AnswerApi.java#L34
2. `AnswerServiceImpl.java`

Evidence location: AnswerServiceImpl.java#L70
3. `AnswerServiceImpl.java`

Evidence location: AnswerServiceImpl.java#L163
4. `AnswerServiceImpl.java`

Evidence location: AnswerServiceImpl.java#L230
5. `AnswerServiceImpl.java`

Evidence location: AnswerServiceImpl.java#L334

## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

所有后台 answer 接口按 `projectId` 做 `@EnableDataPerm`；按 `id` 操作前先解析 `answer.projectId` 再校验。

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/surveyking/issue5.html
