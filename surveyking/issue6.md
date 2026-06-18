---
title: "surveyking issue6: Repo Template Scope Authorization Bypass"
description: "surveyking has a missing authorization vulnerability: Repo Template Scope Authorization Bypass. 向他人题库写入题目、删除模板绑定、读取/导出私有题库内容。"
tags:
  - surveyking
  - 漏洞报告
  - 越权
  - 访问控制
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

surveyking has a missing authorization vulnerability: Repo Template Scope Authorization Bypass. 向他人题库写入题目、删除模板绑定、读取/导出私有题库内容。

- Attack precondition: 任意已登录用户可调用未加权限的 repo 接口；或拥有 `repo:create` 但非目标 repo owner。
- Security impact: 向他人题库写入题目、删除模板绑定、读取/导出私有题库内容。

### 1.2 Exploit path

调用 `/api/repo/import`、`/api/repo/unbind`、`/api/repo/pick`、`/api/repo/export` 或 `batchCreate`，指定他人 `repoId/id`。

### 1.3 Key code evidence

1. `RepoApi.java`

Evidence location: RepoApi.java#L79
2. `RepoApi.java`

Evidence location: RepoApi.java#L155
3. `RepoServiceImpl.java`

Evidence location: RepoServiceImpl.java#L118
4. `RepoServiceImpl.java`

Evidence location: RepoServiceImpl.java#L177
5. `RepoServiceImpl.java`

Evidence location: RepoServiceImpl.java#L190
6. `RepoServiceImpl.java`

Evidence location: RepoServiceImpl.java#L361
7. `RepoPartnerServiceImpl.java`

Evidence location: RepoPartnerServiceImpl.java#L40

## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

所有按 `repoId` 操作模板/导出的接口统一调用 repo owner/partner 权限检查。

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/surveyking/issue6.html
