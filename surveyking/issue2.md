---
title: "surveyking issue2: Workflow Save/Deploy Authorization Bypass"
description: "surveyking has a missing authorization vulnerability: Workflow Save/Deploy Authorization Bypass. 篡改项目工作流审批人、字段可见/可编辑权限、流程定义，影响后续发起与审批授权。"
tags:
  - surveyking
  - 漏洞报告
  - 越权
  - 访问控制
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

surveyking has a missing authorization vulnerability: Workflow Save/Deploy Authorization Bypass. 篡改项目工作流审批人、字段可见/可编辑权限、流程定义，影响后续发起与审批授权。

- Attack precondition: 任意已登录用户，知道或猜到目标 `projectId`。
- Security impact: 篡改项目工作流审批人、字段可见/可编辑权限、流程定义，影响后续发起与审批授权。

### 1.2 Exploit path

调用 `POST /api/workflow/saveFlow` 写入目标项目的 `bpmnXml/nodes.identity/nodes.fieldPermission`，再调用 `POST /api/workflow/deploy` 发布。

### 1.3 Key code evidence

1. `bpmnXml/nodes.identity/nodes.fieldPermission`

Evidence location: bpmnXml/nodes.identity/nodes.fieldPermission
2. `FlowApi.java`

Evidence location: FlowApi.java#L28
3. `FlowServiceImpl.java`

Evidence location: FlowServiceImpl.java#L126
4. `FlowServiceImpl.java`

Evidence location: FlowServiceImpl.java#L144
5. `FlowServiceImpl.java`

Evidence location: FlowServiceImpl.java#L467
6. `WebSecurityConfig.java`

Evidence location: WebSecurityConfig.java

## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

对 `saveFlow/deploy` 增加项目 owner/协作者管理权限校验，并限制可写 workflow 字段。

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/surveyking/issue2.html
