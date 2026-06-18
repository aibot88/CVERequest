---
title: "surveyking issue3: Workflow Configuration Read Authorization Bypass"
description: "surveyking has a missing authorization vulnerability: Workflow Configuration Read Authorization Bypass. 泄露工作流配置，包括审批身份 `identity`、字段权限 `fieldPermission` 和 `bpmnXml`。"
tags:
  - surveyking
  - 漏洞报告
  - 越权
  - 访问控制
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

surveyking has a missing authorization vulnerability: Workflow Configuration Read Authorization Bypass. 泄露工作流配置，包括审批身份 `identity`、字段权限 `fieldPermission` 和 `bpmnXml`。

- Attack precondition: 任意已登录用户，知道目标 `projectId`。
- Security impact: 泄露工作流配置，包括审批身份 `identity`、字段权限 `fieldPermission` 和 `bpmnXml`。

### 1.2 Exploit path

调用 `GET /api/workflow/getFlow?projectId=...`。

### 1.3 Key code evidence

1. `FlowApi.java`

Evidence location: FlowApi.java#L23
2. `FlowServiceImpl.java`

Evidence location: FlowServiceImpl.java#L198
3. `FlowEntryView.java`

Evidence location: FlowEntryView.java
4. `FlowEntryNodeView.java`

Evidence location: FlowEntryNodeView.java

## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

对 `getFlow` 加项目读权限校验；非管理者不要返回完整 workflow 授权配置。

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/surveyking/issue3.html
