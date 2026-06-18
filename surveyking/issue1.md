---
title: "surveyking issue1: Project Partner Management Authorization Bypass"
description: "surveyking has a missing authorization vulnerability: Project Partner Management Authorization Bypass. 普通项目参与者可提升自己/他人为 OWNER/COLLABORATOR，或破坏项目成员绑定。"
tags:
  - surveyking
  - 漏洞报告
  - 越权
  - 访问控制
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

surveyking has a missing authorization vulnerability: Project Partner Management Authorization Bypass. 普通项目参与者可提升自己/他人为 OWNER/COLLABORATOR，或破坏项目成员绑定。

- Attack precondition: 已登录系统用户在目标项目存在任意 `t_project_partner.user_id` 记录，例如 type=3 系统答卷人。
- Security impact: 普通项目参与者可提升自己/他人为 OWNER/COLLABORATOR，或破坏项目成员绑定。

### 1.2 Exploit path

调用 `/api/project/partner/create`，传入 `type=1` 或 `type=2` 和任意 `userIds`；或调用 `/api/project/partner/delete` 删除成员关系。

### 1.3 Key code evidence

1. `ProjectApi.java`

Evidence location: ProjectApi.java#L117
2. `DataPermAspect.java`

Evidence location: DataPermAspect.java#L53
3. `ProjectPartnerMapper.java`

Evidence location: ProjectPartnerMapper.java#L14
4. `ProjectPartnerServiceImpl.java`

Evidence location: ProjectPartnerServiceImpl.java#L85
5. `ProjectPartnerServiceImpl.java`

Evidence location: ProjectPartnerServiceImpl.java#L128

## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

成员管理接口要求 OWNER 或专门管理权限；禁止非 OWNER 写入 type=1/2。

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/surveyking/issue1.html
