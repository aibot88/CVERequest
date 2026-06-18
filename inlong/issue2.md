---
title: "inlong issue2: C-4: ID-based consume get/update/delete without ownership check"
description: "inlong has a missing authorization vulnerability: C-4: ID-based consume get/update/delete without ownership check. Unauthorized read, modification, or deletion of consume records and their authorization-related fields such as creator, in-charges, group/topic binding, status, and related MQ configuration"
tags:
  - inlong
  - 漏洞报告
  - 越权
  - 访问控制
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

inlong has a missing authorization vulnerability: C-4: ID-based consume get/update/delete without ownership check. Unauthorized read, modification, or deletion of consume records and their authorization-related fields such as creator, in-charges, group/topic binding, status, and related MQ configuration

- Attack precondition: The attacker is authenticated in the same deployment and can guess or obtain an `inlong_consume.id` belonging to another user or group
- Security impact: Unauthorized read, modification, or deletion of consume records and their authorization-related fields such as creator, in-charges, group/topic binding, status, and related MQ configuration

### 1.2 Exploit path

Call `/api/consume/get/{id}`, `/api/consume/update`, or `/api/consume/delete/{id}` with another user's consume id

### 1.3 Key code evidence

1. `inlong-manager/manager-web/src/main/java/org/apache/inlong/manager/web/controller/InlongConsumeController.java`

Evidence location: inlong-manager/manager-web/src/main/java/org/apache/inlong/manager/web/controller/InlongConsumeController.java
2. `inlong-manager/manager-web/src/main/java/org/apache/inlong/manager/web/controller/openapi/OpenInlongConsumeController.java`

Evidence location: inlong-manager/manager-web/src/main/java/org/apache/inlong/manager/web/controller/openapi/OpenInlongConsumeController.java
3. `inlong-manager/manager-service/src/main/java/org/apache/inlong/manager/service/consume/InlongConsumeServiceImpl.java`

Evidence location: inlong-manager/manager-service/src/main/java/org/apache/inlong/manager/service/consume/InlongConsumeServiceImpl.java

## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

Replace direct `selectById` authorization paths with scoped lookup or an explicit `checkUser` over consume `creator/inCharges`, related group `inCharges`, and tenant admin/global admin roles

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/inlong/issue2.html
