---
title: "platform issue3: Plan Definition Resource Authorization Can Be Modified Without Permission"
description: "platform has a missing authorization vulnerability in POST /plan-definitions, PUT /plan-definitions/{id}, PUT /plan-definitions/{id}/permissions, itemIdList/resIdList. Alters which platform resources a subscribed tenant receives"
tags:
  - platform
  - vulnerability-report
  - authorization
  - access-control
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

platform has a missing authorization vulnerability in POST /plan-definitions, PUT /plan-definitions/{id}, PUT /plan-definitions/{id}/permissions, itemIdList/resIdList. Alters which platform resources a subscribed tenant receives

- Attack precondition: The attacker is authenticated and knows resource IDs and a plan ID, or can create/modify a plan
- Affected endpoint: `POST /plan-definitions, PUT /plan-definitions/{id}, PUT /plan-definitions/{id}/permissions, itemIdList/resIdList`
- Affected authorization property: `@SaCheckPermission, PlanDefinitionRes, resIdList`
- Security impact: Alters which platform resources a subscribed tenant receives

### 1.2 Exploit path

Use `POST /plan-definitions`, `PUT /plan-definitions/{id}`, or `PUT /plan-definitions/{id}/permissions` to write `itemIdList/resIdList`

### 1.3 Key code evidence

1. `PlanDefinitionController.java`

Evidence location: https://gitee.com/fuyang_lipengjun/platform/blob/master/PlanDefinitionController.java#L75
2. `ProductDefinitionServiceImpl.java`

Evidence location: https://gitee.com/fuyang_lipengjun/platform/blob/master/ProductDefinitionServiceImpl.java#L94
3. `PlanDefResMapper.xml`

Evidence location: https://gitee.com/fuyang_lipengjun/platform/blob/master/PlanDefResMapper.xml#L6
4. `ResourceServiceImpl.java`

Evidence location: https://gitee.com/fuyang_lipengjun/platform/blob/master/ResourceServiceImpl.java#L74

## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

Add plan-definition add/edit/assign permissions and validate that `resIdList` is within the actor's grantable platform-resource set

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/platform/issue3.html
