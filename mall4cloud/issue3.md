---
title: "mall4cloud issue3: Shop File and File Group Operations Miss `shop_id` Ownership Checks"
description: "mall4cloud has a missing authorization vulnerability: Shop File and File Group Operations Miss `shop_id` Ownership Checks. Cross-shop modification, regrouping, or deletion of uploaded assets and file groups"
tags:
  - mall4cloud
  - 漏洞报告
  - 越权
  - 访问控制
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

mall4cloud has a missing authorization vulnerability: Shop File and File Group Operations Miss `shop_id` Ownership Checks. Cross-shop modification, regrouping, or deletion of uploaded assets and file groups

- Affected authorization property: ``attach_file.shop_id`, `attach_file_group.shop_id``
- Security impact: Cross-shop modification, regrouping, or deletion of uploaded assets and file groups

### 1.3 Key code evidence

1. `AttachFileMapper.xml`

Evidence location: AttachFileMapper.xml
2. `AttachFileGroupMapper.xml`

Evidence location: AttachFileGroupMapper.xml

## 2. Existing checks and why they fail

- Create/list are tenant-scoped, but later object-level operations are not.
- There is no service-level ownership assertion before update/delete.
- There is no SQL `WHERE shop_id = currentTenant` condition on the mutation sinks.

## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/mall4cloud/issue3.html
