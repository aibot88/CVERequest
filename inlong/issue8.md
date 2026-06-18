---
title: "inlong issue8: D-6: Region and broker-region relation mutation without authorization"
description: "inlong has a missing authorization vulnerability in /v1/region. Unauthorized creation/deletion of regions and reassignment/reset of broker `regionId` membership"
tags:
  - inlong
  - vulnerability-report
  - authorization
  - access-control
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

inlong has a missing authorization vulnerability in /v1/region. Unauthorized creation/deletion of regions and reassignment/reset of broker `regionId` membership

- Attack precondition: The attacker can access `/v1/region`
- Affected endpoint: `/v1/region`
- Affected authorization property: `method=add, method=modify, method=delete, clusterId, regionId`
- Security impact: Unauthorized creation/deletion of regions and reassignment/reset of broker `regionId` membership

### 1.2 Exploit path

Call `method=add`, `method=modify`, or `method=delete` with target `clusterId`, `regionId`, and broker ids

### 1.3 Key code evidence

1. `inlong-tubemq/tubemq-manager/src/main/java/org/apache/inlong/tubemq/manager/controller/region/RegionController.java`

Evidence location: inlong-tubemq/tubemq-manager/src/main/java/org/apache/inlong/tubemq/manager/controller/region/RegionController.java
2. `inlong-tubemq/tubemq-manager/src/main/java/org/apache/inlong/tubemq/manager/service/RegionServiceImpl.java`

Evidence location: inlong-tubemq/tubemq-manager/src/main/java/org/apache/inlong/tubemq/manager/service/RegionServiceImpl.java

## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

Require cluster-admin authorization before changing region or broker-region membership

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/inlong/issue8.html
