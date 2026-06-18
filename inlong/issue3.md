---
title: "inlong issue3: D-1: `/v1/cluster` leaks TubeMQ master token"
description: "inlong has a missing authorization vulnerability: D-1: `/v1/cluster` leaks TubeMQ master token. Disclosure of master `confModAuthToken`, which protects TubeMQ master modification APIs"
tags:
  - inlong
  - 漏洞报告
  - 越权
  - 访问控制
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

inlong has a missing authorization vulnerability: D-1: `/v1/cluster` leaks TubeMQ master token. Disclosure of master `confModAuthToken`, which protects TubeMQ master modification APIs

- Attack precondition: The attacker can access TubeMQ Manager HTTP `/v1/cluster`
- Security impact: Disclosure of master `confModAuthToken`, which protects TubeMQ master modification APIs

### 1.2 Exploit path

Send `GET /v1/cluster`; response includes `ClusterVo.masterEntries`, each containing `MasterEntry.token`

### 1.3 Key code evidence

1. `inlong-tubemq/tubemq-manager/src/main/java/org/apache/inlong/tubemq/manager/controller/cluster/ClusterController.java`

Evidence location: inlong-tubemq/tubemq-manager/src/main/java/org/apache/inlong/tubemq/manager/controller/cluster/ClusterController.java
2. `inlong-tubemq/tubemq-manager/src/main/java/org/apache/inlong/tubemq/manager/utils/ConvertUtils.java`

Evidence location: inlong-tubemq/tubemq-manager/src/main/java/org/apache/inlong/tubemq/manager/utils/ConvertUtils.java
3. `inlong-tubemq/tubemq-manager/src/main/java/org/apache/inlong/tubemq/manager/entry/MasterEntry.java`

Evidence location: inlong-tubemq/tubemq-manager/src/main/java/org/apache/inlong/tubemq/manager/entry/MasterEntry.java

## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

Never serialize master token in cluster responses; use a sanitized DTO and add authentication/authorization to `/v1/*`

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/inlong/issue3.html
