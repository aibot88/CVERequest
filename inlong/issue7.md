---
title: "inlong issue7: D-5: Group auth/filter/blacklist mutation via manager-filled master token"
description: "inlong has a missing authorization vulnerability: D-5: Group auth/filter/blacklist mutation via manager-filled master token. Unauthorized modification of consumer group authorization, filter conditions, flow-control rules, rebalancing, and blacklist entries"
tags:
  - inlong
  - 漏洞报告
  - 越权
  - 访问控制
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

inlong has a missing authorization vulnerability: D-5: Group auth/filter/blacklist mutation via manager-filled master token. Unauthorized modification of consumer group authorization, filter conditions, flow-control rules, rebalancing, and blacklist entries

- Attack precondition: The attacker can access `/v1/group` or `/v1/group/blackGroup`
- Security impact: Unauthorized modification of consumer group authorization, filter conditions, flow-control rules, rebalancing, and blacklist entries

### 1.2 Exploit path

Submit group add/delete/batchDelete/filterCondition/flowControl/rebalance or blackGroup add/delete requests with a chosen `clusterId`

### 1.3 Key code evidence

1. `inlong-tubemq/tubemq-manager/src/main/java/org/apache/inlong/tubemq/manager/controller/group/GroupController.java`

Evidence location: inlong-tubemq/tubemq-manager/src/main/java/org/apache/inlong/tubemq/manager/controller/group/GroupController.java
2. `inlong-tubemq/tubemq-manager/src/main/java/org/apache/inlong/tubemq/manager/service/MasterServiceImpl.java`

Evidence location: inlong-tubemq/tubemq-manager/src/main/java/org/apache/inlong/tubemq/manager/service/MasterServiceImpl.java

## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

Add authenticated per-cluster/per-group authorization before forwarding group control requests

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/inlong/issue7.html
