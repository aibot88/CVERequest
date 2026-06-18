---
title: "inlong issue9: D-7: Async topic task creates/configures topics via server-side master token"
description: "inlong has a missing authorization vulnerability in /v1/task?method=addTopicTask, /v1/cluster, /v1/node/master. Unauthorized asynchronous topic creation/configuration in the target TubeMQ cluster"
tags:
  - inlong
  - vulnerability-report
  - authorization
  - access-control
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

inlong has a missing authorization vulnerability in /v1/task?method=addTopicTask, /v1/cluster, /v1/node/master. Unauthorized asynchronous topic creation/configuration in the target TubeMQ cluster

- Attack precondition: The attacker can access `/v1/task?method=addTopicTask`; scheduler is enabled; the target cluster has configurable brokers
- Affected endpoint: `/v1/task?method=addTopicTask, /v1/cluster, /v1/node/master`
- Affected authorization property: `BatchAddTopicTaskReq, clusterId, TopicTaskEntry, req.legal(), MasterEntry.token, in_charges`
- Security impact: Unauthorized asynchronous topic creation/configuration in the target TubeMQ cluster

### 1.2 Exploit path

Submit a `BatchAddTopicTaskReq` with target `clusterId` and topic names. The task is saved, then scheduled execution uses the stored master token to configure topics

### 1.3 Key code evidence

1. `inlong-tubemq/tubemq-manager/src/main/java/org/apache/inlong/tubemq/manager/controller/task/TaskController.java`

Evidence location: inlong-tubemq/tubemq-manager/src/main/java/org/apache/inlong/tubemq/manager/controller/task/TaskController.java
2. `inlong-tubemq/tubemq-manager/src/main/java/org/apache/inlong/tubemq/manager/service/TaskServiceImpl.java`

Evidence location: inlong-tubemq/tubemq-manager/src/main/java/org/apache/inlong/tubemq/manager/service/TaskServiceImpl.java
3. `inlong-tubemq/tubemq-manager/src/main/java/org/apache/inlong/tubemq/manager/executors/AddTopicExecutor.java`

Evidence location: inlong-tubemq/tubemq-manager/src/main/java/org/apache/inlong/tubemq/manager/executors/AddTopicExecutor.java
4. `inlong-tubemq/tubemq-manager/src/main/java/org/apache/inlong/tubemq/manager/TubeMQManager.java`

Evidence location: inlong-tubemq/tubemq-manager/src/main/java/org/apache/inlong/tubemq/manager/TubeMQManager.java

## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

Validate caller permission for topic creation on the target cluster before saving the task; record creator and revalidate at execution time if needed

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/inlong/issue9.html
