---
title: "Spring-Cloud-Platform issue4: service-client 列表接口泄露 client secret"
description: "Spring-Cloud-Platform has a missing authorization vulnerability: service-client 列表接口泄露 client secret. 泄露 client secret。该 secret 被用于客户端校验相关接口，属于敏感凭据泄露。"
tags:
  - Spring-Cloud-Platform
  - 漏洞报告
  - 越权
  - 访问控制
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

Spring-Cloud-Platform has a missing authorization vulnerability: service-client 列表接口泄露 client secret. 泄露 client secret。该 secret 被用于客户端校验相关接口，属于敏感凭据泄露。

- Security impact: 泄露 client secret。该 secret 被用于客户端校验相关接口，属于敏感凭据泄露。

### 1.2 Exploit path

`GET /api/auth/service/{id}/client` 访问 service-client 关系列表接口。权限字典没有对应 GET 子资源，父级 `GET /auth/service/{*}` 不能匹配 `/client` 后缀，因此权限检查 fail-open。Controller 返回 `List<Client>`，SQL 查询 `client.*`，实体包含 `secret` 且没有响应 DTO 或 `@JsonIgnore` 过滤。

### 1.3 Key code evidence

1. `ServiceController.java`

Evidence location: ServiceController.java
2. `ClientMapper.xml`

Evidence location: ClientMapper.xml
3. `Client.java`

Evidence location: Client.java
4. `DBAuthClientService.java`

Evidence location: DBAuthClientService.java

## 2. Existing checks and why they fail

无精确 GET 子资源权限；无字段级响应过滤；返回实体对象而非脱敏 DTO。

## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

增加 `GET /auth/service/{*}/client` 权限项；返回 DTO 排除 `secret`；敏感凭据只允许专用安全流程读取或轮换。

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/Spring-Cloud-Platform/issue4.html
