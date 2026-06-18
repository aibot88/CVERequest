---
title: "halo issue2: Public get-by-name 绕过评论 hidden/approved 可见性过滤"
description: "halo has a missing authorization vulnerability: Public get-by-name 绕过评论 hidden/approved 可见性过滤. 匿名或低权限用户可按名称读取 hidden 或未审核评论的正文、raw 内容、审核状态和隐藏状态，绕过公开评论列表的可见性控制。"
tags:
  - halo
  - 漏洞报告
  - 越权
  - 访问控制
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

halo has a missing authorization vulnerability: Public get-by-name 绕过评论 hidden/approved 可见性过滤. 匿名或低权限用户可按名称读取 hidden 或未审核评论的正文、raw 内容、审核状态和隐藏状态，绕过公开评论列表的可见性控制。

- Security impact: 匿名或低权限用户可按名称读取 hidden 或未审核评论的正文、raw 内容、审核状态和隐藏状态，绕过公开评论列表的可见性控制。

### 1.2 Exploit path

1. 攻击者请求 `GET /apis/api.halo.run/v1alpha1/comments/{name}`。 2. `CommentFinderEndpoint.getComment` 调用 `commentPublicQueryService.getByName(name)`。 3. `CommentPublicQueryServiceImpl.getByName` 直接 `client.fetch(Comment.class, name)`。 4. 返回值经 `CommentVo.from(comment)` 转换后响应给客户端。 5. 该路径没有执行 list/reply 路径中使用的 hidden/approved 可见性过滤。

### 1.3 Key code evidence

1. `apis/api.halo.run`

Evidence location: https://github.com/halo-dev/halo/blob/master/apis/api.halo.run
2. `Comment.c`

Evidence location: https://github.com/halo-dev/halo/blob/master/Comment.c
3. `application/src/main/java/run/halo/app/core/endpoint/theme/CommentFinderEndpoint.java`

Evidence location: https://github.com/halo-dev/halo/blob/master/application/src/main/java/run/halo/app/core/endpoint/theme/CommentFinderEndpoint.java
4. `application/src/main/java/run/halo/app/theme/finders/impl/CommentPublicQueryServiceImpl.java`

Evidence location: https://github.com/halo-dev/halo/blob/master/application/src/main/java/run/halo/app/theme/finders/impl/CommentPublicQueryServiceImpl.java
5. `application/src/main/java/run/halo/app/theme/finders/vo/CommentVo.java`

Evidence location: https://github.com/halo-dev/halo/blob/master/application/src/main/java/run/halo/app/theme/finders/vo/CommentVo.java
6. `api/src/main/java/run/halo/app/core/extension/content/Comment.java`

Evidence location: https://github.com/halo-dev/halo/blob/master/api/src/main/java/run/halo/app/core/extension/content/Comment.java

## 2. Existing checks and why they fail

- `filterCommentSensitiveData` 会处理 owner/IP/email 等敏感信息，但不清除 `raw`、`content`、`hidden`、`approved`。
- list/reply 路径有可见性过滤，但 get-by-name 路径未调用。
- 需要知道 comment name 只是利用前提，不是可靠防线。

## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

修改 `CommentPublicQueryServiceImpl.getByName`，fetch comment 后调用与 list/reply 相同的 `populateVisibleListOptions(comment)` 或等价权限检查。 - 对不可见评论返回 not found，避免暴露资源存在性。 - 增加测试覆盖：匿名用户不能按 name 读取 hidden 或未审核评论；评论 owner 或具备 `role-template-view-comments` 的用户可以按策略读取。

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/halo/issue2.html
