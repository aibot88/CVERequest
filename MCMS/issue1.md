---
title: "MCMS issue1: Backend category list bypasses `cms:category:view`"
description: "MCMS has a missing authorization vulnerability in POST /ms/cms/category/list, GET/POST /ms/cms/category/list, /ms/**, /list, /ms/cms/category/list. Unauthorized backend users can read category hierarchy and metadata, including parent links, display/search flags, model bindings, category flags, and business child markers"
tags:
  - MCMS
  - vulnerability-report
  - authorization
  - access-control
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

MCMS has a missing authorization vulnerability in POST /ms/cms/category/list, GET/POST /ms/cms/category/list, /ms/**, /list, /ms/cms/category/list. Unauthorized backend users can read category hierarchy and metadata, including parent links, display/search flags, model bindings, category flags, and business child markers

- Attack precondition: The attacker is an authenticated backend `manager` user but does not have `cms:category:view`
- Affected endpoint: `POST /ms/cms/category/list, GET/POST /ms/cms/category/list, /ms/**, /list, /ms/cms/category/list`
- Affected authorization property: `manager, cms:category:view, categoryBiz.list(...), @RequiresPermissions, new EUListBean(categoryList, categoryList.size()), authc,managerRoles[MANAGER]`
- Security impact: Unauthorized backend users can read category hierarchy and metadata, including parent links, display/search flags, model bindings, category flags, and business child markers

### 1.2 Exploit path

Request `GET/POST /ms/cms/category/list`. The global `/ms/**` Shiro filter only checks backend login/manager role, then the endpoint calls `categoryBiz.list(...)` and returns a full category list

### 1.3 Key code evidence

1. `src/main/java/net/mingsoft/cms/action/CategoryAction.java`

Evidence location: src/main/java/net/mingsoft/cms/action/CategoryAction.java#L96
2. `src/main/java/net/mingsoft/cms/action/CategoryAction.java`

Evidence location: src/main/java/net/mingsoft/cms/action/CategoryAction.java#L104
3. `src/main/java/net/mingsoft/cms/action/CategoryAction.java`

Evidence location: src/main/java/net/mingsoft/cms/action/CategoryAction.java#L81
4. `src/main/java/net/mingsoft/config/ShiroConfig.java`

Evidence location: src/main/java/net/mingsoft/config/ShiroConfig.java#L136

## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

Add `@RequiresPermissions("cms:category:view")` to `/ms/cms/category/list`, or enforce equivalent category-scope authorization before returning results

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/MCMS/issue1.html
