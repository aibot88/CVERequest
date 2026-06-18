---
title: "lamp-cloud issue10: Unauthorized User Account State and Identity Disclosure via `GET /anyone/getUserInfoById`"
description: "lamp-cloud has a missing authorization vulnerability in `GET /anyone/getUserInfoById`. Disclosure of another user's account state and identity-related fields. `state` is authorization/authentication relevant because disabled users are rejected during login/switch checks"
tags:
  - lamp-cloud
  - vulnerability-report
  - authorization
  - access-control
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

lamp-cloud has a missing authorization vulnerability in `GET /anyone/getUserInfoById`. Disclosure of another user's account state and identity-related fields. `state` is authorization/authentication relevant because disabled users are rejected during login/switch checks

- Attack precondition: Any logged-in user who knows or can guess a target `userId`
- Affected endpoint: ``GET /anyone/getUserInfoById``
- Affected authorization property: ``def_user.state` and other account identity fields`
- Security impact: Disclosure of another user's account state and identity-related fields. `state` is authorization/authentication relevant because disabled users are rejected during login/switch checks

### 1.2 Exploit path

Call `GET /anyone/getUserInfoById?userId=<target>`

### 1.3 Key code evidence

1. `lamp-oauth/lamp-oauth-controller/src/main/java/top/tangyh/lamp/oauth/controller/UserInfoController.java`

Evidence location: https://gitee.com/dromara/lamp-cloud/blob/master/lamp-oauth/lamp-oauth-controller/src/main/java/top/tangyh/lamp/oauth/controller/UserInfoController.java
2. `lamp-oauth/lamp-oauth-biz/src/main/java/top/tangyh/lamp/oauth/biz/OauthUserBiz.java`

Evidence location: https://gitee.com/dromara/lamp-cloud/blob/master/lamp-oauth/lamp-oauth-biz/src/main/java/top/tangyh/lamp/oauth/biz/OauthUserBiz.java#L36

```text
   33      private final DefApplicationService defApplicationService;
   34      private final AppendixService appendixService;
   35
   36      public DefUserInfoResultVO getUserById(Long id) {
   37          // [non-English text removed]
   38          DefUser defUser = defUserService.getByIdCache(id);
   39          if (defUser == null) {
   40              return null;
   41          }
   42
   43          // [non-English text removed]
   44          DefUserInfoResultVO resultVO = new DefUserInfoResultVO();
   45          BeanUtil.copyProperties(defUser, resultVO);
   46
   47          // [non-English text removed]
   48          AppendixResultVO appendix = appendixService.getByBiz(defUser.getId(), AppendixType.System.DEF__USER__AVATAR);
   49          if (appendix != null) {
   50              resultVO.setAvatarId(appendix.getId());
   51          }
   52
   53          Long employeeId = ContextUtil.getEmployeeId();
   54          resultVO.setEmployeeId(employeeId);
   55
   56          //[non-English text removed] [non-English text removed]
   57          BaseEmployee employee = baseEmployeeService.getById(employeeId);
   58          resultVO.setBaseEmployee(BeanUtil.toBean(employee, BaseEmployeeResultVO.class));
   59
   60          DefApplication defApplication = defApplicationService.getDefApp(id);
   61          resultVO.setDefApplication(BeanUtil.toBean(defApplication, DefApplicationResultVO.class));
   62          return resultVO;
   63      }
   64  }
```

3. `lamp-oauth/lamp-oauth-biz/src/main/java/top/tangyh/lamp/oauth/granter/AbstractTokenGranter.java`

Evidence location: https://gitee.com/dromara/lamp-cloud/blob/master/lamp-oauth/lamp-oauth-biz/src/main/java/top/tangyh/lamp/oauth/granter/AbstractTokenGranter.java#L448

```text
  445              throw UnauthorizedException.wrap(ExceptionCode.JWT_TOKEN_EXPIRED);
  446          }
  447
  448          if (!Convert.toBool(defUser.getState(), true)) {
  449              throw UnauthorizedException.wrap(ExceptionCode.JWT_USER_DISABLE);
  450          }
  451
  452          BaseEmployee employee = baseEmployeeService.getEmployeeByUser(userId);
```


## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

Restrict this endpoint to current-user lookup only. Provide a separate administrator endpoint for cross-user reads with object-level authorization and sensitive-field filtering

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/lamp-cloud/issue10.html
