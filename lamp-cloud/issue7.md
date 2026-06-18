---
title: "lamp-cloud issue7: Unauthorized Permission Disclosure via `GET /anyone/findVisibleResource`"
description: "lamp-cloud has a missing authorization vulnerability in `GET /anyone/findVisibleResource`. Disclosure of another employee's resource permission codes"
tags:
  - lamp-cloud
  - vulnerability-report
  - authorization
  - access-control
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

lamp-cloud has a missing authorization vulnerability in `GET /anyone/findVisibleResource`. Disclosure of another employee's resource permission codes

- Attack precondition: Any logged-in user who knows or can guess a target `employeeId`
- Affected endpoint: ``GET /anyone/findVisibleResource``
- Affected authorization property: `employee resource codes`
- Security impact: Disclosure of another employee's resource permission codes

### 1.2 Exploit path

Call `GET /anyone/findVisibleResource?employeeId=<target>`

### 1.3 Key code evidence

1. `lamp-oauth/lamp-oauth-controller/src/main/java/top/tangyh/lamp/oauth/controller/ResourceController.java`

Evidence location: https://gitee.com/dromara/lamp-cloud/blob/master/lamp-oauth/lamp-oauth-controller/src/main/java/top/tangyh/lamp/oauth/controller/ResourceController.java
2. `lamp-oauth/lamp-oauth-biz/src/main/java/top/tangyh/lamp/oauth/biz/ResourceBiz.java`

Evidence location: https://gitee.com/dromara/lamp-cloud/blob/master/lamp-oauth/lamp-oauth-biz/src/main/java/top/tangyh/lamp/oauth/biz/ResourceBiz.java#L67

```text
   64       * @param applicationId [non-English text removed]id
   65       * @return [non-English text removed]
   66       */
   67      public List<String> findVisibleResource(Long employeeId, Long applicationId) {
   68          List<DefResource> list;
   69          boolean isAdmin = baseRoleService.checkRole(employeeId, RoleConstant.TENANT_ADMIN);
   70          List<String> resourceCodes = Collections.emptyList();
   71          if (isAdmin) {
   72              // [non-English text removed] [non-English text removed],[non-English text removed],[non-English text removed] [non-English text removed]
   73              list = defResourceService.findResourceListByApplicationId(applicationId != null ? Collections.singletonList(applicationId) : Collections.emptyList(), resourceCodes);
   74          } else {
   75              List<Long> resourceIdList = baseRoleService.findResourceIdByEmployeeId(applicationId, employeeId);
   76              if (resourceIdList.isEmpty()) {
   77                  return Collections.emptyList();
   78              }
   79
   80              list = defResourceService.findByIdsAndType(resourceIdList, resourceCodes);
   81          }
   82          return CollHelper.split(list, DefResource::getCode, StrPool.SEMICOLON);
   83      }
   84
   85      public List<VueRouter> findAllVisibleRouter(Long employeeId, String subGroup, ClientTypeEnum type) {
```

3. `lamp-base/lamp-base-biz/src/main/java/top/tangyh/lamp/base/service/system/impl/BaseRoleServiceImpl.java`

Evidence location: https://gitee.com/dromara/lamp-cloud/blob/master/lamp-base/lamp-base-biz/src/main/java/top/tangyh/lamp/base/service/system/impl/BaseRoleServiceImpl.java#L181

```text
  178      }
  179
  180      @Override
  181      public List<Long> findResourceIdByEmployeeId(Long applicationId, Long employeeId) {
  182          return superManager.findResourceIdByEmployeeId(applicationId, employeeId);
  183      }
  184
  185      @Override
  186      public boolean checkRole(Long employeeId, String... codes) {
  187          return superManager.checkRole(employeeId, codes);
  188      }
  189
  190      @Override
  191      public List<String> findRoleCodeByEmployeeId(Long employeeId) {
  192          List<BaseRole> list = superManager.findRoleByEmployeeId(employeeId);
  193          return list.stream().map(BaseRole::getCode).toList();
  194      }
  195  }
```


## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

Bind `employeeId` to the current login context, or move cross-user lookups behind a management endpoint with object-level authorization

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/lamp-cloud/issue7.html
