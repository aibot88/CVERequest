---
title: "lamp-cloud issue8: Unauthorized Organization Membership Disclosure via `GET /anyone/findDeptByCompany`"
description: "lamp-cloud has a missing authorization vulnerability in `GET /anyone/findDeptByCompany`. Disclosure of another employee's organization membership. The same relationship is authorization-relevant because organization membership can participate in organization role inheritance"
tags:
  - lamp-cloud
  - vulnerability-report
  - authorization
  - access-control
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

lamp-cloud has a missing authorization vulnerability in `GET /anyone/findDeptByCompany`. Disclosure of another employee's organization membership. The same relationship is authorization-relevant because organization membership can participate in organization role inheritance

- Attack precondition: Any logged-in user who knows or can guess a target `employeeId` and `companyId`
- Affected endpoint: ``GET /anyone/findDeptByCompany``
- Affected authorization property: `employee organization membership, department relationship, organization tree path`
- Security impact: Disclosure of another employee's organization membership. The same relationship is authorization-relevant because organization membership can participate in organization role inheritance

### 1.2 Exploit path

Call `GET /anyone/findDeptByCompany?companyId=<company>&employeeId=<target>`

### 1.3 Key code evidence

1. `lamp-oauth/lamp-oauth-controller/src/main/java/top/tangyh/lamp/oauth/controller/UserInfoController.java`

Evidence location: https://gitee.com/dromara/lamp-cloud/blob/master/lamp-oauth/lamp-oauth-controller/src/main/java/top/tangyh/lamp/oauth/controller/UserInfoController.java
2. `lamp-base/lamp-base-biz/src/main/java/top/tangyh/lamp/base/service/user/impl/BaseOrgServiceImpl.java`

Evidence location: https://gitee.com/dromara/lamp-cloud/blob/master/lamp-base/lamp-base-biz/src/main/java/top/tangyh/lamp/base/service/user/impl/BaseOrgServiceImpl.java#L166

```text
  163
  164      @Override
  165      @Transactional(readOnly = true)
  166      public List<BaseOrg> findDeptByEmployeeId(Long employeeId, Long companyId) {
  167          // [non-English text removed] ID ([non-English text removed])
  168          List<Long> orgIdList = baseEmployeeOrgRelManager.findOrgIdByEmployeeId(employeeId);
  169          // [non-English text removed] [non-English text removed]
  170          List<BaseOrg> orgList = findByIds(orgIdList, null);
  171
  172          /*
  173           * [non-English text removed] companyId [non-English text removed],[non-English text removed] orgIdList [non-English text removed]
  174           * [non-English text removed]: [non-English text removed], [non-English text removed] [non-English text removed] [non-English text removed] [non-English text removed] [non-English text removed],[non-English text removed] [non-English text removed] [non-English text removed],[non-English text removed] [non-English text removed].
  175           */
  176
  177          return orgList.stream()
  178                  // [non-English text removed]
  179                  .filter(item -> OrgTypeEnum.DEPT.eq(item.getType()))
  180                  // [non-English text removed] companyId [non-English text removed]
  181                  .filter(item -> companyId == null || StrUtil.contains(item.getTreePath(), TreeUtil.buildTreePath(companyId)))
  182                  .toList();
  183      }
  184
  185
```


## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

Default to the current employee. For cross-employee organization lookups, require management permission and verify the target employee is within the caller's authorized organization scope

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/lamp-cloud/issue8.html
