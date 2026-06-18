---
title: "lamp-cloud issue3: Unauthorized Organization-Role Binding via `POST /baseOrg/orgRole`"
description: "lamp-cloud has a missing authorization vulnerability in `POST /baseOrg/orgRole`. Organization-wide privilege expansion. Employees may inherit roles through organization membership"
tags:
  - lamp-cloud
  - 漏洞报告
  - 越权
  - 访问控制
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

lamp-cloud has a missing authorization vulnerability in `POST /baseOrg/orgRole`. Organization-wide privilege expansion. Employees may inherit roles through organization membership

- Attack precondition: The attacker is logged in and has the URI/API permission for this endpoint, but should not be allowed to assign roles to arbitrary organizations
- Affected endpoint: ``POST /baseOrg/orgRole``
- Affected authorization property: ``base_org_role_rel.org_id`, `base_org_role_rel.role_id``
- Security impact: Organization-wide privilege expansion. Employees may inherit roles through organization membership

### 1.2 Exploit path

Submit an arbitrary `orgId` and privileged `roleIdList` to bind roles to that organization

### 1.3 Key code evidence

1. `lamp-base/lamp-base-controller/src/main/java/top/tangyh/lamp/base/controller/user/BaseOrgController.java`

Evidence location: https://gitee.com/dromara/lamp-cloud/blob/master/lamp-base/lamp-base-controller/src/main/java/top/tangyh/lamp/base/controller/user/BaseOrgController.java
2. `lamp-base/lamp-base-biz/src/main/java/top/tangyh/lamp/base/service/user/impl/BaseOrgServiceImpl.java`

Evidence location: https://gitee.com/dromara/lamp-cloud/blob/master/lamp-base/lamp-base-biz/src/main/java/top/tangyh/lamp/base/service/user/impl/BaseOrgServiceImpl.java#L133

```text
  130  
  131      @Override
  132      @Transactional(rollbackFor = Exception.class)
  133      public List<Long> saveOrgRole(BaseOrgRoleRelSaveVO saveVO) {
  134          if (saveVO.getFlag() == null) {
  135              saveVO.setFlag(true);
  136          }
  137  
  138          baseOrgRoleRelManager.remove(Wraps.<BaseOrgRoleRel>lbQ().eq(BaseOrgRoleRel::getOrgId, saveVO.getOrgId())
  139                  .in(BaseOrgRoleRel::getRoleId, saveVO.getRoleIdList()));
  140  
  141          if (saveVO.getFlag() && CollUtil.isNotEmpty(saveVO.getRoleIdList())) {
  142              List<BaseOrgRoleRel> list = saveVO.getRoleIdList().stream()
  143                      .map(roleId -> BaseOrgRoleRel.builder()
  144                              .roleId(roleId).orgId(saveVO.getOrgId())
  145                              .build()).toList();
  146              baseOrgRoleRelManager.saveBatch(list);
  147          }
  148  
  149          cacheOps.del(OrgRoleCacheKeyBuilder.build(saveVO.getOrgId()));
  150          return findOrgRoleByOrgId(saveVO.getOrgId());
  151      }
  152  
  153      @Override
```

3. `lamp-base/lamp-base-entity/src/main/java/top/tangyh/lamp/base/vo/save/user/BaseOrgRoleRelSaveVO.java`

Evidence location: https://gitee.com/dromara/lamp-cloud/blob/master/lamp-base/lamp-base-entity/src/main/java/top/tangyh/lamp/base/vo/save/user/BaseOrgRoleRelSaveVO.java#L43

```text
   40      /**
   41       * 角色;#base_role
   42       */
   43      @Schema(description = "角色")
   44      @Size(min = 1, message = "请选择角色")
   45      private List<Long> roleIdList;
   46      /**
   47       * 机构;#base_org
   48       */
   49      @Schema(description = "机构")
   50      @NotNull(message = "请选择机构")
   51      private Long orgId;
   52  
   53  }
```


## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

Validate that `orgId` is in the caller's manageable organization tree and that every role in `roleIdList` is grantable by the caller

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/lamp-cloud/issue3.html
