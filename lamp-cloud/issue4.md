---
title: "lamp-cloud issue4: Unauthorized Role-Resource Binding via `POST /baseRole/roleResource`"
description: "lamp-cloud has a missing authorization vulnerability in `POST /baseRole/roleResource`. Privilege expansion for all holders of the modified role. Added resources are used by the authorization system"
tags:
  - lamp-cloud
  - vulnerability-report
  - authorization
  - access-control
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

lamp-cloud has a missing authorization vulnerability in `POST /baseRole/roleResource`. Privilege expansion for all holders of the modified role. Added resources are used by the authorization system

- Attack precondition: The attacker is logged in and has the URI/API permission for this endpoint, but should not be allowed to grant arbitrary resources to arbitrary roles
- Affected endpoint: ``POST /baseRole/roleResource``
- Affected authorization property: ``base_role_resource_rel.role_id`, `base_role_resource_rel.resource_id`, `base_role_resource_rel.application_id``
- Security impact: Privilege expansion for all holders of the modified role. Added resources are used by the authorization system

### 1.2 Exploit path

Submit a target `roleId` and an `applicationResourceMap` containing high-privilege resource IDs

### 1.3 Key code evidence

1. `lamp-base/lamp-base-controller/src/main/java/top/tangyh/lamp/base/controller/system/BaseRoleController.java`

Evidence location: https://gitee.com/dromara/lamp-cloud/blob/master/lamp-base/lamp-base-controller/src/main/java/top/tangyh/lamp/base/controller/system/BaseRoleController.java
2. `lamp-base/lamp-base-biz/src/main/java/top/tangyh/lamp/base/service/system/impl/BaseRoleServiceImpl.java`

Evidence location: https://gitee.com/dromara/lamp-cloud/blob/master/lamp-base/lamp-base-biz/src/main/java/top/tangyh/lamp/base/service/system/impl/BaseRoleServiceImpl.java#L152

```text
  149
  150      @Override
  151      @Transactional(rollbackFor = Exception.class)
  152      public Boolean saveRoleResource(BaseRoleResourceRelSaveVO saveVO) {
  153          Map<Long, List<Long>> applicationResourceMap = saveVO.getApplicationResourceMap();
  154          baseRoleResourceRelManager.remove(Wraps.<BaseRoleResourceRel>lbQ().eq(BaseRoleResourceRel::getRoleId, saveVO.getRoleId()));
  155          if (CollUtil.isEmpty(applicationResourceMap)) {
  156              return false;
  157          }
  158
  159          List<BaseRoleResourceRel> list = new ArrayList<>();
  160          List<CacheKey> keys = new ArrayList<>();
  161          applicationResourceMap.forEach((applicationId, resourceList) -> {
  162              if (CollUtil.isNotEmpty(resourceList)) {
  163                  for (Long resourceId : resourceList) {
  164                      BaseRoleResourceRel baseRoleResRel = new BaseRoleResourceRel();
  165                      baseRoleResRel.setRoleId(saveVO.getRoleId());
  166                      baseRoleResRel.setResourceId(resourceId);
  167                      baseRoleResRel.setApplicationId(applicationId);
  168                      list.add(baseRoleResRel);
  169                  }
  170              }
  171              keys.add(RoleResourceCacheKeyBuilder.build(applicationId, saveVO.getRoleId()));
  172          });
  173          keys.add(RoleResourceCacheKeyBuilder.build(null, saveVO.getRoleId()));
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

4. `lamp-base/lamp-base-entity/src/main/java/top/tangyh/lamp/base/vo/save/system/BaseRoleResourceRelSaveVO.java`

Evidence location: https://gitee.com/dromara/lamp-cloud/blob/master/lamp-base/lamp-base-entity/src/main/java/top/tangyh/lamp/base/vo/save/system/BaseRoleResourceRelSaveVO.java#L42

```text
   39      /**
   40       * [non-English text removed]id;#base_role
   41       */
   42      @Schema(description = "[non-English text removed]id")
   43      @NotNull(message = "[non-English text removed]id")
   44      private Long roleId;
   45      /**
   46       * [non-English text removed]
   47       */
   48      @Schema(description = "[non-English text removed]-[non-English text removed] [non-English text removed] [[non-English text removed]]")
   49      @NotNull
   50      private Map<Long, List<Long>> applicationResourceMap;
   51  }
```


## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

Enforce role management authorization, resource grant authorization, and application-resource ownership consistency before writing any relation

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/lamp-cloud/issue4.html
