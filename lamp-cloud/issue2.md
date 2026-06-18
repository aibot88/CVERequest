---
title: "lamp-cloud issue2: Unauthorized Role-Employee Binding via `POST /baseRole/roleEmployee`"
description: "lamp-cloud has a missing authorization vulnerability in `POST /baseRole/roleEmployee`. Batch privilege escalation by assigning sensitive roles to arbitrary users"
tags:
  - lamp-cloud
  - vulnerability-report
  - authorization
  - access-control
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

lamp-cloud has a missing authorization vulnerability in `POST /baseRole/roleEmployee`. Batch privilege escalation by assigning sensitive roles to arbitrary users

- Attack precondition: The attacker is logged in and has the URI/API permission for this endpoint, but should not be allowed to bind arbitrary employees to arbitrary roles
- Affected endpoint: ``POST /baseRole/roleEmployee``
- Affected authorization property: ``base_employee_role_rel.role_id`, `base_employee_role_rel.employee_id``
- Security impact: Batch privilege escalation by assigning sensitive roles to arbitrary users

### 1.2 Exploit path

Submit a privileged `roleId` and arbitrary `employeeIdList` to grant that role to one or more employees

### 1.3 Key code evidence

1. `lamp-base/lamp-base-controller/src/main/java/top/tangyh/lamp/base/controller/system/BaseRoleController.java`

Evidence location: https://gitee.com/dromara/lamp-cloud/blob/master/lamp-base/lamp-base-controller/src/main/java/top/tangyh/lamp/base/controller/system/BaseRoleController.java
2. `lamp-base/lamp-base-biz/src/main/java/top/tangyh/lamp/base/service/system/impl/BaseRoleServiceImpl.java`

Evidence location: https://gitee.com/dromara/lamp-cloud/blob/master/lamp-base/lamp-base-biz/src/main/java/top/tangyh/lamp/base/service/system/impl/BaseRoleServiceImpl.java#L115

```text
  112
  113      @Override
  114      @Transactional(rollbackFor = Exception.class)
  115      public List<Long> saveRoleEmployee(RoleEmployeeSaveVO saveVO) {
  116          if (saveVO.getFlag() == null) {
  117              saveVO.setFlag(true);
  118          }
  119
  120          baseEmployeeRoleRelManager.remove(Wraps.<BaseEmployeeRoleRel>lbQ().eq(BaseEmployeeRoleRel::getRoleId, saveVO.getRoleId())
  121                  .in(BaseEmployeeRoleRel::getEmployeeId, saveVO.getEmployeeIdList()));
  122          if (saveVO.getFlag()) {
  123              List<BaseEmployeeRoleRel> list = saveVO.getEmployeeIdList().stream().map(employeeId ->
  124                      BaseEmployeeRoleRel.builder().employeeId(employeeId).roleId(saveVO.getRoleId()).build()).toList();
  125              baseEmployeeRoleRelManager.saveBatch(list);
  126          }
  127
  128          CacheKey[] cacheKeys = saveVO.getEmployeeIdList().stream().map(EmployeeRoleCacheKeyBuilder::build).toArray(CacheKey[]::new);
  129          cacheOps.del(cacheKeys);
  130          return findEmployeeIdByRoleId(saveVO.getRoleId());
  131      }
  132
  133      @Override
```

3. `lamp-base/lamp-base-entity/src/main/java/top/tangyh/lamp/base/vo/save/system/RoleEmployeeSaveVO.java`

Evidence location: https://gitee.com/dromara/lamp-cloud/blob/master/lamp-base/lamp-base-entity/src/main/java/top/tangyh/lamp/base/vo/save/system/RoleEmployeeSaveVO.java#L43

```text
   40      /**
   41       * [non-English text removed];#base_role
   42       */
   43      @Schema(description = "[non-English text removed]")
   44      @NotNull(message = "[non-English text removed]")
   45      private Long roleId;
   46      /**
   47       * [non-English text removed];#base_employee
   48       */
   49      @Schema(description = "[non-English text removed]")
   50      @Size(min = 1, message = "[non-English text removed]")
   51      private List<Long> employeeIdList;
   52
   53  }
```


## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

Validate that the caller can manage the target `roleId` and every employee in `employeeIdList`. Reject requests containing any out-of-scope employee or non-grantable role

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/lamp-cloud/issue2.html
