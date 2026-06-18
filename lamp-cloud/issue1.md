---
title: "lamp-cloud issue1: Unauthorized Employee-Role Binding via `POST /baseEmployee/employeeRole`"
description: "lamp-cloud has a missing authorization vulnerability in `POST /baseEmployee/employeeRole`. Privilege escalation and lateral privilege expansion. The written role relation is later used by the permission calculation chain"
tags:
  - lamp-cloud
  - 漏洞报告
  - 越权
  - 访问控制
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

lamp-cloud has a missing authorization vulnerability in `POST /baseEmployee/employeeRole`. Privilege escalation and lateral privilege expansion. The written role relation is later used by the permission calculation chain

- Attack precondition: The attacker is logged in and has the URI/API permission for this endpoint, but should not be allowed to grant arbitrary roles
- Affected endpoint: ``POST /baseEmployee/employeeRole``
- Affected authorization property: ``base_employee_role_rel.employee_id`, `base_employee_role_rel.role_id``
- Security impact: Privilege escalation and lateral privilege expansion. The written role relation is later used by the permission calculation chain

### 1.2 Exploit path

Submit an arbitrary `employeeId` and high-privilege `roleIdList`, such as a tenant administrator role, to bind privileged roles to self or another employee

### 1.3 Key code evidence

1. `lamp-base/lamp-base-controller/src/main/java/top/tangyh/lamp/base/controller/user/BaseEmployeeController.java`

Evidence location: https://gitee.com/dromara/lamp-cloud/blob/master/lamp-base/lamp-base-controller/src/main/java/top/tangyh/lamp/base/controller/user/BaseEmployeeController.java
2. `lamp-base/lamp-base-biz/src/main/java/top/tangyh/lamp/base/service/user/impl/BaseEmployeeServiceImpl.java`

Evidence location: https://gitee.com/dromara/lamp-cloud/blob/master/lamp-base/lamp-base-biz/src/main/java/top/tangyh/lamp/base/service/user/impl/BaseEmployeeServiceImpl.java#L86

```text
   83  
   84      @Override
   85      @Transactional(rollbackFor = Exception.class)
   86      public List<Long> saveEmployeeRole(BaseEmployeeRoleRelSaveVO saveVO) {
   87          if (saveVO.getFlag() == null) {
   88              saveVO.setFlag(true);
   89          }
   90  
   91          baseEmployeeRoleRelManager.remove(Wraps.<BaseEmployeeRoleRel>lbQ().eq(BaseEmployeeRoleRel::getEmployeeId, saveVO.getEmployeeId())
   92                  .in(BaseEmployeeRoleRel::getRoleId, saveVO.getRoleIdList()));
   93  
   94          if (saveVO.getFlag() && CollUtil.isNotEmpty(saveVO.getRoleIdList())) {
   95              List<BaseEmployeeRoleRel> list = saveVO.getRoleIdList().stream()
   96                      .map(roleId -> BaseEmployeeRoleRel.builder()
   97                              .roleId(roleId).employeeId(saveVO.getEmployeeId())
   98                              .build()).toList();
   99              baseEmployeeRoleRelManager.saveBatch(list);
  100          }
  101  
  102          cacheOps.del(EmployeeRoleCacheKeyBuilder.build(saveVO.getEmployeeId()));
  103          return findEmployeeRoleByEmployeeId(saveVO.getEmployeeId());
  104      }
  105  
  106      @Override
```

3. `lamp-base/lamp-base-entity/src/main/java/top/tangyh/lamp/base/vo/save/user/BaseEmployeeRoleRelSaveVO.java`

Evidence location: https://gitee.com/dromara/lamp-cloud/blob/master/lamp-base/lamp-base-entity/src/main/java/top/tangyh/lamp/base/vo/save/user/BaseEmployeeRoleRelSaveVO.java#L43

```text
   40      /**
   41       * 角色;#base_role
   42       */
   43      @Schema(description = "角色")
   44      @Size(min = 1, message = "请选择角色")
   45      private List<Long> roleIdList;
   46      /**
   47       * 员工;#base_employee
   48       */
   49      @Schema(description = "员工")
   50      @NotNull(message = "请选择员工")
   51      private Long employeeId;
   52  
   53  }
```


## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

Enforce service-layer authorization. Validate that the caller can manage `employeeId`, and that every role in `roleIdList` is within the caller's grantable role set. Deny sensitive or equal/higher privilege role grants by default

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/lamp-cloud/issue1.html
