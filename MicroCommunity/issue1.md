---
title: "MicroCommunity issue1: Confirmed Vulnerability"
description: "MicroCommunity has a missing authorization vulnerability in POST /app/role.saveRoleStaff, POST /app/add.privilege.PrivilegeGroup, POST /app/role.saveStaffCommunity, POST /app/owner.saveOwnerMember, POST /app/owner.editOwnerMember, POST /app/ownerSettled.saveOwnerSettledApply. A user with access to this action can bind a high-privilege role to themselves or another staff account, causing privilege escalation across the backend permission system"
tags:
  - MicroCommunity
  - vulnerability-report
  - authorization
  - access-control
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

MicroCommunity has a missing authorization vulnerability in POST /app/role.saveRoleStaff, POST /app/add.privilege.PrivilegeGroup, POST /app/role.saveStaffCommunity, POST /app/owner.saveOwnerMember, POST /app/owner.editOwnerMember, POST /app/ownerSettled.saveOwnerSettledApply. A user with access to this action can bind a high-privilege role to themselves or another staff account, causing privilege escalation across the backend permission system

- Attack precondition: Any authenticated user
- Affected endpoint: `POST /app/role.saveRoleStaff, POST /app/add.privilege.PrivilegeGroup, POST /app/role.saveStaffCommunity, POST /app/owner.saveOwnerMember, POST /app/owner.editOwnerMember, POST /app/ownerSettled.saveOwnerSettledApply`
- Affected authorization property: `mrbpc_detector, role.saveRoleStaff, roleId, staffs[].staffId, pgId, pIds[].pId`
- Security impact: A user with access to this action can bind a high-privilege role to themselves or another staff account, causing privilege escalation across the backend permission system

### 1.2 Exploit path

1. Request reaches `AppController.servicePost` through `/app/{service}`. 2. `AppController` performs action-level `hasPrivilege` for `/app/role.saveRoleStaff`. 3. `SaveRoleStaffCmd.validate` only checks that `roleId` exists and `staffs` is non-empty. 4. `SaveRoleStaffCmd.doCmd` loops through `staffs` and writes: - `staffs[].staffId` -> `p_privilege_user.user_id` - `roleId` -> `p_privilege_user.p_id` - `PrivilegeUserDto.PRIVILEGE_FLAG_GROUP` -> `p_privilege_user.privilege_flag` 5. Downstream menu/resource authorization uses `p_privilege_user` and `p_privilege_rel` to determine granted permissions

### 1.3 Key code evidence

1. `app/role.saveRoleStaff`

Evidence location: https://github.com/java110/MicroCommunity/blob/master/app/role.saveRoleStaff
2. `app/add.privilege.PrivilegeGroup`

Evidence location: https://github.com/java110/MicroCommunity/blob/master/app/add.privilege.PrivilegeGroup
3. `app/role.saveStaffCommunity`

Evidence location: https://github.com/java110/MicroCommunity/blob/master/app/role.saveStaffCommunity
4. `app/owner.saveOwnerMember`

Evidence location: https://github.com/java110/MicroCommunity/blob/master/app/owner.saveOwnerMember
5. `app/owner.editOwnerMember`

Evidence location: https://github.com/java110/MicroCommunity/blob/master/app/owner.editOwnerMember
6. `app/ownerSettled.saveOwnerSettledApply`

Evidence location: https://github.com/java110/MicroCommunity/blob/master/app/ownerSettled.saveOwnerSettledApply
7. `service-api/src/main/java/com/java110/api/controller/app/AppController.java`

Evidence location: https://github.com/java110/MicroCommunity/blob/master/service-api/src/main/java/com/java110/api/controller/app/AppController.java#L83

```text
   80       */
   81
   82      @RequestMapping(path = "/{service:.+}", method = RequestMethod.POST)
   83      @ApiOperation(value = "[non-English text removed]post[non-English text removed]", notes = "test: [non-English text removed] 2XX [non-English text removed]")
   84      @ApiImplicitParam(paramType = "query", name = "service", value = "[non-English text removed]", required = true, dataType = "String")
   85      @Java110Lang
   86      public ResponseEntity<String> servicePost(@PathVariable String service,
```

8. `service-api/src/main/java/com/java110/api/controller/app/AppController.java`

Evidence location: https://github.com/java110/MicroCommunity/blob/master/service-api/src/main/java/com/java110/api/controller/app/AppController.java#L103

```text
  100              IPageData pd = (IPageData) request.getAttribute(CommonConstant.CONTEXT_PAGE_DATA);
  101              //todo [non-English text removed] [non-English text removed] [non-English text removed] [non-English text removed],[non-English text removed]"/app/" + service [non-English text removed] [non-English text removed] [non-English text removed]
  102              privilegeSMOImpl.hasPrivilege(restTemplate, pd, "/app/" + service);
  103              //todo [non-English text removed] [non-English text removed] [non-English text removed]
  104              responseEntity = apiSMOImpl.doApi(postInfo, headers,request);
  105              //todo [non-English text removed] token
  106              wirteToken(request,pd,service,responseEntity);
```

9. `service-user/src/main/java/com/java110/user/cmd/role/SaveRoleStaffCmd.java`

Evidence location: https://github.com/java110/MicroCommunity/blob/master/service-user/src/main/java/com/java110/user/cmd/role/SaveRoleStaffCmd.java#L84

```text
   81                  throw new CmdException("[non-English text removed]");
   82              }
   83          }
   84
   85          cmdDataFlowContext.setResponseEntity(ResultVo.success());
   86      }
   87  }
```

10. `service-user/src/main/java/com/java110/user/cmd/role/SaveRoleStaffCmd.java`

Evidence location: https://github.com/java110/MicroCommunity/blob/master/service-user/src/main/java/com/java110/user/cmd/role/SaveRoleStaffCmd.java#L122
11. `service-user/src/main/java/com/java110/user/cmd/role/SaveRoleStaffCmd.java`

Evidence location: https://github.com/java110/MicroCommunity/blob/master/service-user/src/main/java/com/java110/user/cmd/role/SaveRoleStaffCmd.java#L124
12. `service-user/src/main/java/com/java110/user/cmd/role/SaveRoleStaffCmd.java`

Evidence location: https://github.com/java110/MicroCommunity/blob/master/service-user/src/main/java/com/java110/user/cmd/role/SaveRoleStaffCmd.java#L130

## 2. Existing checks and why they fail

`hasPrivilege` only proves the caller may invoke the route. It does not prove that the caller may grant the specific `roleId` to the specific `staffId`. The mapper insert has no database-level constraint enforcing grant hierarchy or management scope

## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

Before saving the binding:

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/MicroCommunity/issue1.html
