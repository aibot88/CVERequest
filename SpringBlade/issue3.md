---
title: "SpringBlade issue3: `POST /role/grant`"
description: "SpringBlade has a missing authorization vulnerability in /role/grant, roleIds/menuIds/dataScopeIds/apiScopeIds. expands role menu access, data-scope access, or API-scope access beyond the operator's allowed authorization boundary"
tags:
  - SpringBlade
  - vulnerability-report
  - authorization
  - access-control
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

SpringBlade has a missing authorization vulnerability in /role/grant, roleIds/menuIds/dataScopeIds/apiScopeIds. expands role menu access, data-scope access, or API-scope access beyond the operator's allowed authorization boundary

- Attack precondition: tenant admin with `HAS_ROLE_ADMIN` can call `/role/grant`
- Affected endpoint: `/role/grant, roleIds/menuIds/dataScopeIds/apiScopeIds`
- Affected authorization property: `HAS_ROLE_ADMIN, roleMenu.roleId, roleMenu.menuId, roleScope.roleId, roleScope.scopeId, roleScope.scopeCategory`
- Security impact: expands role menu access, data-scope access, or API-scope access beyond the operator's allowed authorization boundary

### 1.2 Exploit path

attacker submits a role in their tenant as `roleIds`, but supplies `menuIds`, `dataScopeIds`, or `apiScopeIds` outside their own grantable set. Service deletes existing bindings and writes the provided IDs

### 1.3 Key code evidence

1. `blade-service/blade-system/src/main/java/org/springblade/system/controller/RoleController.java`

Evidence location: https://github.com/chillzhuang/SpringBlade/blob/master/blade-service/blade-system/src/main/java/org/springblade/system/controller/RoleController.java#L137

```text
  134  		return R.status(roleService.removeByIds(Func.toLongList(ids)));
  135  	}
  136
  137  	/**
  138  	 * [non-English text removed]
  139  	 */
  140  	@PostMapping("/grant")
```

2. `blade-service/blade-system/src/main/java/org/springblade/system/service/impl/RoleServiceImpl.java`

Evidence location: https://github.com/chillzhuang/SpringBlade/blob/master/blade-service/blade-system/src/main/java/org/springblade/system/service/impl/RoleServiceImpl.java#L117

```text
  114  		roleScopeService.remove(Wrappers.<RoleScope>update().lambda().eq(RoleScope::getScopeCategory, API_SCOPE_CATEGORY).in(RoleScope::getRoleId, roleIds));
  115  		// [non-English text removed]
  116  		List<RoleScope> roleApiScopes = new ArrayList<>();
  117  		roleIds.forEach(roleId -> apiScopeIds.forEach(scopeId -> {
  118  			RoleScope roleScope = new RoleScope();
  119  			roleScope.setScopeCategory(API_SCOPE_CATEGORY);
  120  			roleScope.setScopeId(scopeId);
```

3. `blade-service/blade-system/src/main/java/org/springblade/system/service/impl/RoleServiceImpl.java`

Evidence location: https://github.com/chillzhuang/SpringBlade/blob/master/blade-service/blade-system/src/main/java/org/springblade/system/service/impl/RoleServiceImpl.java#L152
4. `blade-service/blade-system/src/main/java/org/springblade/system/service/impl/MenuServiceImpl.java`

Evidence location: https://github.com/chillzhuang/SpringBlade/blob/master/blade-service/blade-system/src/main/java/org/springblade/system/service/impl/MenuServiceImpl.java#L145

```text
  142
  143  	@Override
  144  	public List<MenuVO> grantTree(BladeUser user) {
  145  		return ForestNodeMerger.merge(user.getTenantId().equals(BladeConstant.ADMIN_TENANT_ID) ? baseMapper.grantTree() : baseMapper.grantTreeByRole(Func.toLongList(user.getRoleId())));
  146  	}
  147
  148  	@Override
```


## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

for non-`administrator`, compute the current user's grantable menu/data-scope/api-scope ID set and reject any submitted ID outside that set. Also verify existence and category consistency

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/SpringBlade/issue3.html
