---
title: "SpringBlade issue6: `GET /menu/role-tree-keys`"
description: "SpringBlade has a missing authorization vulnerability: `GET /menu/role-tree-keys`. discloses role-to-permission bindings and authorization structure, which are sensitive authorization relationships"
tags:
  - SpringBlade
  - 漏洞报告
  - 越权
  - 访问控制
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

SpringBlade has a missing authorization vulnerability: `GET /menu/role-tree-keys`. discloses role-to-permission bindings and authorization structure, which are sensitive authorization relationships

- Attack precondition: any authenticated user who can guess or obtain role IDs
- Security impact: discloses role-to-permission bindings and authorization structure, which are sensitive authorization relationships

### 1.2 Exploit path

attacker calls `/menu/role-tree-keys?roleIds=...`; service returns menu/data-scope/api-scope key lists for arbitrary roles

### 1.3 Key code evidence

1. `blade-service/blade-system/src/main/java/org/springblade/system/controller/MenuController.java`

Evidence location: https://github.com/chillzhuang/SpringBlade/blob/master/blade-service/blade-system/src/main/java/org/springblade/system/controller/MenuController.java#L197

```text
  194  	/**
  195  	 * 获取权限分配树形结构
  196  	 */
  197  	@GetMapping("/role-tree-keys")
  198  	@ApiOperationSupport(order = 11)
  199  	@Operation(summary = "角色所分配的树", description = "角色所分配的树")
  200  	public R<CheckedTreeVO> roleTreeKeys(String roleIds) {
```

2. `blade-service/blade-system/src/main/java/org/springblade/system/service/impl/MenuServiceImpl.java`

Evidence location: https://github.com/chillzhuang/SpringBlade/blob/master/blade-service/blade-system/src/main/java/org/springblade/system/service/impl/MenuServiceImpl.java#L159

```text
  156  	}
  157  
  158  	@Override
  159  	public List<String> roleTreeKeys(String roleIds) {
  160  		List<RoleMenu> roleMenus = roleMenuService.list(Wrappers.<RoleMenu>query().lambda().in(RoleMenu::getRoleId, Func.toLongList(roleIds)));
  161  		return roleMenus.stream().map(roleMenu -> Func.toStr(roleMenu.getMenuId())).collect(Collectors.toList());
  162  	}
```

3. `blade-service/blade-system/src/main/java/org/springblade/system/service/impl/MenuServiceImpl.java`

Evidence location: https://github.com/chillzhuang/SpringBlade/blob/master/blade-service/blade-system/src/main/java/org/springblade/system/service/impl/MenuServiceImpl.java#L164

```text
  161  		return roleMenus.stream().map(roleMenu -> Func.toStr(roleMenu.getMenuId())).collect(Collectors.toList());
  162  	}
  163  
  164  	@Override
  165  	public List<String> dataScopeTreeKeys(String roleIds) {
  166  		List<RoleScope> roleScopes = roleScopeService.list(Wrappers.<RoleScope>query().lambda().eq(RoleScope::getScopeCategory, DATA_SCOPE_CATEGORY).in(RoleScope::getRoleId, Func.toLongList(roleIds)));
  167  		return roleScopes.stream().map(roleScope -> Func.toStr(roleScope.getScopeId())).collect(Collectors.toList());
```

4. `blade-gateway/src/main/java/org/springblade/gateway/provider/AuthProvider.java`

Evidence location: https://github.com/chillzhuang/SpringBlade/blob/master/blade-gateway/src/main/java/org/springblade/gateway/provider/AuthProvider.java#L33

```text
   30  	public static String AUTH_KEY = TokenConstant.HEADER;
   31  	private static final List<String> DEFAULT_SKIP_URL = new ArrayList<>();
   32  
   33  	static {
   34  		DEFAULT_SKIP_URL.add("/example");
   35  		DEFAULT_SKIP_URL.add("/token/**");
   36  		DEFAULT_SKIP_URL.add("/captcha/**");
```


## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

add admin authorization and validate all submitted role IDs against current tenant and current operator's manageable role set

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/SpringBlade/issue6.html
