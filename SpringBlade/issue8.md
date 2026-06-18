---
title: "SpringBlade issue8: `POST /data-scope/*` and `POST /api-scope/*`"
description: "SpringBlade has a missing authorization vulnerability in POST /user/save-user, POST /user/user-auth-info, POST /role/grant, GET /user/detail, GET /user/user-list, GET /tenant/page. expands data visibility or API path permissions once the rule is bound to a role, or immediately if modifying an already-bound scope"
tags:
  - SpringBlade
  - vulnerability-report
  - authorization
  - access-control
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

SpringBlade has a missing authorization vulnerability in POST /user/save-user, POST /user/user-auth-info, POST /role/grant, GET /user/detail, GET /user/user-list, GET /tenant/page. expands data visibility or API path permissions once the rule is bound to a role, or immediately if modifying an already-bound scope

- Attack precondition: admin with access to data/API scope management endpoints
- Affected endpoint: `POST /user/save-user, POST /user/user-auth-info, POST /role/grant, GET /user/detail, GET /user/user-list, GET /tenant/page`
- Affected authorization property: `DataScope.menuId, DataScope.scopeColumn, DataScope.scopeValue, ApiScope.menuId, ApiScope.scopePath, @PreAuth(HAS_ROLE_ADMIN)`
- Security impact: expands data visibility or API path permissions once the rule is bound to a role, or immediately if modifying an already-bound scope

### 1.2 Exploit path

attacker creates or modifies authorization rule objects directly through `/data-scope/save`, `/data-scope/update`, `/data-scope/submit`, `/api-scope/save`, `/api-scope/update`, or `/api-scope/submit`

### 1.3 Key code evidence

1. `blade-service/blade-system/src/main/java/org/springblade/system/controller/DataScopeController.java`

Evidence location: https://github.com/chillzhuang/SpringBlade/blob/master/blade-service/blade-system/src/main/java/org/springblade/system/controller/DataScopeController.java#L82

```text
   79  	@ApiOperationSupport(order = 3)
   80  	@Operation(summary = "[non-English text removed]", description = "[non-English text removed]dataScope")
   81  	public R save(@Valid @RequestBody DataScope dataScope) {
   82  		CacheUtil.clear(SYS_CACHE);
   83  		return R.status(dataScopeService.save(dataScope));
   84  	}
   85
```

2. `blade-service/blade-system/src/main/java/org/springblade/system/controller/DataScopeController.java`

Evidence location: https://github.com/chillzhuang/SpringBlade/blob/master/blade-service/blade-system/src/main/java/org/springblade/system/controller/DataScopeController.java#L93

```text
   90  	@ApiOperationSupport(order = 4)
   91  	@Operation(summary = "[non-English text removed]", description = "[non-English text removed]dataScope")
   92  	public R update(@Valid @RequestBody DataScope dataScope) {
   93  		CacheUtil.clear(SYS_CACHE);
   94  		return R.status(dataScopeService.updateById(dataScope));
   95  	}
   96
```

3. `blade-service/blade-system/src/main/java/org/springblade/system/controller/DataScopeController.java`

Evidence location: https://github.com/chillzhuang/SpringBlade/blob/master/blade-service/blade-system/src/main/java/org/springblade/system/controller/DataScopeController.java#L104

```text
  101  	@ApiOperationSupport(order = 5)
  102  	@Operation(summary = "[non-English text removed]", description = "[non-English text removed]dataScope")
  103  	public R submit(@Valid @RequestBody DataScope dataScope) {
  104  		CacheUtil.clear(SYS_CACHE);
  105  		return R.status(dataScopeService.saveOrUpdate(dataScope));
  106  	}
  107
```

4. `blade-service/blade-system/src/main/java/org/springblade/system/controller/ApiScopeController.java`

Evidence location: https://github.com/chillzhuang/SpringBlade/blob/master/blade-service/blade-system/src/main/java/org/springblade/system/controller/ApiScopeController.java#L81

```text
   78  	@ApiOperationSupport(order = 3)
   79  	@Operation(summary = "[non-English text removed]", description = "[non-English text removed]dataScope")
   80  	public R save(@Valid @RequestBody ApiScope dataScope) {
   81  		CacheUtil.clear(SYS_CACHE);
   82  		return R.status(apiScopeService.save(dataScope));
   83  	}
   84
```

5. `blade-service-api/blade-scope-api/src/main/java/org/springblade/system/handler/DataScopeModelHandler.java`

Evidence location: https://github.com/chillzhuang/SpringBlade/blob/master/blade-service-api/blade-scope-api/src/main/java/org/springblade/system/handler/DataScopeModelHandler.java#L39

```text
   36  	 * @return DataScopeModel
   37  	 */
   38  	@Override
   39  	public DataScopeModel getDataScopeByMapper(String mapperId, String roleId) {
   40  		return DataScopeCache.getDataScopeByMapper(mapperId, roleId);
   41  	}
   42
```

6. `blade-service-api/blade-scope-api/src/main/java/org/springblade/system/handler/ApiScopePermissionHandler.java`

Evidence location: https://github.com/chillzhuang/SpringBlade/blob/master/blade-service-api/blade-scope-api/src/main/java/org/springblade/system/handler/ApiScopePermissionHandler.java#L44

```text
   41  			return false;
   42  		}
   43  		String uri = request.getRequestURI();
   44  		List<String> paths = permissionPath(user.getRoleId());
   45  		if (paths == null || paths.isEmpty()) {
   46  			return false;
   47  		}
```


## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

validate scope `menuId/resourceCode/path/column/value` against current operator's manageable resources. For non-administrator users, prevent creating or editing scopes outside their existing grantable menu/resource set; restrict scope fields to approved whitelists

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/SpringBlade/issue8.html
