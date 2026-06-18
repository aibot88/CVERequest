---
title: "SpringBlade issue5: `GET /tenant/page`"
description: "SpringBlade has a missing authorization vulnerability in /tenant/page. cross-tenant enumeration and disclosure of tenant records and contact metadata"
tags:
  - SpringBlade
  - vulnerability-report
  - authorization
  - access-control
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

SpringBlade has a missing authorization vulnerability in /tenant/page. cross-tenant enumeration and disclosure of tenant records and contact metadata

- Attack precondition: tenant admin with `HAS_ROLE_ADMIN`
- Affected endpoint: `/tenant/page`
- Affected authorization property: `HAS_ROLE_ADMIN, tenant.tenantId, selectTenantPage, administrator, applyTenantScope, blade_tenant where is_deleted = 0`
- Security impact: cross-tenant enumeration and disclosure of tenant records and contact metadata

### 1.2 Exploit path

attacker calls `/tenant/page`; controller invokes `selectTenantPage`, whose mapper selects all non-deleted tenants

### 1.3 Key code evidence

1. `blade-service/blade-system/src/main/java/org/springblade/system/controller/TenantController.java`

Evidence location: https://github.com/chillzhuang/SpringBlade/blob/master/blade-service/blade-system/src/main/java/org/springblade/system/controller/TenantController.java#L95

```text
   92  	@Operation(summary = "[non-English text removed]", description = "[non-English text removed]tenant")
   93  	public R<List<Tenant>> select(Tenant tenant, BladeUser bladeUser) {
   94  		QueryWrapper<Tenant> queryWrapper = Condition.getQueryWrapper(tenant);
   95  		List<Tenant> list = tenantService.list((!bladeUser.getTenantId().equals(BladeConstant.ADMIN_TENANT_ID)) ? queryWrapper.lambda().eq(Tenant::getTenantId, bladeUser.getTenantId()) : queryWrapper);
   96  		return R.data(list);
   97  	}
   98
```

2. `blade-service/blade-system/src/main/java/org/springblade/system/service/impl/TenantServiceImpl.java`

Evidence location: https://github.com/chillzhuang/SpringBlade/blob/master/blade-service/blade-system/src/main/java/org/springblade/system/service/impl/TenantServiceImpl.java#L66

```text
   63  		return page.setRecords(baseMapper.selectTenantPage(page, tenant));
   64  	}
   65
   66  	@Override
   67  	public Tenant getByTenantId(String tenantId) {
   68  		return getOne(Wrappers.<Tenant>query().lambda().eq(Tenant::getTenantId, tenantId));
   69  	}
```

3. `blade-service/blade-system/src/main/java/org/springblade/system/service/impl/TenantServiceImpl.java`

Evidence location: https://github.com/chillzhuang/SpringBlade/blob/master/blade-service/blade-system/src/main/java/org/springblade/system/service/impl/TenantServiceImpl.java#L161
4. `blade-service/blade-system/src/main/java/org/springblade/system/mapper/TenantMapper.xml`

Evidence location: https://github.com/chillzhuang/SpringBlade/blob/master/blade-service/blade-system/src/main/java/org/springblade/system/mapper/TenantMapper.xml#L21

```text
   18      </resultMap>
   19
   20
   21      <select id="selectTenantPage" resultMap="tenantResultMap">
   22          select * from blade_tenant where is_deleted = 0
   23      </select>
   24
```


## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

make `/tenant/page` call scoped `selectPage` or apply the same `applyTenantScope` logic inside `selectTenantPage`

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/SpringBlade/issue5.html
