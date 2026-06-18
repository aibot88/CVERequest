---
title: "jeesite5 issue5: empUser/listData?isAll=true"
description: "jeesite5 has a missing authorization vulnerability in GET/POST ${adminPath}/sys/empUser/listData?isAll=true. An authenticated attacker can perform authorization-sensitive operations through GET/POST ${adminPath}/sys/empUser/listData?isAll=true without the required permission."
tags:
  - jeesite5
  - vulnerability-report
  - authorization
  - access-control
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

jeesite5 has a missing authorization vulnerability in GET/POST ${adminPath}/sys/empUser/listData?isAll=true. An authenticated attacker can perform authorization-sensitive operations through GET/POST ${adminPath}/sys/empUser/listData?isAll=true without the required permission.

- Attack precondition: Any authenticated user
- Affected endpoint: `GET/POST ${adminPath}/sys/empUser/listData?isAll=true`
- Affected authorization property: `strictMode=false, EmpUser.userCode, EmpUser.employee.office.officeCode, EmpUser.employee.company.companyCode, EmpUser.roleCode, listData`
- Security impact: An authenticated attacker can perform authorization-sensitive operations through GET/POST ${adminPath}/sys/empUser/listData?isAll=true without the required permission.

### 1.2 Exploit path

The attacker sends crafted requests to GET/POST ${adminPath}/sys/empUser/listData?isAll=true with target identifiers or authorization-sensitive fields that should be rejected.

### 1.3 Key code evidence

1. `EmpUser.employee.company.c`

Evidence location: https://gitee.com/thinkgem/jeesite5/blob/master/EmpUser.employee.company.c
2. `modules/core/src/main/java/com/jeesite/modules/sys/web/user/EmpUserController.java`

Evidence location: https://gitee.com/thinkgem/jeesite5/blob/master/modules/core/src/main/java/com/jeesite/modules/sys/web/user/EmpUserController.java#L114

```text
  111  	@RequiresPermissions("user")
  112  	@RequestMapping(value = "listData")
  113  	@ResponseBody
  114  	public Page<EmpUser> listData(EmpUser empUser,
  115  								  @Parameter(description = "[non-English text removed]") @RequestParam(required = false) Boolean isAll,
  116  								  @Parameter(description = "[non-English text removed]") @RequestParam(required = false) String ctrlPermi,
  117  								  HttpServletRequest request, HttpServletResponse response) {
  118  		empUser.getEmployee().getOffice().setIsQueryChildren(true);
  119  		empUser.getEmployee().getCompany().setIsQueryChildren(true);
  120  		if (!(isAll != null && isAll) || Global.isStrictMode()){
  121  			empUserService.addDataScopeFilter(empUser, ctrlPermi);
  122  		}
  123  		empUser.setPage(new Page<>(request, response));
  124  		Page<EmpUser> page = empUserService.findPage(empUser);
  125  		return page;
  126  	}
  127
  128  	@RequiresPermissions("sys:empUser:view")
  129  	@RequestMapping(value = "form")
  130  	public String form(EmpUser empUser, @Parameter(description = "[non-English text removed]") String op, Model model) {
  131
  132  		Employee employee = empUser.getEmployee();
  133
  134  		// [non-English text removed]
  135  		if (StringUtils.isBlank(employee.getCompany().getCompanyCode())) {
  136  			employee.setCompany(EmpUtils.getCompany());
  137  		}
  138
```

3. `modules/core/src/main/java/com/jeesite/modules/sys/service/support/EmpUserServiceSupport.java`

Evidence location: https://gitee.com/thinkgem/jeesite5/blob/master/modules/core/src/main/java/com/jeesite/modules/sys/service/support/EmpUserServiceSupport.java#L65

```text
   62  		this.companyDao = companyDao;
   63  	}
   64
   65  	/**
   66  	 * [non-English text removed]
   67  	 */
   68  	@Override
   69  	public EmpUser get(EmpUser empUser) {
   70  		return super.get(empUser);
   71  	}
   72
   73  	/**
   74  	 * [non-English text removed]
   75  	 * @param empUser [non-English text removed]
   76  	 * @param ctrlPermi [non-English text removed]([non-English text removed]:DataScope.CTRL_PERMI_HAVE,[non-English text removed]:DataScope.CTRL_PERMI_HAVE)
   77  	 */
   78  	@Override
   79  	public void addDataScopeFilter(EmpUser empUser, String ctrlPermi) {
   80  		QueryDataScope dataScope = empUser.sqlMap().getDataScope();
   81  		dataScope.addFilter("dsfOffice", "Office",
   82  				"e.office_code", "a.create_by", ctrlPermi, "office_user");
   83  		if (StringUtils.isNotBlank(EmpUtils.getCompany().getCompanyCode())){
   84  			dataScope.addFilter("dsfCompany", "Company",
   85  					"e.company_code", "a.create_by", ctrlPermi, "office_user");
   86  		}
   87  //		dataScope.addFilterByPermission("dsfOffice", "sys:empUser:view", "Office",
   88  //				"e.office_code", "a.create_by", ctrlPermi);
   89  //		dataScope.addFilterByPermission("dsfOffice", "sys:empUser:view", "User",
   90  //				"a.user_code", ctrlPermi);
   91  	}
```

4. `modules/core/src/main/resources/config/jeesite-core.yml`

Evidence location: https://gitee.com/thinkgem/jeesite5/blob/master/modules/core/src/main/resources/config/jeesite-core.yml#L750

```text
  747    # [non-English text removed],[non-English text removed] CDN [non-English text removed],[non-English text removed] ctxPath [non-English text removed],[non-English text removed] "//" [non-English text removed] [non-English text removed] [non-English text removed] "://" [non-English text removed] ctxPath.
  748    staticPrefix: /static
  749
  750    # [non-English text removed]([non-English text removed])
  751    strictMode: false
  752
  753    # [non-English text removed]xss[non-English text removed],[non-English text removed]xss[non-English text removed]
  754    xssFilterExcludeUri: /ureport/,/visual/
```


## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

Enforce server-side authorization for GET/POST ${adminPath}/sys/empUser/listData?isAll=true before reading or writing target objects, roles, permissions, ownership, tenant, organization, or grant-bound state.

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/jeesite5/issue5.html
