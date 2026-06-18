---
title: "jeesite5 issue5: empUser/listData?isAll=true 员工数据枚举"
description: "jeesite5 has a missing authorization vulnerability: empUser/listData?isAll=true 员工数据枚举. 攻击者可绕过员工数据范围限制，枚举员工及其组织归属等权限边界信息。"
tags:
  - jeesite5
  - 漏洞报告
  - 越权
  - 访问控制
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

jeesite5 has a missing authorization vulnerability: empUser/listData?isAll=true 员工数据枚举. 攻击者可绕过员工数据范围限制，枚举员工及其组织归属等权限边界信息。

- Attack precondition: 任意登录用户；默认配置 `strictMode=false`。
- Security impact: 攻击者可绕过员工数据范围限制，枚举员工及其组织归属等权限边界信息。

### 1.2 Exploit path

- 登录用户访问 `listData` 并传入 `isAll=true`。

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
  115  								  @Parameter(description = "查询全部数据") @RequestParam(required = false) Boolean isAll,
  116  								  @Parameter(description = "数据控制权限") @RequestParam(required = false) String ctrlPermi,
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
  130  	public String form(EmpUser empUser, @Parameter(description = "操作类型") String op, Model model) {
  131  		
  132  		Employee employee = empUser.getEmployee();
  133  		
  134  		// 设置默认的部门
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
   66  	 * 获取单条数据
   67  	 */
   68  	@Override
   69  	public EmpUser get(EmpUser empUser) {
   70  		return super.get(empUser);
   71  	}
   72  	
   73  	/**
   74  	 * 添加数据权限过滤条件
   75  	 * @param empUser 控制对象
   76  	 * @param ctrlPermi 控制权限类型（拥有的数据权限：DataScope.CTRL_PERMI_HAVE、可管理的数据权限：DataScope.CTRL_PERMI_HAVE）
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
  747    # 静态资源路径前缀，可做 CDN 加速优化，默认前面增加 ctxPath 前缀，如果前面写 “//” 两个斜杠 或 包含 “://” 不加 ctxPath。
  748    staticPrefix: /static
  749    
  750    # 严格模式（更严格的数据安全验证）
  751    strictMode: false
  752  
  753    # 所有请求信息将进行xss过滤，这里列出不被xss过滤的地址
  754    xssFilterExcludeUri: /ureport/,/visual/
```


## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

普通请求永远应用员工 data scope；`isAll` 只能由服务端可信调用或高权限管理员使用。

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/jeesite5/issue5.html
