---
title: "jeesite5 issue7: company/office/treeData?isAll=true /"
description: "jeesite5 has a missing authorization vulnerability in GET/POST ${adminPath}/sys/company/treeData?isAll=true, GET/POST ${adminPath}/sys/office/treeData?isAll=true, isLoadUser=true/lazy, EmpUser.userCode/loginCode/userName, office/treeData, company/listData. An authenticated attacker can perform authorization-sensitive operations through GET/POST ${adminPath}/sys/company/treeData?isAll=true, GET/POST ${adminPath}/sys/office/treeData?isAll=true, isLoadUser=true/lazy, EmpUser.userCode/loginCode/userName, office/treeData, company/listData without the required permission."
tags:
  - jeesite5
  - vulnerability-report
  - authorization
  - access-control
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

jeesite5 has a missing authorization vulnerability in GET/POST ${adminPath}/sys/company/treeData?isAll=true, GET/POST ${adminPath}/sys/office/treeData?isAll=true, isLoadUser=true/lazy, EmpUser.userCode/loginCode/userName, office/treeData, company/listData. An authenticated attacker can perform authorization-sensitive operations through GET/POST ${adminPath}/sys/company/treeData?isAll=true, GET/POST ${adminPath}/sys/office/treeData?isAll=true, isLoadUser=true/lazy, EmpUser.userCode/loginCode/userName, office/treeData, company/listData without the required permission.

- Attack precondition: Any authenticated user
- Affected endpoint: `GET/POST ${adminPath}/sys/company/treeData?isAll=true, GET/POST ${adminPath}/sys/office/treeData?isAll=true, isLoadUser=true/lazy, EmpUser.userCode/loginCode/userName, office/treeData, company/listData`
- Affected authorization property: `strictMode=false, Company.companyCode, id, Company.viewCode, Company.fullName, Office.officeCode`
- Security impact: An authenticated attacker can perform authorization-sensitive operations through GET/POST ${adminPath}/sys/company/treeData?isAll=true, GET/POST ${adminPath}/sys/office/treeData?isAll=true, isLoadUser=true/lazy, EmpUser.userCode/loginCode/userName, office/treeData, company/listData without the required permission.

### 1.2 Exploit path

The attacker sends crafted requests to GET/POST ${adminPath}/sys/company/treeData?isAll=true, GET/POST ${adminPath}/sys/office/treeData?isAll=true, isLoadUser=true/lazy, EmpUser.userCode/loginCode/userName, office/treeData, company/listData with target identifiers or authorization-sensitive fields that should be rejected.

### 1.3 Key code evidence

1. `Company.c`

Evidence location: https://gitee.com/thinkgem/jeesite5/blob/master/Company.c
2. `modules/core/src/main/java/com/jeesite/modules/sys/web/CompanyController.java`

Evidence location: https://gitee.com/thinkgem/jeesite5/blob/master/modules/core/src/main/java/com/jeesite/modules/sys/web/CompanyController.java#L234

```text
  231  	 * @param isShowCode [non-English text removed](true or 1:[non-English text removed];2:[non-English text removed];false or null:[non-English text removed])
  232  	 * @param isShowFullName [non-English text removed]
  233  	 */
  234  	@RequiresPermissions("user")
  235  	@RequestMapping(value = "treeData")
  236  	@ResponseBody
  237  	public List<Map<String, Object>> treeData(String excludeCode, String parentCode, Boolean isAll, String isShowCode,
  238  			String isShowFullName, String ctrlPermi) {
  239  		List<Map<String, Object>> mapList = ListUtils.newArrayList();
  240  		Company where = new Company();
  241  		where.setStatus(Company.STATUS_NORMAL);
  242  		if (StringUtils.isNotBlank(parentCode)){
  243  			where.setParentCode(parentCode);
  244  		}
  245  		if (!(isAll != null && isAll) || Global.isStrictMode()){
  246  			companyService.addDataScopeFilter(where, ctrlPermi);
  247  		}
  248  		List<Company> list = companyService.findList(where);
  249  		for (int i = 0; i < list.size(); i++) {
  250  			Company e = list.get(i);
  251  			// [non-English text removed]
  252  			if (!Company.STATUS_NORMAL.equals(e.getStatus())){
  253  				continue;
  254  			}
  255  			// [non-English text removed]([non-English text removed])
  256  			if (StringUtils.isNotBlank(excludeCode)){
  257  				if (e.getId().equals(excludeCode)){
  258  					continue;
  259  				}
  260  				if (e.getParentCodes().contains("," + excludeCode + ",")){
  261  					continue;
  262  				}
  263  			}
  264  			Map<String, Object> map = MapUtils.newHashMap();
  265  			map.put("id", e.getId());
  266  			map.put("pId", e.getParentCode());
  267  			String name = e.getCompanyName();
  268  			if ("true".equals(isShowFullName) || "1".equals(isShowFullName)){
  269  				name = e.getFullName();
  270  			}
  271  			map.put("code", e.getViewCode());
  272  			map.put("name", StringUtils.getTreeNodeName(isShowCode, e.getViewCode(), name));
  273  			map.put("title", e.getFullName());
  274  			map.put("isParent", !e.getIsTreeLeaf());
  275  			mapList.add(map);
  276  		}
  277  		return mapList;
  278  	}
  279
  280  	@RequiresPermissions("sys:company:edit")
```

3. `modules/core/src/main/java/com/jeesite/modules/sys/web/OfficeController.java`

Evidence location: https://gitee.com/thinkgem/jeesite5/blob/master/modules/core/src/main/java/com/jeesite/modules/sys/web/OfficeController.java#L294

```text
  291  	 * @param postCode		[non-English text removed]
  292  	 * @param roleCode		[non-English text removed]
  293  	 */
  294  	@RequiresPermissions("user")
  295  	@RequestMapping(value = "treeData")
  296  	@ResponseBody
  297  	public List<Map<String, Object>> treeData(String excludeCode, String parentCode, Boolean isAll,
  298  			String officeTypes, String companyCode, String isShowCode, String isShowFullName,
  299  			String isLoadUser, String userIdPrefix, String postCode, String roleCode, String ctrlPermi) {
  300  		List<Map<String, Object>> mapList = ListUtils.newArrayList();
  301  		Office where = new Office();
  302  		where.setStatus(Office.STATUS_NORMAL);
  303  		where.setCompanyCode(companyCode);
  304  		if (!(isAll != null && isAll) || Global.isStrictMode()){
  305  			officeService.addDataScopeFilter(where, ctrlPermi);
  306  		}
  307  		// [non-English text removed]
  308  		if (StringUtils.isNotBlank(parentCode)){
  309  			where.setParentCode(parentCode);
  310  		}
  311  		// [non-English text removed]
  312  		if (StringUtils.isNotBlank(officeTypes)){
  313  			where.setOfficeType_in(officeTypes.split(","));
  314  		}
  315  		List<String> idList = ListUtils.newArrayList();
  316  		List<Office> list = officeService.findList(where);
  317  		for (int i = 0; i < list.size(); i++) {
  318  			Office e = list.get(i);
  319  			// [non-English text removed]
  320  			if (!Office.STATUS_NORMAL.equals(e.getStatus())){
  321  				continue;
  322  			}
  323  			// [non-English text removed]([non-English text removed])
  324  			if (StringUtils.isNotBlank(excludeCode)){
  325  				if (e.getId().equals(excludeCode)){
  326  					continue;
  327  				}
  328  				if (e.getParentCodes().contains("," + excludeCode + ",")){
  329  					continue;
  330  				}
  331  			}
  332  			idList.add(e.getId());
  333  			Map<String, Object> map = MapUtils.newHashMap();
  334  			map.put("id", e.getId());
  335  			map.put("pId", e.getParentCode());
  336  			String name = e.getOfficeName();
  337  			if ("true".equals(isShowFullName) || "1".equals(isShowFullName)){
  338  				name = e.getFullName();
  339  			}
  340  			map.put("code", e.getViewCode());
  341  			map.put("name", StringUtils.getTreeNodeName(isShowCode, e.getViewCode(), name));
  342  			map.put("title", e.getFullName());
  343  			// [non-English text removed],[non-English text removed],[non-English text removed],[non-English text removed]
  344  			map.put("isParent", !e.getIsTreeLeaf() || StringUtils.inString(isLoadUser, "true", "lazy"));
  345  			mapList.add(map);
  346  		}
  347  		// [non-English text removed],[non-English text removed],[non-English text removed]
  348  		if (StringUtils.equals(isLoadUser, "true") && !idList.isEmpty()) {
  349  			List<Map<String, Object>> userList =
  350  				empUserController.treeData(userIdPrefix, idList.toArray(new String[0]),
  351  						companyCode, postCode, roleCode, isAll, isShowCode, ctrlPermi);
  352  			mapList.addAll(userList);
  353  		}
  354  		// [non-English text removed],[non-English text removed]([non-English text removed],[non-English text removed],[non-English text removed] listselect [non-English text removed])
  355  		if (StringUtils.inString(isLoadUser, "lazy") && StringUtils.isNotBlank(parentCode)) {
  356  			List<Map<String, Object>> userList =
  357  					empUserController.treeData(userIdPrefix, new String[]{parentCode},
  358  							companyCode, postCode, roleCode, isAll, isShowCode, ctrlPermi);
  359  			mapList.addAll(userList);
  360  		}
  361  		return mapList;
  362  	}
  363
  364  	@RequiresPermissions("sys:office:edit")
```

4. `modules/core/src/main/java/com/jeesite/modules/sys/web/user/EmpUserController.java`

Evidence location: https://gitee.com/thinkgem/jeesite5/blob/master/modules/core/src/main/java/com/jeesite/modules/sys/web/user/EmpUserController.java#L418

```text
  415  			employee.getOffice().setOfficeCode(officeCode[0]);
  416  		}else {
  417  			employee.getOffice().setId_in(officeCode);
  418  		}
  419  		employee.getOffice().setIsQueryChildren(false);
  420  		employee.getCompany().setCompanyCode(companyCode);
  421  		employee.getCompany().setIsQueryChildren(false);
  422  		employee.setPostCode(postCode);
  423  		empUser.setRoleCode(roleCode);
  424  		empUser.setStatus(User.STATUS_NORMAL);
  425  		empUser.setUserType(User.USER_TYPE_EMPLOYEE);
  426  		if (!(isAll != null && isAll) || Global.isStrictMode()) {
  427  			empUserService.addDataScopeFilter(empUser, ctrlPermi);
  428  		}
  429  		List<EmpUser> list = empUserService.findList(empUser);
  430  		for (int i = 0; i < list.size(); i++) {
  431  			EmpUser e = list.get(i);
  432  			Map<String, Object> map = MapUtils.newHashMap();
  433  			map.put("id", ObjectUtils.defaultIfNull(idPrefix, "u_") + e.getId());
  434  			map.put("pId", StringUtils.defaultIfBlank(e.getEmployee().getOffice().getOfficeCode(), "0"));
  435  			map.put("name", StringUtils.getTreeNodeName(isShowCode, e.getLoginCode(), e.getUserName()));
  436  			mapList.add(map);
  437  		}
  438  		return mapList;
  439  	}
  440
  441  	/**
  442  	 * [non-English text removed]
  443  	 */
  444  	@RequiresPermissions("user")
  445  	@RequestMapping(value = "empUserSelect")
  446  	public String empUserSelect(EmpUser empUser, String selectData, Model model) {
  447  		String selectDataJson = EncodeUtils.decodeUrl(selectData);
  448  		if (selectDataJson != null && JSONValidator.from(selectDataJson).validate()){
  449  			model.addAttribute("selectData", selectDataJson);
  450  		}
  451  		// [non-English text removed]
  452  //		Role role = new Role();
  453  //		role.setUserType(User.USER_TYPE_MEMBER);
  454  //		model.addAttribute("roleList", roleService.findList(role));
```

5. `modules/core/src/main/java/com/jeesite/modules/sys/service/support/CompanyServiceSupport.java`

Evidence location: https://gitee.com/thinkgem/jeesite5/blob/master/modules/core/src/main/java/com/jeesite/modules/sys/service/support/CompanyServiceSupport.java#L56

```text
   53  	 * [non-English text removed]
   54  	 */
   55  	@Override
   56  	public void addDataScopeFilter(Company company, String ctrlPermi) {
   57  		company.sqlMap().getDataScope().addFilter("dsf", "Company", "a.company_code",
   58  				null, ctrlPermi, "office_user");
   59  	}
   60
   61  	/**
```

6. `modules/core/src/main/java/com/jeesite/modules/sys/service/support/OfficeServiceSupport.java`

Evidence location: https://gitee.com/thinkgem/jeesite5/blob/master/modules/core/src/main/java/com/jeesite/modules/sys/service/support/OfficeServiceSupport.java#L57

```text
   54  	 * [non-English text removed]
   55  	 */
   56  	@Override
   57  	public void addDataScopeFilter(Office office, String ctrlPermi) {
   58  		office.sqlMap().getDataScope().addFilter("dsf", "Office", "a.office_code",
   59  				null, ctrlPermi , "office_user");
   60  //		office.sqlMap().getDataScope().addFilterByPermission("dsf", "sys:empUser:view",
   61  //				"Office", "a.office_code", ctrlPermi);
   62  	}
```

7. `RoleUtils.h`

Evidence location: https://gitee.com/thinkgem/jeesite5/blob/master/RoleUtils.h

## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

Enforce server-side authorization for GET/POST ${adminPath}/sys/company/treeData?isAll=true, GET/POST ${adminPath}/sys/office/treeData?isAll=true, isLoadUser=true/lazy, EmpUser.userCode/loginCode/userName, office/treeData, company/listData before reading or writing target objects, roles, permissions, ownership, tenant, organization, or grant-bound state.

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/jeesite5/issue7.html
