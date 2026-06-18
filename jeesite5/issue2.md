---
title: "jeesite5 issue2: empUser/importData"
description: "jeesite5 has a missing authorization vulnerability in POST ${adminPath}/sys/empUser/importData, /, OfficeType/CompanyType. An authenticated attacker can perform authorization-sensitive operations through POST ${adminPath}/sys/empUser/importData, /, OfficeType/CompanyType without the required permission."
tags:
  - jeesite5
  - vulnerability-report
  - authorization
  - access-control
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

jeesite5 has a missing authorization vulnerability in POST ${adminPath}/sys/empUser/importData, /, OfficeType/CompanyType. An authenticated attacker can perform authorization-sensitive operations through POST ${adminPath}/sys/empUser/importData, /, OfficeType/CompanyType without the required permission.

- Attack precondition: Any authenticated user
- Affected endpoint: `POST ${adminPath}/sys/empUser/importData, /, OfficeType/CompanyType`
- Affected authorization property: `sys:empUser:edit, EmpUser.employee.office, EmpUser.employee.company, sys_employee.office_code, sys_employee.company_code, EmpUserController.importData()`
- Security impact: An authenticated attacker can perform authorization-sensitive operations through POST ${adminPath}/sys/empUser/importData, /, OfficeType/CompanyType without the required permission.

### 1.2 Exploit path

The attacker sends crafted requests to POST ${adminPath}/sys/empUser/importData, /, OfficeType/CompanyType with target identifiers or authorization-sensitive fields that should be rejected.

### 1.3 Key code evidence

1. `EmpUser.employee.c`

Evidence location: https://gitee.com/thinkgem/jeesite5/blob/master/EmpUser.employee.c
2. `sys_employee.c`

Evidence location: https://gitee.com/thinkgem/jeesite5/blob/master/sys_employee.c
3. `EmpUser.c`

Evidence location: https://gitee.com/thinkgem/jeesite5/blob/master/EmpUser.c
4. `modules/core/src/main/java/com/jeesite/modules/sys/web/user/EmpUserController.java`

Evidence location: https://gitee.com/thinkgem/jeesite5/blob/master/modules/core/src/main/java/com/jeesite/modules/sys/web/user/EmpUserController.java#L277

```text
  274  			String message = empUserService.importData(file, isUpdateSupport);
  275  			return renderResult(Global.TRUE, "posfull:"+message);
  276  		} catch (Exception ex) {
  277  			return renderResult(Global.FALSE, "posfull:"+ex.getMessage());
  278  		}
  279  	}
  280
  281  	/**
  282  	 * [non-English text removed]
  283  	 */
  284  	@RequiresPermissions("sys:empUser:updateStatus")
  285  	@ResponseBody
  286  	@RequestMapping(value = "disable")
```

5. `modules/core/src/main/java/com/jeesite/modules/sys/service/support/EmpUserServiceSupport.java`

Evidence location: https://gitee.com/thinkgem/jeesite5/blob/master/modules/core/src/main/java/com/jeesite/modules/sys/service/support/EmpUserServiceSupport.java#L214

```text
  211  		return dao.findUserListByRoleCodes(empUser);
  212  	}
  213
  214  	/**
  215  	 * [non-English text removed],[non-English text removed]
  216  	 */
  217  	@Override
  218  	public List<EmpUser> findUserListByPostCodes(EmpUser empUser){
  219  		return dao.findUserListByPostCodes(empUser);
  220  	}
  221
  222  	/**
  223  	 * [non-English text removed]
  224  	 */
  225  	@Override
  226  	@Transactional
  227  	public void save(EmpUser user) {
  228  		// 1,[non-English text removed]
  229  		if (user.getIsNewRecord()){
  230  			// [non-English text removed],[non-English text removed]
  231  			if (StringUtils.isBlank(user.getUserCode())){
  232  				userService.genId(user, user.getLoginCode());
  233  				user.setUserCode(user.getUserCode()+"_"+IdGen.randomShortString());
  234  			}
  235  			user.setUserType(EmpUser.USER_TYPE_EMPLOYEE);
  236  			user.setMgrType(EmpUser.MGR_TYPE_NOT_ADMIN);
  237  		}
  238  		Employee employee = user.getEmployee();
  239  		// [non-English text removed],[non-English text removed]
  240  		if (StringUtils.isBlank(employee.getEmpCode())){
```

6. `modules/core/src/main/java/com/jeesite/modules/sys/entity/EmpUser.java`

Evidence location: https://gitee.com/thinkgem/jeesite5/blob/master/modules/core/src/main/java/com/jeesite/modules/sys/entity/EmpUser.java#L94

```text
   91
   92  	private String[] codes; // [non-English text removed]
   93
   94  	@ExcelFields({
   95  		@ExcelField(title="[non-English text removed]", attrName="employee.office", align=Align.CENTER, sort=10, fieldType=OfficeType.class),
   96  		@ExcelField(title="[non-English text removed]", attrName="employee.company", align = Align.CENTER, sort=20, fieldType=CompanyType.class),
   97  		@ExcelField(title="[non-English text removed]", attrName="loginCode", align=Align.CENTER, sort=30),
   98  		@ExcelField(title="[non-English text removed]", attrName="userName", align=Align.CENTER, sort=40),
   99  		@ExcelField(title="[non-English text removed]", attrName="email", align=Align.LEFT, sort=50),
  100  		@ExcelField(title="[non-English text removed]", attrName="mobile", align=Align.CENTER, sort=60),
  101  		@ExcelField(title="[non-English text removed]", attrName="phone", align=Align.CENTER, sort=70),
  102  		@ExcelField(title="[non-English text removed]", attrName="sex", dictType="sys_user_sex", align=Align.CENTER, words=10, sort=75),
  103  		@ExcelField(title="[non-English text removed]", attrName="employee.empCode", align=Align.CENTER, sort=80),
  104  		@ExcelField(title="[non-English text removed]", attrName="employee.empName", align=Align.CENTER, sort=95),
  105  		@ExcelField(title="[non-English text removed]", attrName="userRoleString", align=Align.LEFT, sort=800, type=ExcelField.Type.IMPORT),
  106  		@ExcelField(title="[non-English text removed]", attrName="createDate", align=Align.CENTER, words=15, sort=900, type=ExcelField.Type.EXPORT, dataFormat="yyyy-MM-dd"),
  107  		@ExcelField(title="[non-English text removed]", attrName="lastLoginDate", align=Align.CENTER, words=20, sort=900, type=ExcelField.Type.EXPORT),
  108  	})
```

7. `modules/core/src/main/java/com/jeesite/common/utils/excel/fieldtype/OfficeType.java`

Evidence location: https://gitee.com/thinkgem/jeesite5/blob/master/modules/core/src/main/java/com/jeesite/common/utils/excel/fieldtype/OfficeType.java#L23

```text
   20
   21  	private final List<Office> list;
   22
   23  	public OfficeType() {
   24  		list = EmpUtils.getOfficeAllList();
   25  	}
   26
   27  	/**
   28  	 * [non-English text removed]([non-English text removed])
   29  	 */
   30  	@Override
   31  	public Object getValue(String val) {
   32  		for (Office e : list){
   33  			if (StringUtils.trimToEmpty(val).equals(e.getOfficeName())){
   34  				return e;
   35  			}
   36  		}
   37  		return null;
   38  	}
   39
   40  	/**
```

8. `modules/core/src/main/java/com/jeesite/common/utils/excel/fieldtype/CompanyType.java`

Evidence location: https://gitee.com/thinkgem/jeesite5/blob/master/modules/core/src/main/java/com/jeesite/common/utils/excel/fieldtype/CompanyType.java#L23

```text
   20
   21  	private final List<Company> list;
   22
   23  	public CompanyType() {
   24  		list = EmpUtils.getCompanyAllList();
   25  	}
   26
   27  	/**
   28  	 * [non-English text removed]([non-English text removed])
   29  	 */
   30  	@Override
   31  	public Object getValue(String val) {
   32  		for (Company e : list){
   33  			if (StringUtils.trimToEmpty(val).equals(e.getCompanyName())){
   34  				return e;
   35  			}
   36  		}
   37  		return null;
   38  	}
   39
   40  	/**
```


## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

Enforce server-side authorization for POST ${adminPath}/sys/empUser/importData, /, OfficeType/CompanyType before reading or writing target objects, roles, permissions, ownership, tenant, organization, or grant-bound state.

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/jeesite5/issue2.html
