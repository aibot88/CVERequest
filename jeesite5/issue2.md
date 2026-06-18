---
title: "jeesite5 issue2: empUser/importData 组织重绑定"
description: "jeesite5 has a missing authorization vulnerability: empUser/importData 组织重绑定. 攻击者可批量创建或更新员工的机构/公司归属，放大组织边界污染。"
tags:
  - jeesite5
  - 漏洞报告
  - 越权
  - 访问控制
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

jeesite5 has a missing authorization vulnerability: empUser/importData 组织重绑定. 攻击者可批量创建或更新员工的机构/公司归属，放大组织边界污染。

- Attack precondition: 攻击者拥有 `sys:empUser:edit` 和导入入口访问权。
- Security impact: 攻击者可批量创建或更新员工的机构/公司归属，放大组织边界污染。

### 1.2 Exploit path

- 上传 Excel 文件。

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
  282  	 * 停用用户
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
  215  	 * 根据岗位编码查询用户，仅返回基本信息
  216  	 */
  217  	@Override
  218  	public List<EmpUser> findUserListByPostCodes(EmpUser empUser){
  219  		return dao.findUserListByPostCodes(empUser);
  220  	}
  221  	
  222  	/**
  223  	 * 保存用户员工
  224  	 */
  225  	@Override
  226  	@Transactional
  227  	public void save(EmpUser user) {
  228  		// 1、初始化用户信息
  229  		if (user.getIsNewRecord()){
  230  			// 如果没有设置用户编码，则根据登录名生成一个
  231  			if (StringUtils.isBlank(user.getUserCode())){
  232  				userService.genId(user, user.getLoginCode());
  233  				user.setUserCode(user.getUserCode()+"_"+IdGen.randomShortString());
  234  			}
  235  			user.setUserType(EmpUser.USER_TYPE_EMPLOYEE);
  236  			user.setMgrType(EmpUser.MGR_TYPE_NOT_ADMIN);
  237  		}
  238  		Employee employee = user.getEmployee();
  239  		// 如果员工编码为空，则使用用户编码
  240  		if (StringUtils.isBlank(employee.getEmpCode())){
```

6. `modules/core/src/main/java/com/jeesite/modules/sys/entity/EmpUser.java`

Evidence location: https://gitee.com/thinkgem/jeesite5/blob/master/modules/core/src/main/java/com/jeesite/modules/sys/entity/EmpUser.java#L94

```text
   91  	
   92  	private String[] codes; // 查询用
   93  
   94  	@ExcelFields({
   95  		@ExcelField(title="归属机构", attrName="employee.office", align=Align.CENTER, sort=10, fieldType=OfficeType.class),
   96  		@ExcelField(title="归属公司", attrName="employee.company", align = Align.CENTER, sort=20, fieldType=CompanyType.class),
   97  		@ExcelField(title="登录账号", attrName="loginCode", align=Align.CENTER, sort=30),
   98  		@ExcelField(title="用户昵称", attrName="userName", align=Align.CENTER, sort=40),
   99  		@ExcelField(title="电子邮箱", attrName="email", align=Align.LEFT, sort=50),
  100  		@ExcelField(title="手机号码", attrName="mobile", align=Align.CENTER, sort=60),
  101  		@ExcelField(title="办公电话", attrName="phone", align=Align.CENTER, sort=70),
  102  		@ExcelField(title="性别", attrName="sex", dictType="sys_user_sex", align=Align.CENTER, words=10, sort=75),
  103  		@ExcelField(title="员工编码", attrName="employee.empCode", align=Align.CENTER, sort=80),
  104  		@ExcelField(title="员工姓名", attrName="employee.empName", align=Align.CENTER, sort=95),
  105  		@ExcelField(title="拥有角色编号", attrName="userRoleString", align=Align.LEFT, sort=800, type=ExcelField.Type.IMPORT),
  106  		@ExcelField(title="建档日期", attrName="createDate", align=Align.CENTER, words=15, sort=900, type=ExcelField.Type.EXPORT, dataFormat="yyyy-MM-dd"),
  107  		@ExcelField(title="最后登录", attrName="lastLoginDate", align=Align.CENTER, words=20, sort=900, type=ExcelField.Type.EXPORT),
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
   28  	 * 获取对象值（导入）
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
   28  	 * 获取对象值（导入）
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

导入每一行在 `save` 前校验目标 company/office 可管理；不合法则拒绝该行或整批失败。

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/jeesite5/issue2.html
