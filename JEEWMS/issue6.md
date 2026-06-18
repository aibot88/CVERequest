---
title: "JEEWMS issue6: `/rest/tmsYwDingdanController` 运输订单 REST CRUD 缺少组织 scope"
description: "JEEWMS has a missing authorization vulnerability: `/rest/tmsYwDingdanController` 运输订单 REST CRUD 缺少组织 scope. 可绕过正常页面列表的组织范围过滤，跨组织读取或篡改运输订单；`sysOrgCode` 是该业务对象的数据归属边界字段。"
tags:
  - JEEWMS
  - 漏洞报告
  - 越权
  - 访问控制
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

JEEWMS has a missing authorization vulnerability: `/rest/tmsYwDingdanController` 运输订单 REST CRUD 缺少组织 scope. 可绕过正常页面列表的组织范围过滤，跨组织读取或篡改运输订单；`sysOrgCode` 是该业务对象的数据归属边界字段。

- Attack precondition: 攻击者能访问 `/rest/tmsYwDingdanController` REST API。
- Security impact: 可绕过正常页面列表的组织范围过滤，跨组织读取或篡改运输订单；`sysOrgCode` 是该业务对象的数据归属边界字段。

### 1.2 Exploit path

通过 REST GET/POST/PUT/DELETE 读取、创建、修改、删除运输订单，或在请求体中写入 `sysOrgCode`。

### 1.3 Key code evidence

1. `src/main/java/com/zzjee/tms/controller/TmsYwDingdanController.java`

Evidence location: https://gitee.com/erzhongxmu/JEEWMS/blob/master/src/main/java/com/zzjee/tms/controller/TmsYwDingdanController.java#L150

```text
  147  	 * @param dataGrid
  148  	 */
  149  
  150  	@RequestMapping(params = "datagrid")
  151  	public void datagrid(TmsYwDingdanEntity tmsYwDingdan, HttpServletRequest request, HttpServletResponse response, DataGrid dataGrid) {
  152  		CriteriaQuery cq = new CriteriaQuery(TmsYwDingdanEntity.class, dataGrid);
  153  		//查询条件组装器
  154  		org.jeecgframework.core.extend.hqlsearch.HqlGenerateUtil.installHql(cq, tmsYwDingdan, request.getParameterMap());
  155  		try{
  156  		//自定义追加查询条件
  157  		String query_sdsj_begin = request.getParameter("sdsj_begin");
  158  		String query_sdsj_end = request.getParameter("sdsj_end");
  159  		if(StringUtil.isNotEmpty(query_sdsj_begin)){
  160  			cq.ge("sdsj", Integer.parseInt(query_sdsj_begin));
  161  		}
  162  		if(StringUtil.isNotEmpty(query_sdsj_end)){
  163  			cq.le("sdsj", Integer.parseInt(query_sdsj_end));
  164  		}
  165  		}catch (Exception e) {
  166  			// 抛出异常信息
  167  			throw new BusinessException(e.getMessage());
  168  		}
  169  		TSUser user = ResourceUtil.getSessionUser();
  170  		if(!StringUtil.isEmpty(user.getCurrentDepart().getOrgCode())){
  171  			cq.like("sysOrgCode",user.getCurrentDepart().getOrgCode()+"%");
  172  
  173  		}
  174  		cq.eq("zhuangtai","已下单");
  175  		cq.add();
  176  		this.tmsYwDingdanService.getDataGridReturn(cq, true);
  177  		TagUtil.datagrid(response, dataGrid);
  178  	}
  179  
  180  
```

2. `jeewms-cloud/java/base-cloud-module/base-cloud-busin/src/main/java/com/base/modules/jeewms/controller/TmsYwDingdanController.java`

Evidence location: https://gitee.com/erzhongxmu/JEEWMS/blob/master/jeewms-cloud/java/base-cloud-module/base-cloud-busin/src/main/java/com/base/modules/jeewms/controller/TmsYwDingdanController.java#L1074
3. `TmsYwDingdanEntity.c`

Evidence location: https://gitee.com/erzhongxmu/JEEWMS/blob/master/TmsYwDingdanEntity.c
4. `jeewms-cloud/java/base-cloud-module/base-cloud-busin/src/main/java/com/base/modules/jeewms/controller/TmsYwDingdanController.java`

Evidence location: https://gitee.com/erzhongxmu/JEEWMS/blob/master/jeewms-cloud/java/base-cloud-module/base-cloud-busin/src/main/java/com/base/modules/jeewms/controller/TmsYwDingdanController.java#L1093
5. `jeewms-cloud/java/base-cloud-module/base-cloud-busin/src/main/java/com/base/modules/jeewms/controller/TmsYwDingdanController.java`

Evidence location: https://gitee.com/erzhongxmu/JEEWMS/blob/master/jeewms-cloud/java/base-cloud-module/base-cloud-busin/src/main/java/com/base/modules/jeewms/controller/TmsYwDingdanController.java#L1113
6. `jeewms-cloud/java/base-cloud-module/base-cloud-busin/src/main/java/com/base/modules/jeewms/controller/TmsYwDingdanController.java`

Evidence location: https://gitee.com/erzhongxmu/JEEWMS/blob/master/jeewms-cloud/java/base-cloud-module/base-cloud-busin/src/main/java/com/base/modules/jeewms/controller/TmsYwDingdanController.java#L1135
7. `security-reports/pure_fix_code/src/main/java/org/jeecgframework/core/interceptors/AuthInterceptor.java`

Evidence location: https://gitee.com/erzhongxmu/JEEWMS/blob/master/security-reports/pure_fix_code/src/main/java/org/jeecgframework/core/interceptors/AuthInterceptor.java#L95

```text
   92          } else if (moHuContain(excludeContainUrls, requestPath)) {
   93              return true;
   94          } else {
   95              // 步骤二： 权限控制，优先重组请求 URL（考虑 online 请求前缀一致问题）
   96              String clickFunctionId = request.getParameter("clickFunctionId");
   97              Client client = ClientManager.getInstance().getClient(ContextHolderUtils.getSession().getId());
   98              TSUser currLoginUser = client != null ? client.getUser() : null;
   99              if (client != null && currLoginUser != null) {
```


## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

REST 入口强制认证并复用相同组织 scope；创建/更新时由服务端写入当前用户组织，禁止客户端提交 `sysOrgCode`；查询和删除必须按当前用户组织过滤目标记录。

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/JEEWMS/issue6.html
