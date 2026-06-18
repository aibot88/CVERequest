---
title: "onedev issue4: Detector POST /projects forkedFromId 未校验源项目读权限"
description: "onedev has a missing authorization vulnerability: Detector POST /projects forkedFromId 未校验源项目读权限. 当前代码下不能用无权 source project id 直接 fork/copy 私有仓库内容。"
tags:
  - onedev
  - 漏洞报告
  - 越权
  - 访问控制
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

onedev has a missing authorization vulnerability: Detector POST /projects forkedFromId 未校验源项目读权限. 当前代码下不能用无权 source project id 直接 fork/copy 私有仓库内容。

- Attack precondition: detector 依赖“只检查目标项目创建权限，不检查 fork source 权限”的旧代码假设。
- Security impact: 当前代码下不能用无权 source project id 直接 fork/copy 私有仓库内容。

### 1.2 Exploit path

当前路径中 `forkedFromId` 被 load 后，在复制 settings / fork repo 之前会检查 source project `canReadCode`。

### 1.3 Key code evidence

1. `server-core/src/main/java/io/onedev/server/rest/resource/ProjectResource.java`

Evidence location: https://code.onedev.io/onedev/server/server-core/src/main/java/io/onedev/server/rest/resource/ProjectResource.java#L303

```text
  300  		checkProjectNameDuplication(project);		
  301  
  302  		if (project.getForkedFrom() != null) {
  303  			var forkedFrom = project.getForkedFrom();
  304  			project.getBuildSetting().setBuildPreservations(forkedFrom.getBuildSetting().getBuildPreservations());
  305  			project.getBuildSetting().setCachePreserveDays(forkedFrom.getBuildSetting().getCachePreserveDays());
  306  			project.getBuildSetting().setJobProperties(forkedFrom.getBuildSetting().getJobProperties());
```

2. `server-core/src/main/java/io/onedev/server/rest/resource/ProjectResource.java`

Evidence location: https://code.onedev.io/onedev/server/server-core/src/main/java/io/onedev/server/rest/resource/ProjectResource.java#L305

```text
  302  		if (project.getForkedFrom() != null) {
  303  			var forkedFrom = project.getForkedFrom();
  304  			project.getBuildSetting().setBuildPreservations(forkedFrom.getBuildSetting().getBuildPreservations());
  305  			project.getBuildSetting().setCachePreserveDays(forkedFrom.getBuildSetting().getCachePreserveDays());
  306  			project.getBuildSetting().setJobProperties(forkedFrom.getBuildSetting().getJobProperties());
  307  			project.getBuildSetting().setDefaultFixedIssueFilters(forkedFrom.getBuildSetting().getDefaultFixedIssueFilters());
  308  			project.getBuildSetting().setListParams(forkedFrom.getBuildSetting().getListParams(false));
```

3. `SecurityUtils.c`

Evidence location: https://code.onedev.io/onedev/server/SecurityUtils.c
4. `server-core/src/main/java/io/onedev/server/rest/resource/ProjectResource.java`

Evidence location: https://code.onedev.io/onedev/server/server-core/src/main/java/io/onedev/server/rest/resource/ProjectResource.java#L320

```text
  317  		} else {
  318  			projectService.create(user, project);
  319  		}
  320  
  321  		auditService.audit(project, "created project via RESTful API", null, VersionedXmlDoc.fromBean(data).toXML());
  322  
  323      	return project.getId();
```


## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

保留该检查并补 REST fork 创建回归测试。

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/onedev/issue4.html
