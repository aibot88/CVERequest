---
title: "onedev issue5: Detector work log 写入绕过 time tracking gate"
description: "onedev has a missing authorization vulnerability: Detector work log 写入绕过 time tracking gate. 无 time-tracking 权限的用户可创建 time-tracking 记录，影响 issue work log 数据；REST 路径非管理员只能写自己，未扩大为伪造任意他人 work。"
tags:
  - onedev
  - 漏洞报告
  - 越权
  - 访问控制
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

onedev has a missing authorization vulnerability: Detector work log 写入绕过 time tracking gate. 无 time-tracking 权限的用户可创建 time-tracking 记录，影响 issue work log 数据；REST 路径非管理员只能写自己，未扩大为伪造任意他人 work。

- Attack precondition: 已认证用户，可访问目标 issue；订阅 active；项目开启 time tracking；但用户没有 `AccessTimeTracking`。
- Security impact: 无 time-tracking 权限的用户可创建 time-tracking 记录，影响 issue work log 数据；REST 路径非管理员只能写自己，未扩大为伪造任意他人 work。

### 1.2 Exploit path

调用 `POST /issue-works` 写入自己的 `IssueWork`，或调用 `/tod/log-work` 以当前用户写入 work log。

### 1.3 Key code evidence

1. `server-core/src/main/java/io/onedev/server/rest/resource/IssueWorkResource.java`

Evidence location: https://code.onedev.io/onedev/server/server-core/src/main/java/io/onedev/server/rest/resource/IssueWorkResource.java#L57

```text
   54  	
   55  	@Api(order=200, description="Log new issue work")
   56  	@POST
   57  	public Long createWork(@NotNull IssueWork work) {
   58  		if (!subscriptionService.isSubscriptionActive()) 
   59  			throw new NotAcceptableException("This feature requires an active subscription");
   60  		if (!work.getIssue().getProject().isTimeTracking())
```

2. `TodResource.java`

Evidence location: https://code.onedev.io/onedev/server/TodResource.java#L857
3. `issueWorkService.c`

Evidence location: https://code.onedev.io/onedev/server/issueWorkService.c
4. `server-core/src/main/java/io/onedev/server/web/component/issue/activities/IssueActivitiesPanel.java`

Evidence location: https://code.onedev.io/onedev/server/server-core/src/main/java/io/onedev/server/web/component/issue/activities/IssueActivitiesPanel.java#L151

```text
  148  				otherActivities.add(new IssueCommentActivity(comment));
  149  		}
  150  		
  151  		if (showWorkLog && getIssue().getProject().isTimeTracking() 
  152  				&& WicketUtils.isSubscriptionActive() 
  153  				&& canAccessTimeTracking(getIssue().getProject())) {
  154  			for (IssueWork work: getIssue().getWorks())
```

5. `server-core/src/main/java/io/onedev/server/model/Role.java`

Evidence location: https://code.onedev.io/onedev/server/server-core/src/main/java/io/onedev/server/model/Role.java#L274

```text
  271  	@Editable(order=500, description = "This permission enables one to schedule issues into iterations")
  272  	@DependsOn(property="manageIssues", value="false")
  273  	public boolean isScheduleIssues() {
  274  		return scheduleIssues;
  275  	}
  276  
  277  	public void setScheduleIssues(boolean scheduleIssues) {
```

6. `IssueWorkResource.c`

Evidence location: https://code.onedev.io/onedev/server/IssueWorkResource.c
7. `SecurityUtils.c`

Evidence location: https://code.onedev.io/onedev/server/SecurityUtils.c

## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

在 `IssueWorkResource.createWork` 和 `TodResource.logWork` 中增加 `SecurityUtils.canAccessTimeTracking(issue.getProject())`；如产品语义希望“可见 issue 即可记工”，则需要新增显式 `LogWork` 权限，而不是复用隐式绕过。

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/onedev/issue5.html
