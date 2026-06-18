---
title: "onedev issue2: Detector REST issue time tracking 读取泄露"
description: "onedev has a missing authorization vulnerability: Detector REST issue time tracking 读取泄露. 可读取 work log 或时间变更历史中的 spent/estimated time old/new value，绕过 `AccessTimeTracking`。"
tags:
  - onedev
  - 漏洞报告
  - 越权
  - 访问控制
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

onedev has a missing authorization vulnerability: Detector REST issue time tracking 读取泄露. 可读取 work log 或时间变更历史中的 spent/estimated time old/new value，绕过 `AccessTimeTracking`。

- Attack precondition: 攻击者能访问 issue，但没有目标项目的 `AccessTimeTracking`；`GET /issue-works/{workId}` 还需要订阅 active，并知道或枚举到 work id。
- Security impact: 可读取 work log 或时间变更历史中的 spent/estimated time old/new value，绕过 `AccessTimeTracking`。

### 1.2 Exploit path

当前代码中，`GET /issues/{id}`、`GET /issues` 的标量 time 字段已过滤，`GET /issues/{id}/works` 也已加 time-tracking 检查；但 `GET /issues/{id}/changes` 仍直接返回 change data，`GET /issue-works/{workId}` 仍只检查 `canAccessIssue`。

### 1.3 Key code evidence

1. `server-core/src/main/java/io/onedev/server/rest/resource/IssueResource.java`

Evidence location: https://code.onedev.io/onedev/server/server-core/src/main/java/io/onedev/server/rest/resource/IssueResource.java#L131

```text
  128      }
  129  
  130  	@Api(order=200, exampleProvider = "getFieldsExample")
  131  	@Path("/{issueId}/fields")
  132      @GET
  133      public Map<String, Serializable> getFields(@PathParam("issueId") Long issueId) {
  134  		Issue issue = issueService.load(issueId);
```

2. `server-core/src/main/java/io/onedev/server/rest/resource/IssueResource.java`

Evidence location: https://code.onedev.io/onedev/server/server-core/src/main/java/io/onedev/server/rest/resource/IssueResource.java#L171

```text
  168  		Issue issue = issueService.load(issueId);
  169      	if (!SecurityUtils.canAccessIssue(issue)) 
  170  			throw new UnauthorizedException();
  171      	return issue.getComments();
  172      }
  173  
  174  	@Api(order=425)
```

3. `server-core/src/main/java/io/onedev/server/rest/resource/IssueWorkResource.java`

Evidence location: https://code.onedev.io/onedev/server/server-core/src/main/java/io/onedev/server/rest/resource/IssueWorkResource.java#L46

```text
   43  	@Api(order=100)
   44  	@Path("/{workId}")
   45  	@GET
   46  	public IssueWork getWork(@PathParam("workId") Long workId) {
   47  		if (!subscriptionService.isSubscriptionActive())
   48  			throw new UnsupportedOperationException("This feature requires an active subscription");
   49  		IssueWork work = workService.load(workId);
```

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

5. `SecurityUtils.c`

Evidence location: https://code.onedev.io/onedev/server/SecurityUtils.c

## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

对 `getChanges` 中 time-tracking change data 做过滤，或无权限时拒绝；`IssueWorkResource.getWork` 增加 `SecurityUtils.canAccessTimeTracking(work.getIssue().getProject())`。

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/onedev/issue2.html
