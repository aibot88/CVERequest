---
title: "onedev issue5: Detector work log time tracking gate"
description: "onedev has a missing authorization vulnerability in POST /issue-works, POST /projects, /tod/log-work, /issues/{id}/works, /issue-works/{id}, /mcp-helper. An authenticated attacker can perform authorization-sensitive operations through POST /issue-works, POST /projects, /tod/log-work, /issues/{id}/works, /issue-works/{id}, /mcp-helper without the required permission."
tags:
  - onedev
  - vulnerability-report
  - authorization
  - access-control
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

onedev has a missing authorization vulnerability in POST /issue-works, POST /projects, /tod/log-work, /issues/{id}/works, /issue-works/{id}, /mcp-helper. An authenticated attacker can perform authorization-sensitive operations through POST /issue-works, POST /projects, /tod/log-work, /issues/{id}/works, /issue-works/{id}, /mcp-helper without the required permission.

- Attack precondition: Any authenticated user
- Affected endpoint: `POST /issue-works, POST /projects, /tod/log-work, /issues/{id}/works, /issue-works/{id}, /mcp-helper`
- Affected authorization property: `AccessTimeTracking, IssueWork, canAccessTimeTracking, createWork, canAccessIssue, issueWorkService.createOrUpdate(work)`
- Security impact: An authenticated attacker can perform authorization-sensitive operations through POST /issue-works, POST /projects, /tod/log-work, /issues/{id}/works, /issue-works/{id}, /mcp-helper without the required permission.

### 1.2 Exploit path

The attacker sends crafted requests to POST /issue-works, POST /projects, /tod/log-work, /issues/{id}/works, /issue-works/{id}, /mcp-helper with target identifiers or authorization-sensitive fields that should be rejected.

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

Enforce server-side authorization for POST /issue-works, POST /projects, /tod/log-work, /issues/{id}/works, /issue-works/{id}, /mcp-helper before reading or writing target objects, roles, permissions, ownership, tenant, organization, or grant-bound state.

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/onedev/issue5.html
