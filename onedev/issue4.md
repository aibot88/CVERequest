---
title: "onedev issue4: Detector POST /projects forkedFromId"
description: "onedev has a missing authorization vulnerability. An authenticated attacker can read authorization-sensitive data that should be restricted."
tags:
  - onedev
  - vulnerability-report
  - authorization
  - access-control
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

onedev has a missing authorization vulnerability. An authenticated attacker can read authorization-sensitive data that should be restricted.

- Attack precondition: Any authenticated user
- Affected authorization property: `forkedFromId, canReadCode, projectService.fork, project.getForkedFrom() != null, !SecurityUtils.canReadCode(subject, forkedFrom), UnauthorizedException`
- Security impact: An authenticated attacker can read authorization-sensitive data that should be restricted.

### 1.2 Exploit path

The attacker sends crafted requests to the affected endpoint with target identifiers or authorization-sensitive fields that should be rejected.

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

Enforce server-side authorization for the vulnerable operation before reading or writing target objects, roles, permissions, ownership, tenant, organization, or grant-bound state.

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/onedev/issue4.html
