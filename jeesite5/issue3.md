---
title: "jeesite5 issue3: cms/article/save"
description: "jeesite5 has a missing authorization vulnerability in POST ${adminPath}/cms/article/save. An authenticated attacker can perform authorization-sensitive operations through POST ${adminPath}/cms/article/save without the required permission."
tags:
  - jeesite5
  - vulnerability-report
  - authorization
  - access-control
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

jeesite5 has a missing authorization vulnerability in POST ${adminPath}/cms/article/save. An authenticated attacker can perform authorization-sensitive operations through POST ${adminPath}/cms/article/save without the required permission.

- Attack precondition: Any authenticated user
- Affected endpoint: `POST ${adminPath}/cms/article/save`
- Affected authorization property: `cms:article:edit, Article.category, cms_article.category_code, Article.status, status, article.category.id`
- Security impact: An authenticated attacker can perform authorization-sensitive operations through POST ${adminPath}/cms/article/save without the required permission.

### 1.2 Exploit path

The attacker sends crafted requests to POST ${adminPath}/cms/article/save with target identifiers or authorization-sensitive fields that should be rejected.

### 1.3 Key code evidence

1. `Article.c`

Evidence location: https://gitee.com/thinkgem/jeesite5/blob/master/Article.c
2. `cms_article.c`

Evidence location: https://gitee.com/thinkgem/jeesite5/blob/master/cms_article.c
3. `article.c`

Evidence location: https://gitee.com/thinkgem/jeesite5/blob/master/article.c
4. `modules/cms/src/main/java/com/jeesite/modules/cms/web/ArticleController.java`

Evidence location: https://gitee.com/thinkgem/jeesite5/blob/master/modules/cms/src/main/java/com/jeesite/modules/cms/web/ArticleController.java#L150

```text
  147  	/**
  148  	 * [non-English text removed]
  149  	 */
  150  	@RequiresPermissions("cms:article:edit")
  151  	@PostMapping(value = "save")
  152  	@ResponseBody
  153  	public String save(@Validated Article article) {
  154  		articleService.save(article);
  155  		return renderResult(Global.TRUE, text("[non-English text removed]"));
  156  	}
  157
  158  	/**
```

5. `modules/cms/src/main/java/com/jeesite/modules/cms/service/ArticleService.java`

Evidence location: https://gitee.com/thinkgem/jeesite5/blob/master/modules/cms/src/main/java/com/jeesite/modules/cms/service/ArticleService.java#L95

```text
   92  	 * [non-English text removed]
   93  	 */
   94  	@Override
   95  	public void addDataScopeFilter(Article entity, String ctrlPermi) {
   96  		entity.sqlMap().getDataScope().addFilter("dsfCategory",
   97  				"Category", "a.category_code", "a.create_by", ctrlPermi);
   98  	}
   99
  100  	/**
  101  	 * [non-English text removed]
```

6. `modules/cms/src/main/java/com/jeesite/modules/cms/service/ArticleService.java`

Evidence location: https://gitee.com/thinkgem/jeesite5/blob/master/modules/cms/src/main/java/com/jeesite/modules/cms/service/ArticleService.java#L160

```text
  157  		if (StringUtils.isBlank(article.getCategory().getId())) {
  158  			throw new ServiceException(text("[non-English text removed]."));
  159  		}
  160  		// [non-English text removed],[non-English text removed]
  161  		if (isCanUseAuth && Global.YES.equals(article.getCategory().getIsNeedAudit())) {
  162  			articleAuthService.submit(article, this::saveArticle);
  163  		} else {
  164  			// [non-English text removed]
  165  			saveArticle(article);
  166  			// [non-English text removed]
  167  			if (Article.STATUS_NORMAL.equals(article.getStatus())) {
  168  				updateStatus(article);
  169  			}
  170  		}
  171  	}
  172
  173  	private void saveArticle(Article article) {
  174  		// [non-English text removed]
  175  		ArticleData articleData = article.getArticleData();
  176  		article.setWordCount(StringUtils.stripHtml(articleData.getContent()).length());
  177  		// [non-English text removed]
  178  		if (article.getIsNewRecord()) {
  179  			dao.insert(article);
  180  			articleData.setId(article.getId());
  181  			articleDataDao.insert(articleData);
  182  		} else {
```

7. `modules/cms/src/main/java/com/jeesite/modules/cms/entity/Article.java`

Evidence location: https://gitee.com/thinkgem/jeesite5/blob/master/modules/cms/src/main/java/com/jeesite/modules/cms/entity/Article.java#L31

```text
   28   * @author ThinkGem,[non-English text removed],[non-English text removed]
   29   * @version 2018-10-15
   30   */
   31  @Table(name = "${_prefix}cms_article", alias = "a", columns = {
   32  		@Column(name = "id", attrName = "id", label = "[non-English text removed]", isPK = true),
   33  		@Column(name = "category_code", attrName = "category.categoryCode", label = "[non-English text removed]", isQuery = false),
   34  		@Column(name = "module_type", attrName = "moduleType", label = "[non-English text removed]"),
   35  		@Column(name = "title", attrName = "title", label = "[non-English text removed]", queryType = QueryType.LIKE),
   36  		@Column(name = "href", attrName = "href", label = "[non-English text removed]"),
   37  		@Column(name = "color", attrName = "color", label = "[non-English text removed]"),
```


## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

Enforce server-side authorization for POST ${adminPath}/cms/article/save before reading or writing target objects, roles, permissions, ownership, tenant, organization, or grant-bound state.

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/jeesite5/issue3.html
