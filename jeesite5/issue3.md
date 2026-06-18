---
title: "jeesite5 issue3: cms/article/save 栏目重绑定"
description: "jeesite5 has a missing authorization vulnerability: cms/article/save 栏目重绑定. 攻击者可把文章创建或迁移到无权管理的栏目，绕过栏目级内容管理边界。"
tags:
  - jeesite5
  - 漏洞报告
  - 越权
  - 访问控制
  - CVE
---

## Vulnerability call chain

### 1.1 Summary

jeesite5 has a missing authorization vulnerability: cms/article/save 栏目重绑定. 攻击者可把文章创建或迁移到无权管理的栏目，绕过栏目级内容管理边界。

- Attack precondition: 攻击者拥有 `cms:article:edit`，但只应管理部分栏目。
- Security impact: 攻击者可把文章创建或迁移到无权管理的栏目，绕过栏目级内容管理边界。

### 1.2 Exploit path

- 请求提交 `article.category.id` 或相关栏目字段。

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
  148  	 * 保存文章表
  149  	 */
  150  	@RequiresPermissions("cms:article:edit")
  151  	@PostMapping(value = "save")
  152  	@ResponseBody
  153  	public String save(@Validated Article article) {
  154  		articleService.save(article);
  155  		return renderResult(Global.TRUE, text("保存文章表成功！"));
  156  	}
  157  
  158  	/**
```

5. `modules/cms/src/main/java/com/jeesite/modules/cms/service/ArticleService.java`

Evidence location: https://gitee.com/thinkgem/jeesite5/blob/master/modules/cms/src/main/java/com/jeesite/modules/cms/service/ArticleService.java#L95

```text
   92  	 * 添加数据权限
   93  	 */
   94  	@Override
   95  	public void addDataScopeFilter(Article entity, String ctrlPermi) {
   96  		entity.sqlMap().getDataScope().addFilter("dsfCategory",
   97  				"Category", "a.category_code", "a.create_by", ctrlPermi);
   98  	}
   99  	
  100  	/**
  101  	 * 查询分页数据
```

6. `modules/cms/src/main/java/com/jeesite/modules/cms/service/ArticleService.java`

Evidence location: https://gitee.com/thinkgem/jeesite5/blob/master/modules/cms/src/main/java/com/jeesite/modules/cms/service/ArticleService.java#L160

```text
  157  		if (StringUtils.isBlank(article.getCategory().getId())) {
  158  			throw new ServiceException(text("归属栏目不正确或为空。"));
  159  		}
  160  		// 如果需要文章审核流程，则进行下一步流程操作
  161  		if (isCanUseAuth && Global.YES.equals(article.getCategory().getIsNeedAudit())) {
  162  			articleAuthService.submit(article, this::saveArticle);
  163  		} else {
  164  			// 保存文章
  165  			saveArticle(article);
  166  			// 发布文章
  167  			if (Article.STATUS_NORMAL.equals(article.getStatus())) {
  168  				updateStatus(article);
  169  			}
  170  		}
  171  	}
  172  
  173  	private void saveArticle(Article article) {
  174  		// 计算内容字数
  175  		ArticleData articleData = article.getArticleData();
  176  		article.setWordCount(StringUtils.stripHtml(articleData.getContent()).length());
  177  		// 保存详细内容
  178  		if (article.getIsNewRecord()) {
  179  			dao.insert(article);
  180  			articleData.setId(article.getId());
  181  			articleDataDao.insert(articleData);
  182  		} else {
```

7. `modules/cms/src/main/java/com/jeesite/modules/cms/entity/Article.java`

Evidence location: https://gitee.com/thinkgem/jeesite5/blob/master/modules/cms/src/main/java/com/jeesite/modules/cms/entity/Article.java#L31

```text
   28   * @author ThinkGem、长春叭哥、一往无前
   29   * @version 2018-10-15
   30   */
   31  @Table(name = "${_prefix}cms_article", alias = "a", columns = {
   32  		@Column(name = "id", attrName = "id", label = "编号", isPK = true),
   33  		@Column(name = "category_code", attrName = "category.categoryCode", label = "栏目编码", isQuery = false),
   34  		@Column(name = "module_type", attrName = "moduleType", label = "模块类型"),
   35  		@Column(name = "title", attrName = "title", label = "内容标题", queryType = QueryType.LIKE),
   36  		@Column(name = "href", attrName = "href", label = "外部链接"),
   37  		@Column(name = "color", attrName = "color", label = "标题颜色"),
```


## 3. Root Cause Analysis

Root Cause 1: Missing server-side authorization on the vulnerable operation.

The endpoint accepts user-controlled authorization-sensitive identifiers or fields, but the write/read path does not prove that the current caller may operate on the target object.

Root Cause 2: Missing object-scope or grant-bound validation.

The implementation relies on endpoint access, UI filtering, or object existence checks instead of enforcing target ownership, tenant boundary, role ceiling, or grantable-resource constraints at the service layer.

## 4. Recommended fix

保存前对目标 `category_code` 做写权限/data scope 校验；无权限则拒绝保存。

## 5. Verification after fix

- Unauthorized callers receive HTTP 403 or equivalent rejection.
- Out-of-scope target identifiers are rejected before database writes or sensitive reads.
- Role, permission, tenant, organization, ownership, or grant-bound ceilings are enforced server-side.
- Direct HTTP requests are rejected even when front-end controls are hidden.

Published reference: https://aibot88.github.io/CVERequest/jeesite5/issue3.html
