DETECTOR_PROMPT = """敏感字段绑定/Mass Assignment 判断提示：
- 判断目标：客户端能否提交或篡改服务端应控制的字段，导致越权赋值、归属切换、租户切换或关键业务值被服务端采纳。
- 覆盖字段：role/permission/privilege/admin/is_staff/is_superuser/access_level/scope、tenant/org/company/workspace、owner/user/account/member/customer、price/amount/total/discount/quota/limit/balance/credit/level，以及嵌套 JSON 中的同类字段。
- confirmed：mutate_param 主动验证篡改敏感字段后返回 2xx/3xx/204/202，且响应或后续流量显示字段被接受，产生权限提升、归属人变化、租户变化、金额/折扣/额度变化、用户等级变化等业务结果；普通用户把自己提升为管理员、切换 owner/tenant、修改金额额度均可 confirmed。
- likely：变异请求成功且响应结构表明保存/更新成功，但缺少明确字段回显；或历史流量显示客户端提交敏感字段，后续响应又把该字段作为服务端结果返回。
- needs_manual_review：只有敏感字段出现；缺少变异验证；字段语义不清；当前账号权限未知；响应没有说明服务端采纳该字段；字段可能只是客户端本地缓存。
- false_positive：字段只是查询筛选、排序、前端展示缓存、服务端忽略、返回校验失败/权限不足、只有管理员正常提交管理字段、字段属于当前用户允许编辑的普通资料。
- 不要把“请求里存在 role/tenant/owner/amount”直接判漏洞；必须证明服务端信任了客户端提交的敏感字段。
- 对 JSON，需要关注嵌套路径，例如 user.role、profile.is_staff、items[0].price、tenant.id；如果只变异了错误字段或服务端未采纳，应降级。
- evidence 应包含：字段名、原值、篡改值、提交位置(query/form/json)、主动验证状态码、服务端接受后的字段回显或业务结果；证据不足时写清缺少字段回显、后续状态或权限上下文。"""
