# 开源漏洞披露协作

这是使用 Python 标准库、SQLite 和 `http.server` 实现的保密漏洞协作后台。系统支持报告人、协调员、维护者三种角色，管理受影响产品版本、私密证明材料、保密期限、修复计划、状态历史、延期、通知、披露前评审和公开公告。

## 披露前评审

协调员确认修复后必须发起评审批次并指定必须表态的人（报告人、维护者等协作范围内的成员）。评审人可以赞同、反对（反对必须填写理由）或通过版本更正补充影响范围。只要还有人未表态或存在未处理的反对意见，披露就会被阻止；协调员处理完反对意见后需发起新批次重新表态。每次版本更正都会记录操作、版本和原因，并使进行中的批次失效。已公开的公告对外保持原样，不受评审记录影响。

## 启动

```bash
python app.py
```

默认端口 `8113`，页面为 <http://127.0.0.1:8113>。首次启动创建示例网关漏洞。可用环境变量 `PORT` 和 `VULN_DB` 调整端口及数据库位置。

## 测试

```bash
python -m unittest discover -s tests -v
```

测试覆盖：创建报告、加入维护者、分级、提交修复计划、解决、阻止提前披露、到期披露并读取公告；披露前评审的发起、表态、反对阻断、新批次解除阻断、未表态名单和版本更正留痕；同时验证外部用户无权查看、相同产品版本会触发重复报告，以及维护者看不到协调员专用材料。

## 接口

- `POST /api/users`、`POST /api/products`、`POST /api/reports`
- `GET /api/duplicates?product_id=...&version=...`
- `POST /api/members`、`POST /api/evidence`
- `POST /api/fixes`、`POST /api/extensions`
- `POST /api/reports/{id}/status`
- `POST /api/advisories`、`GET /api/reports/{id}/advisory?user_id=...`
- `POST /api/reviews`、`POST /api/reviews/{id}/vote`
- `POST /api/reports/{id}/versions`
- `POST /api/reports/{id}/publish`
- `GET /api/reports/{id}?user_id=...`
- `GET /api/reports/{id}/notifications`

状态流转限制为 `new -> triaged -> fixing -> resolved -> published`，拒绝或回到修复中也有显式规则。披露日期早于保密期限时请求会失败，不会只修改显示状态；`published` 只能经由发布接口到达，发布前必须存在全员赞同且无未处理反对意见的评审批次。
