# 开源漏洞披露协作

这是使用 Python 标准库、SQLite 和 `http.server` 实现的保密漏洞协作后台。系统支持报告人、协调员、维护者三种角色，管理受影响产品版本、私密证明材料、保密期限、修复计划、状态历史、延期、通知和公开公告。披露前增加评审环节：协调员发起评审批次并指定必须表态的成员，评审人可以赞同、反对或补充影响范围；存在未处理反对意见或有人未表态时披露会被阻止。受影响版本的每次更正都会记录修改内容和原因。

## 启动

```bash
python app.py
```

默认端口 `8113`，页面为 <http://127.0.0.1:8113>。首次启动创建示例网关漏洞。可用环境变量 `PORT` 和 `VULN_DB` 调整端口及数据库位置。

## 测试

```bash
python -m unittest discover -s tests -v
```

测试覆盖：创建报告、加入维护者、分级、提交修复计划、解决、阻止提前披露、到期披露并读取公告；同时验证外部用户无权查看、相同产品版本会触发重复报告，以及维护者看不到协调员专用材料。披露前评审覆盖：未评审或有人未表态时禁止披露、反对意见阻断披露直到撤回、非指定评审人不能表态、新批次取代旧批次；版本更正覆盖：每次修改及原因留痕、无权用户不能更正、至少保留一个版本、披露后禁止更正且公开公告对外保持原样。

## 接口

- `POST /api/users`、`POST /api/products`、`POST /api/reports`
- `GET /api/duplicates?product_id=...&version=...`
- `POST /api/members`、`POST /api/evidence`
- `POST /api/fixes`、`POST /api/extensions`
- `POST /api/reports/{id}/status`
- `POST /api/advisories`、`GET /api/reports/{id}/advisory?user_id=...`
- `POST /api/reviews`、`POST /api/reviews/{id}/votes`
- `POST /api/version_corrections`
- `POST /api/reports/{id}/publish`
- `GET /api/reports/{id}?user_id=...`
- `GET /api/reports/{id}/notifications`

状态流转限制为 `new -> triaged -> fixing -> resolved -> published`，拒绝或回到修复中也有显式规则。披露日期早于保密期限时请求会失败，不会只修改显示状态。报告进入 `resolved` 后协调员可发起评审批次（再次发起会取代未完成的旧批次），只有全部指定评审人赞同且没有未处理的反对意见才能披露；评审人的每次表态都会保留。页面"披露前评审"区块展示当前结论、未表态人员、历次表态和版本更正历史；已公开公告无需权限即可读取，内容保持发布时原样。
