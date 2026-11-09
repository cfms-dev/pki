# 安全更新上线手册

## 本地验证

Python 使用 3.15.2，Worker 工具链使用 Node.js 26.13.0、npm 12.2.2。

```text
uv sync --locked
uv run --locked pytest -q
uv run --locked ruff check .
uv run --locked ruff format --check .
```

在 `workers/acme` 目录执行：

```text
npm ci
npm run typecheck
npm test
npm run test:runtime
npm audit --audit-level=low
```

运行时冒烟测试只使用临时本地 D1 和临时 CA；验证旧数据库升级、Worker
文件系统中的 CA 读取、真实签名、签发落库及 CRL Distribution Point。
DNS 验证结果在此测试中直接写入本地 D1；DNS/HTTP 验证另有集成测试覆盖。

## 数据库迁移

1. 先通过 Cloudflare D1 导出/Time Travel 记录备份，并记录当前 Worker 版本。
2. 为管理命令配置 `CLOUDFLARE_ACCOUNT_ID`、`CLOUDFLARE_D1_DATABASE_ID` 和
   `CLOUDFLARE_API_TOKEN`。该令牌需要目标账户的 D1 管理权限；不要使用 CRL
   发布的读取令牌，也不要将令牌放入命令参数、源码或日志。
3. 在 Worker 目录运行 `npm run migrate:account-keys`。脚本先应用增量表结构，
   每批处理 50 个账户并打印计数；遇到未解决冲突后以非零状态结束。重复运行可恢复。
4. 检查 `account_key_conflicts`，逐项修复非法公钥或重复实际密钥。账户 ID、
   JWK、协议 thumbprint 和历史所有权不会由迁移脚本更改。任何人工账户修复
   均需先核对历史订单及授权，不能通过伪造 fingerprint 绕过唯一索引。
5. 确认下列计数为零，再启用新 Worker 的签发流量：

```sql
SELECT COUNT(*) AS unresolved FROM accounts WHERE public_key_fingerprint IS NULL;
SELECT * FROM account_key_conflicts;
```

迁移未完成时，注册、密钥轮换和 finalize 返回 503；读取和既有账户鉴权仍可用。
请求路径不会自动执行公钥回填。新增的签发租约、代次和 `certificates.ca_id`
列均为增量变更，无需删除旧表。

如需持久化历史证书的 CA 归属，在仓库根目录使用管理令牌执行：

```text
uv run --locked python -m cfms_pki.acme_export --backfill-ca-ids --output <临时目录>/revocations.json
```

脚本从保存的证书核验签名、AKI/签发者和序列号，并要求注册 CA 唯一匹配。
无法确定或元数据不一致时停止，不会根据名称猜测 CA。该回填也可重复执行。

## 撤销与 CRL 发布

GitHub Actions 配置以下仓库变量和密钥：

| 类型 | 名称 | 用途 |
| --- | --- | --- |
| Variable | `CLOUDFLARE_ACCOUNT_ID` | Cloudflare 账户 ID |
| Variable | `CLOUDFLARE_D1_DATABASE_ID` | 与 Worker 配置一致的 D1 ID |
| Secret | `CLOUDFLARE_D1_READ_TOKEN` | 专用 D1 Read 令牌，仅限目标账户 |
| Secret | `PK_GENERIC_INTERMEDIATE` | 已有 CRL 签名私钥 |
| Secret | `CFMS_PKI_KEY_PASSWORD` | 已有可选私钥口令 |

Pages 工作流每小时第 17 分钟运行，也可手动触发。导出器分页读取已撤销记录，
核验 CA 与证书身份，将结果合并到临时输入，不修改版本控制中的撤销注册表。
只有全部查询、核验、CRL 签名及页面构建成功后才部署；失败保留上一次发布。
失败的 Actions 运行就是发布故障信号，应检查权限、证书归属和 CRL `nextUpdate`。
小时级调度不等于实时撤销，GitHub 排队也可能延迟发布。

新证书使用 `CRL_BASE_URL/<crl-file>`（默认 `<ca-id>.crl`，支持注册表 `crl_path` 的文件名），默认基址为
`https://cfms-pki.crpteam.club/crl`。若站点域名不同，应在签发前设置该变量。
历史证书无法补加扩展，客户端需要既有的撤销检查配置或重签证书。
新增 CA 时还需给 CRL 工作流配置其对应的签名私钥，保持注册表、Worker
证书包和 Pages 输出一致。

上线后用测试域名签发、撤销证书，手动触发 CRL 发布，下载 CRL 并验证签名、
CA 归属、序列号和有效期。生产凭据和线上验证未包含在本地测试结果中。

## 回滚

上线前先完成迁移和只读导出检查，再部署 Worker。保留新增列和索引，代码回滚
不应删除账户指纹、证书或撤销记录。不得回滚到允许越权撤销或 CAA 查询失败放行
的版本；如新版本签发异常，应暂停签发并保持已发布 CRL 可下载，再修复或部署
保留安全修复的回退版本。D1 恢复前须核对备份之后的全部签发和撤销，避免丢失状态。

管理脚本使用 Cloudflare 官方 [D1 Query API](https://developers.cloudflare.com/api/resources/d1/subresources/database/methods/query/) 的单查询及 `batch` 请求结构。
