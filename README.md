# DNS 转发实验（FastAPI + dnslib）

终端仍向同一个 DNS 地址发起 UDP A 查询，本服务按**可热更新的后缀规则**把查询转发
到不同上游解析器；规则通过 FastAPI 提供的 HTTP 接口在 `/docs` 页面维护。

正向 A 缓存支持**提前刷新（early refresh）**：命中缓存立即按剩余 TTL 回包，当
剩余 TTL 不超过原 TTL 的 20%（`REFRESH_TTL_RATIO` 可调）时，向当前规则选出的上游
发起一次后台刷新，客户端无需等待上游回包。

## 架构

```
终端 (UDP A 查询)
      │ 127.0.0.1:5300/udp
      ▼
┌─────────────────────────────── dns_forwarder ───────────────────────────────┐
│ UDP 协议层 (asyncio DatagramEndpoint)                                        │
│   ├─ 仅接受 A 查询，其他类型返回 REFUSED；畸形报文直接丢弃                    │
│   ├─ 规则匹配：最长 DNS 后缀优先，无匹配走 default_upstream                   │
│   ├─ 缓存层：A 答复 / 带 SOA 的 NXDOMAIN，按 TTL 过期，命中时回写剩余 TTL     │
│   ├─ 提前刷新：剩余 TTL ≤ 原 TTL 20% 时后台刷新，每条缓存最多一次，身份守卫   │
│   └─ 在途查询：每个查询一个 loop 任务，每次上游尝试一个独立 UDP socket        │
│ FastAPI 控制面 (0.0.0.0:8080)：/docs、/rules、/cache、/refreshes、           │
│                                /inflight、/stats                             │
└──────────────┬───────────────────────────────────┬──────────────────────────┘
               ▼                                     ▼
        upstream-a:5353/udp                    upstream-b:5353/udp
        (mock_upstream, 可延迟应答)            (mock_upstream, 可延迟应答)
        控制面 8090                             控制面 8091
```

所有组件运行在同一个 asyncio 事件循环里（转发器内部），因此规则更新、缓存失效、
在途查询改投都在同一次 API 调用中同步完成，**不等待任何上游应答**。

## 关键语义与实现方式

| 需求 | 实现 |
| --- | --- |
| 最长后缀匹配，无匹配走默认上游 | `dns_forwarder/rules.py` 的 `Matcher.match`，规则不可变快照 + 单调版本号 |
| 按 TTL 缓存 A 答复 | 取应答区最小 TTL；命中缓存时按已存放时间递减所有 RR 的 TTL（跳过 EDNS OPT） |
| 缓存带 SOA 的 NXDOMAIN | RFC 2308：负向 TTL = min(SOA RR TTL, SOA MINIMUM)；无 SOA 的 NXDOMAIN、NODATA、SERVFAIL、TTL=0 一律不缓存 |
| 命中正向缓存立即回包并按剩余 TTL 触发提前刷新 | `service.py` 的 `_maybe_schedule_refresh`：剩余 TTL ≤ 原 TTL × 0.2 即安排后台刷新（仅正向 A，负向条目不刷新） |
| 每份缓存答复只触发一次刷新 | 条目级 `refresh_scheduled` 标记 + 按 `entry_id` 去重的 `RefreshRegistry`；后续命中不再重复安排 |
| 刷新答复按新 TTL 替换旧条目 | `DNSCache.apply_refresh`：仅当原条目仍有效且仍是当前条目（`entry_id` 相同）才写入，替换后获得新身份和完整新 TTL |
| 刷新失败保留原到期时间 | 上游超时/ICMP/解析失败只计 `refreshes_failed`，不动缓存；条目自然过期后的查询照常回源 |
| 清缓存后迟到结果不得写回 | `POST /cache/flush` 取消全部刷新任务并清空条目；迟到答复过不了 `entry_id` 守卫 |
| 改路导致条目失效后迟到结果不得写回 | `apply_diff` 驱逐改上游的条目并取消其刷新；另有“刷新答复的上游 ≠ 当前规则上游则丢弃”的防御检查 |
| 规则更新未改变该域名上游时刷新仍生效 | 失效判定只看上游端点；上游未变的条目身份不变、刷新任务不取消，照常按原条件完成 |
| 改规则不等上游、立即生效 | `PUT/POST/DELETE /rules` 在规则锁内同步执行 diff，立即返回失效/改投/取消计数 |
| 在途查询随即改投新上游 | 取消当前 attempt 任务并关闭其 socket，loop 任务按新规则重选上游重新发起 |
| 丢弃迟到的旧应答 | 每次 attempt 使用一次性 socket，取消即关闭；刷新与前台共用同一交换路径 |
| 上游超时或失败返回 SERVFAIL | `UPSTREAM_TIMEOUT`（默认 2s）超时、socket/ICMP 错误、应答无法解析均回 SERVFAIL，且不缓存、不忙等重试 |
| 上游未变的域名继续命中原缓存 | 失效判定只看上游端点是否变化，TTL 窗口不重置 |

### 提前刷新的状态与计数

* 每个缓存条目有单调递增的 `entry_id`；刷新、前台回源替换、清缓存、改路驱逐都会
  产生新身份（或直接消失），因此迟到的刷新结果只能被拒绝，不可能覆盖新状态。
* `/cache` 视图增加 `entry_id`、`ttl_original`、`refresh_scheduled`、`refresh_in_flight`；
  新增 `/refreshes` 查看在途后台刷新；`/stats` 增加五个 `refreshes_*` 计数器。
* 刷新窗口由环境变量 `REFRESH_TTL_RATIO` 控制，默认 `0.2`，取值范围 `(0, 1]`。

## HTTP 接口（交互式文档：`http://127.0.0.1:8080/docs`）

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/rules` | 查看当前规则集 |
| PUT | `/rules` | 整体替换规则集，body：`{"default_upstream": "host:port", "rules": [{"suffix": "lab.example.com", "upstream": "host:port"}]}` |
| POST | `/rules` | 新增/更新单条后缀规则 |
| DELETE | `/rules/{suffix}` | 删除单条后缀规则（默认规则不可删） |
| GET | `/cache` | 缓存条目、剩余/原始 TTL、刷新标记与条目身份 |
| POST | `/cache/flush` | 清空缓存并取消其全部后台刷新 |
| GET | `/refreshes` | 在途的提前刷新任务（条目 id、域名、上游） |
| GET | `/inflight` | 在途查询、当前上游、尝试次数 |
| GET | `/stats` | 计数器（查询、命中、改投、取消、SERVFAIL、超时、提前刷新等） |
| GET | `/health` | 存活探针 |

上游控制面（模拟上游）：`PUT /records/{qname}` 配置记录、`POST /delay`
配置逐域名/全局应答延迟、`GET /counters` 查询统计。

## 用 Docker Compose 启动

```bash
docker compose up --build
# 转发器：127.0.0.1:5300/udp，规则 API：http://127.0.0.1:8080/docs
# 上游 A 控制面：http://127.0.0.1:8090，上游 B：http://127.0.0.1:8091
```

让 A 对某个域名慢应答 3 秒：

```bash
curl -X POST 127.0.0.1:8090/delay -H 'content-type: application/json' \
  -d '{"qnames": {"slow.lab.example.com.": 3.0}}'
```

把 `lab.example.com` 从 A 切到 B（立即生效，旧缓存驱逐、在途查询改投）：

```bash
curl -X PUT 127.0.0.1:8080/rules -H 'content-type: application/json' -d '{
  "default_upstream": "upstream-a:5353",
  "rules": [{"suffix": "lab.example.com", "upstream": "upstream-b:5353"}]
}'
```

观察一次提前刷新（先在 A 上配一个短 TTL 记录，查询两次，第二次落在刷新窗口）：

```bash
curl -X PUT 127.0.0.1:8090/records/demo.lab.example.com -H 'content-type: application/json' \
  -d '{"kind":"A","ttl":10,"addresses":["10.10.0.50"]}'
# 第一次查询建立缓存；约 8 秒后再查一次即触发后台刷新（默认 20% 窗口）
curl -s 127.0.0.1:8080/cache | python3 -m json.tool   # entry_id / refresh_scheduled / TTL
curl -s 127.0.0.1:8080/refreshes                     # 在途刷新
curl -s 127.0.0.1:8080/stats | python3 -m json.tool  # refreshes_* 计数
```

## 不依赖 Docker 的本地验证

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python tests/test_cache_refresh_guard.py   # 缓存身份守卫单元测试
.venv/bin/python tests/integration_test.py           # 端到端测试
```

集成测试通过环境变量 `REFRESH_TTL_RATIO=0.8` 把刷新窗口调大，让提前刷新场景保持
快速、确定；生产默认值仍是 `0.2`。

## 目录结构

```
dns_forwarder/            转发服务（规则、缓存、提前刷新、在途注册表、UDP、FastAPI、入口）
  refreshes.py            后台提前刷新任务注册表（按缓存条目 id 去重/取消）
mock_upstream/            可配置/可延迟的模拟 DNS 上游 + 两份 zone
config/                   初始规则（compose 用容器别名，本地测试用 127.0.0.1）
tests/integration_test.py    端到端测试（11 组 92 项断言）
tests/test_cache_refresh_guard.py  缓存身份守卫单元测试（8 组）
docker-compose.yml        forwarder + upstream-a + upstream-b
```
