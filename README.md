# DNS 转发实验（FastAPI + dnslib）

终端仍向同一个 DNS 地址发起 UDP A 查询，本服务按**可热更新的后缀规则**把查询转发
到不同上游解析器；规则通过 FastAPI 提供的 HTTP 接口在 `/docs` 页面维护。

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
│   └─ 在途查询：每个查询一个 loop 任务，每次上游尝试一个独立 UDP socket        │
│ FastAPI 控制面 (0.0.0.0:8080)：/docs、/rules、/cache、/inflight、/stats      │
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
| 改规则不等上游、立即生效 | `PUT/POST/DELETE /rules` 在规则锁内同步执行 diff，立即返回失效/改投计数 |
| 改走其他上游的域名立即停用旧缓存 | diff 对比每个缓存条目“产生它的上游”与新规则选出的上游，不同即驱逐；上游未变的条目保留原过期时间 |
| 在途查询随即改投新上游 | 取消当前 attempt 任务并关闭其 socket，loop 任务按新规则重选上游重新发起 |
| 丢弃迟到的旧应答 | 每次 attempt 使用一次性 socket，取消即关闭，旧上游迟到报文被内核丢弃；另有一层“应答上游 ≠ 当前规则上游则丢弃”的防御检查（`stale_replies_discarded`） |
| 上游超时或失败返回 SERVFAIL | `UPSTREAM_TIMEOUT`（默认 2s）超时、socket/ICMP 错误、应答无法解析均回 SERVFAIL，且不缓存、不忙等重试 |
| 上游未变的域名继续命中原缓存 | 失效判定只看上游端点是否变化，TTL 窗口不重置 |

## HTTP 接口（交互式文档：`http://127.0.0.1:8080/docs`）

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/rules` | 查看当前规则集 |
| PUT | `/rules` | 整体替换规则集，body：`{"default_upstream": "host:port", "rules": [{"suffix": "lab.example.com", "upstream": "host:port"}]}` |
| POST | `/rules` | 新增/更新单条后缀规则 |
| DELETE | `/rules/{suffix}` | 删除单条后缀规则（默认规则不可删） |
| GET | `/cache` | 缓存条目与剩余 TTL |
| POST | `/cache/flush` | 清空缓存 |
| GET | `/inflight` | 在途查询、当前上游、尝试次数 |
| GET | `/stats` | 计数器（查询、命中、改投、取消、SERVFAIL、超时等） |
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

## 不依赖 Docker 的本地验证

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python tests/integration_test.py
```

## 目录结构

```
dns_forwarder/          转发服务（规则、缓存、在途注册表、UDP 服务、FastAPI、入口）
mock_upstream/          可配置/可延迟的模拟 DNS 上游 + 两份 zone
config/                 初始规则（compose 用容器别名，本地测试用 127.0.0.1）
tests/integration_test.py  端到端测试（7 组 51 项断言）
docker-compose.yml      forwarder + upstream-a + upstream-b
```
