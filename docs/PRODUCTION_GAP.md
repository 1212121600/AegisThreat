# AegisThreat 投入使用缺口分析

> 基于代码级审计：86 个问题定位，按阻塞度排序

---

## 总览

| 指标 | 数值 |
|------|------|
| 代码中的 Mock/占位符 | 38 处 |
| 推迟到 Phase 2 的功能 | 28 处 |
| 完全未实现的功能 | 11 处 |
| 空操作占位 | 5 处 |
| 依赖缺失回退 | 3 处 |

**核心结论：代码架构是完整的** — 每个组件都有正确的接口、数据流和错误处理。**差距在于：所有外部系统都用 Mock 代替了真实系统。**

---

## 一、阻塞级（没有这些，系统完全不可用）

### 1.1 无真实数据源 — 38 处 Mock 的根源

```
当前状态：Detection Agent 只能消费内存中的字典（ingest_alert 参数）
缺失：    实际 SIEM/EDR 告警流入管道
影响：    整个系统在真实环境无输入，三个 Agent 全部空转
```

**具体缺失：**

| 组件 | 当前 | 需要 |
|------|------|------|
| `aegis/connectors/siem.py` | 5 个平台适配器全部 `logger.warning("not yet implemented")` | 至少 1 个真实数据源接入 |
| `aegis/core/alert_dedup.py` | 代码完整，但从未在真实流量上测试 | 真实告警去重验证 |
| `aegis/agents/detection.py` | TTP 映射规则表是手工编写的，未经真实数据校准 | 基于真实告警的规则优化 |

**最小可行方案（2 周）：**
接入 Suricata 的 `eve.json` 文件（`SuricataAdapter` 的文件读取部分已实现），配上真实的 TTP 映射规则。

### 1.2 知识图谱是硬编码字典 — 15 处 Mock

```
当前状态：Tracing Agent 的 _get_attck_adjacency() 返回一个手写的 Python dict（约 60 个技术节点）
缺失：    Neo4j 图数据库 + 完整的 ATT&CK v15 数据（200+ 技术，500+ 子技术）
影响：    BFS 路径推理只能覆盖手写字典中的技术，大量 ATT&CK 技术不在搜索空间中
```

**具体缺失：**

| 组件 | 当前 | 需要 |
|------|------|------|
| `aegis/knowledge/graph.py` | 15 处 `if self._use_mock` → 返回硬编码结果 | Neo4j 连接 + Cypher 查询 |
| `aegis/knowledge/attck_loader.py` | 代码完整但 `import to Neo4j not yet wired` | 执行 ATT&CK STIX 导入 |
| `aegis/knowledge/schema.cypher` | Schema 定义完整 | 在 Neo4j 实例中执行 |
| 资产拓扑 | 不存在 | 企业 CMDB 数据导入 |
| 检测覆盖图 | 不存在 | 哪些技术有对应的 SIEM 规则 |

**最小可行方案（1 周）：**
`docker-compose up neo4j`，运行 `python tools/attck_importer.py --neo4j-uri bolt://localhost:7687`，将 `KnowledgeGraph` 的 `use_mock` 设为 `False`。

---

## 二、功能级（系统能跑，但产出质量不可接受）

### 2.1 攻击路径评分是启发式的 — 无 ML

```
当前状态：_score_paths() 用 if/else 规则打分（覆盖率、连贯性、平台一致性、长度）
缺失：    GraphSAGE 模型训练 + 历史攻击链嵌入
影响：    路径评分是手工规则的加权和，不能从历史数据中学习，对新型攻击可能评分失准
```

| 文件 | 88 行 |
|------|------|
| `aegis/inference/path_scorer.py` | `GraphSAGE training not yet implemented` → `_mock_score()` |

### 2.2 LLM 验证未接入 — 4 处未实现

```
当前状态：Tracing Agent 的 _llm_verify() 只记日志不调用
缺失：    GPT-4o API key 或本地 vLLM 部署
影响：    攻击路径的语义验证缺失，可能产生逻辑不连贯的链
```

| 文件 | 现状 |
|------|------|
| `aegis/agents/tracing.py:352` | `logger.info("LLM verification ... not yet implemented")` |
| `aegis/llm/client.py` | OpenAI 后端需要 `httpx` + API key；vLLM 需要本地 GPU |

### 2.3 告警摘要是模板填充的 — 无 NLP

```
当前状态：_generate_summary() 拼接 "IP: x.x.x.x。Hosts: server01。TTPs: T1566。"
缺失：    LLM 自然语言摘要
影响：    摘要对分析师可读性差，不能捕捉攻击语义（如"暴力破解后横向移动到文件服务器"）
```

### 2.4 三个 ML 模块是完全的空桩

| 文件 | 状态 |
|------|------|
| `aegis/inference/alert_cluster.py` | DBSCAN 聚类逻辑完整，但向量化依赖 `sentence-transformers`（未安装）→ 回退到随机向量 |
| `aegis/inference/bayesian.py` | CPT 构建逻辑完整，但 `joint_probability()` → 回退到 `_mock_probability()` |
| `aegis/sandbox/mcts.py` | UCB1 选择和反向传播完整，但 `search()` → 跳过 MCTS 直接返回输入 |

---

## 三、工程级（系统能产出，但不能部署到生产环境）

### 3.1 无持久化

```
当前状态：API 服务器的状态存储在内存的 dict 中（_fragments, _chains, _decisions）
缺失：    数据库持久化（PostgreSQL / SQLite / Neo4j）
影响：    重启丢失所有数据，不能查询历史，不能做审计
```

### 3.2 无认证授权

```
当前状态：API 完全开放（CORS origins: ["*"]），decision/approve 端点无权限控制
缺失：    JWT / OAuth2 / API key 认证
影响：    任何人都可以批准或拒绝防御决策
```

### 3.3 无前端

```
当前状态：只有 Swagger 文档页面（/docs）
缺失：    React + D3.js 攻击链可视化、实时告警看板、决策审核界面
影响：    安全分析师无法直观理解攻击链，必须手动调用 API 查看 JSON
```

### 3.4 无自动化防御执行

```
当前状态：SOAR connector 的 execute_action() 只打印日志 → 返回 PENDING
缺失：    SOAR 平台 API 集成（Splunk Phantom / Palo Alto XSOAR）
影响：    无法自动执行任何防御动作，全部依赖人工
```

### 3.5 WebSocket 存在但未集成到管道

```
当前状态：websocket.py 定义了 ConnectionManager + broadcast 方法
缺失：    在 server.py 的 fragment/chain/decision 事件处理中调用 broadcast
影响：    WebSocket 端点可以连接，但永远不会收到任何推送事件
```

---

## 四、投入估算

### 最小可用版本（2 人 × 4 周）

这个版本可以：接入一个数据源，产出攻击链，生成防御建议（不执行），用 Swagger 查看。

| 任务 | 工作量 | 依赖 |
|------|--------|------|
| 部署 Neo4j + 导入 ATT&CK | 2 天 | Docker |
| 接入 Suricata eve.json | 3 天 | 测试环境有 Suricata |
| KnowledgeGraph 切换到 Neo4j | 2 天 | Neo4j 已部署 |
| TTP 映射规则校准 | 3 天 | Suricata 规则集 |
| API 添加 JWT 认证 | 2 天 | — |
| WebSocket 集成到管道 | 1 天 | — |
| 部署到测试环境 + 影子运行 | 5 天 | 服务器 |
| **合计** | **18 天** | |

### 生产试点版本（3 人 × 8 周）

| 任务 | 工作量 | 
|------|--------|
| 以上全部 + | — |
| 接入企业 SIEM API | 1 周 |
| 部署本地 LLM（vLLM）| 1 周 |
| React 前端原型（攻击链可视化）| 3 周 |
| 数据库持久化 | 1 周 |
| SOAR 只读集成（建议模式）| 1 周 |
| 性能测试 + 安全审计 | 1 周 |
| **合计** | **8 周** |

### 完整生产版本（5 人 × 6 月）

| 任务 | 工作量 |
|------|--------|
| 以上全部 + | — |
| GraphSAGE 训练 + 部署 | 4 周 |
| GPT-4o 集成 | 2 周 |
| MCTS 实时推演 | 3 周 |
| 多轮辩论引擎 | 2 周 |
| SOAR 自动执行 | 3 周 |
| K8s 部署 | 2 周 |
| 多租户 + 计费 | 2 周 |
| 合规审计 | 2 周 |
| **合计** | **~24 周** |

---

## 五、按文件的具体差距

```
aegis/knowledge/graph.py      ███████████████ 15 mock 分支
aegis/inference/path_scorer.py ██████████      11 mock/placeholder
aegis/sandbox/red_team.py     ██████████      10 手写 fallback_map
aegis/sandbox/mcts.py         ██████           6 Phase 2 deferred
aegis/connectors/siem.py      █████            5 not yet implemented
aegis/connectors/soar.py      █████            5 not yet implemented
aegis/llm/client.py           █████            5 dependency/Phase 2
aegis/inference/alert_cluster █████            5 dependency/Phase 2
aegis/sandbox/debate.py       ████             4 Phase 2 deferred
aegis/agents/tracing.py       ████             4 Phase 2 deferred
aegis/inference/bayesian.py   ███              3 mock fallback
aegis/knowledge/attck_loader  ██               2 not yet wired
aegis/agents/* (base/det/def) ██               3 minor
config/settings.py            ██               2 mock default
```

---

## 六、立即可做的事（不需要写新代码）

1. `pip install pydantic fastapi uvicorn numpy pyyaml` → 解锁完整 Demo
2. `python -m aegis.cli demo` → 端到端验证 Agent 管道
3. `python tools/data_generator.py --scenario all --format api > demo.json` → 生成测试数据
4. `docker-compose up -d` → 启动 Kafka + Neo4j（如果装了 Docker）
5. `python tools/attck_importer.py --output import.cypher` → 生成 ATT&CK 导入脚本
