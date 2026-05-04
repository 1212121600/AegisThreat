# AegisThreat 生产就绪度评估

评估日期：2026-05-04 | 版本：v0.1 (Phase 0 MVP)

---

## 一、结论：当前不能投入生产使用

AegisThreat 处于 **Phase 0（概念验证 / MVP 脚手架）** 阶段。项目可以用作：

- 架构参考和设计评审
- 合成数据生成与演示
- 攻击路径推理的可视化原型
- 安全编排决策的流程验证

**不能用于**：任何生产环境的实时威胁检测、自动溯源或防御执行。

---

## 二、当前状态：模块可用性矩阵

### 已验证可用（VM 沙箱中实测通过）

| 模块 | 功能 | 依赖 | 状态 |
|------|------|------|------|
| `tools/data_generator.py` | 4 个 APT 场景合成数据 | Python 标准库 | ✅ 已测试 |
| `aegis/inference/path_pruner.py` | 攻击路径 BFS + 剪枝 | Python 标准库 | ✅ 已测试 |
| `aegis/sandbox/red_team.py` | 三级红队策略模拟 | Python 标准库 | ✅ 已测试 |
| `aegis/sandbox/arbitrator.py` | 防御策略量化仲裁 | Python 标准库 | ✅ 已测试 |
| `aegis/llm/client.py` | LLM 客户端（无后端时优雅降级）| httpx (可选) | ✅ 已测试 |
| `aegis/connectors/soar.py` | SOAR Playbook 构建与人工导出 | Python 标准库 | ✅ 已测试 |
| `aegis/connectors/siem.py` | SIEM 适配器接口（Suricata 文件读取可用）| Python 标准库 | ✅ 已测试 |
| `aegis/inference/alert_cluster.py` | DBSCAN 聚类 | numpy + sklearn | ✅ 已测试（向量化未实现） |
| `aegis/inference/bayesian.py` | 贝叶斯概率推理 | Python 标准库 | ✅ 已测试 |
| `aegis/sandbox/mcts.py` | MCTS 博弈推演 | Python 标准库 | ✅ 已测试 |
| `aegis/sandbox/debate.py` | 辩论引擎 | Python 标准库 | ✅ 已测试 |

### 需外部依赖（`pip install -e .` 后可用）

| 模块 | 阻塞依赖 | 说明 |
|------|---------|------|
| `aegis/core/models.py` | **pydantic** | 核心数据模型，一切 Agent 的前置条件 |
| `aegis/core/bus.py` | pydantic + kafka-python (可选) | InMemoryBus 开箱即用 |
| `aegis/core/security.py` | pydantic | HMAC 签名 + 防重放 |
| `aegis/agents/detection.py` | pydantic + numpy | 侦测 Agent（告警聚合） |
| `aegis/agents/tracing.py` | pydantic | 溯源 Agent（攻击链推理） |
| `aegis/agents/defense.py` | pydantic | 防御 Agent（策略生成） |
| `aegis/api/server.py` | pydantic + fastapi + uvicorn | REST API 服务器 |
| `aegis/api/websocket.py` | fastapi | WebSocket 实时推送 |

### 完全不可用（Phase 2+ 的 ML 训练管线）

| 功能 | 缺少什么 |
|------|---------|
| DBSCAN 实时告警聚类 | 真实告警数据 + sentence-transformers 模型 |
| GraphSAGE 路径评分 | PyTorch Geometric + 标注攻击链训练数据 |
| 贝叶斯网络推理 | 真实环境检测覆盖率数据 |
| MCTS 博弈推演 | SOAR API 集成 + 模拟环境 |
| LLM 语义验证 | GPT-4o API key 或本地 GPU 部署 vLLM |
| SOAR 自动执行 | SOAR 平台 API 凭证和权限 |
| SIEM 实时接入 | SIEM API 凭证 + 网络连通性 |
| WebSocket 实时看板 | 前端 React 应用 |

---

## 三、当前可以做什么

### 3.1 生成攻击演示数据

```bash
cd D:\code\AegisThreat

# 生成 JSON 告警数据
python tools/data_generator.py --scenario phishing-to-exfil --format api --output demo_alerts.json

# 查看所有可用场景
python tools/data_generator.py --list
```

输出 4 个场景的完整告警时间线，可直接 `POST` 到 API。

### 3.2 攻击路径可视化推理

```python
from aegis.inference.path_pruner import anchor_based_bfs

adjacency = {
    "T1566": ["T1059", "T1204"],
    "T1059": ["T1003", "T1083"],
    ...
}
paths = anchor_based_bfs(adjacency, observed_ttps=["T1566"], max_depth=6)
for path in paths:
    print(" → ".join(path))
```

### 3.3 红蓝对抗推演

```python
from aegis.sandbox.red_team import RedTeamSimulator, APT_ATTACKER
sim = RedTeamSimulator(seed=42)

# 模拟攻击者对防御措施的响应
for action in ["T1566", "T1059", "T1071"]:
    next_move = sim.simulate_response(action, APT_ATTACKER)
    print(f"Block {action} → attacker tries {next_move}")
```

### 3.4 防御策略仲裁

```python
from aegis.sandbox.arbitrator import Arbitrator
arb = Arbitrator(max_rounds=3, coverage_threshold=0.6)

chain_ttps = ["T1566", "T1059", "T1003"]
defense = [
    {"action": "block_ip", "expected_effect": "T1566", "reason": "...", "target_ttp": "T1566"},
    {"action": "kill_process", "expected_effect": "T1059", "reason": "...", "target_ttp": "T1059"},
]
verdict = arb.evaluate(1, chain_ttps, defense, business_impact_score=25)
print(f"Coverage: {verdict.coverage_score:.0%}, Accepted: {verdict.defense_accepted}")
```

### 3.5 SOAR Playbook 导出

```python
from aegis.connectors.soar import SOARConnector
soar = SOARConnector(dry_run=True)
playbook = soar.build_playbook("dec-001", defense_steps, impact_score=35)
print(soar.export_for_manual(playbook))
# → 可打印的人类可读操作手册
```

### 3.6 完整 Agent 管道（需要先安装依赖）

```bash
# 1. 安装
pip install -e D:\code\AegisThreat

# 2. 运行端到端演示
python -m aegis.cli demo --scenario phishing-to-exfil

# 3. 启动 API 服务器
python -m aegis.cli server
# 访问 http://localhost:8000/docs 查看 Swagger

# 4. 在其他终端发送测试告警
curl -X POST http://localhost:8000/alerts \
  -H "Content-Type: application/json" \
  -d '{"rule_name":"brute_force","source_ip":"1.2.3.4","destination_ip":"10.0.0.5","action":"failed login","severity":"high"}'
```

---

## 四、达到生产就绪还需要什么

### 阶段 A：最小可行生产（还需 3-6 个月）

- [ ] 接入一个真实数据源（Suricata eve.json 最简单）
- [ ] 在一个测试环境影子模式运行 30 天
- [ ] 与安全分析师人工研判结果对比，积累标注
- [ ] 根据标注结果调优 TTP 映射规则
- [ ] 实现基本的告警去重和抑制
- [ ] 添加 API 认证和速率限制
- [ ] 审计日志持久化到文件/数据库

### 阶段 B：生产试点（还需 6-12 个月）

- [ ] 接入企业 SIEM（Splunk/Elastic）API
- [ ] 部署 Neo4j 知识图谱并导入 ATT&CK 数据
- [ ] 部署本地 LLM（vLLM + Llama-3-8B）用于告警摘要
- [ ] 实现基于规则的自动响应（低风险动作）
- [ ] 构建安全运营看板（React 前端）
- [ ] 建立模型性能监控和漂移检测

### 阶段 C：完整生产（还需 12-18 个月）

- [ ] GraphSAGE 模型训练和部署
- [ ] GPT-4o 集成（高置信度路径验证）
- [ ] 贝叶斯网络在线学习
- [ ] SOAR 平台 API 直连
- [ ] MCTS 实时推演
- [ ] 多租户支持
- [ ] K8s 部署和自动扩缩

---

## 五、诚实的使用建议

**如果你是安全研究者/学生：**
这个项目是一个非常好的学习材料。研究 Agent 间通信模式、ATT&CK 图谱建模、攻击链推理算法。运行 `python tools/data_generator.py` 和 `python -m aegis.cli demo` 来理解整个流程。

**如果你是安全团队负责人：**
不要部署到生产环境。但可以：
1. 在隔离环境运行影子模式，产出建议不执行
2. 用合成数据验证你的检测规则是否覆盖了关键 ATT&CK 技术
3. 将 SOAR playbook 导出功能用于编写响应 runbook 的起点

**如果你是投资者/决策者：**
架构设计是合理的，技术选型是务实的。但需要 12-18 个月 + 一个完整的工程团队才能达到生产就绪。当前阶段的合理价值在于：证明多 Agent 协作的攻击链推理在技术上是可行的。
