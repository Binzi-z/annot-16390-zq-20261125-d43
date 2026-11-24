# 隔离升级 · 双凭据切换与恢复（离线演练工具）

给**两组隔离工作站**做演练：批准从**旧保护配置**迁移到**新配置**。
使用**原生 Windows + Python 3.12 标准库**实现，完全离线，只处理**合成配置文件**，
不接触任何真实工作站、真实密钥或外部服务。

> 运行：`py -3.12 run_drill.py`（或 `python -m iso_drill`）
> 测试：`py -3.12 run_tests.py`（或 `python -m unittest discover -s tests -t .`）

---

## 1. 题面要求 → 实现位置

| 要求 | 实现 |
|---|---|
| 两组隔离工作站 | `iso_drill/__init__.py` 的 `grp-bench-01/02`；`world.py` |
| 旧→新，串联**两个中间版本**，每步独立可复核批准 | 每代策略代 1→2(A)→3(B)→4(新)，每组 **3 步**，每步一份双签批准：`world.py` |
| 采购签发者 + 设备安全员**独立签署** | `pki.py` 两角色席位；`approval.py` 两签名块 |
| **同一根控制人不能占两席** | `pki.assert_distinct_roots`，构造期 + 复核期双强制；反例测试 |
| 签名绑定**实际配置摘要 / 目标设备组 / 策略代**（另绑前驱摘要） | `approval.build_approval` 签名 payload；`bind_actual_config` 对**实际落盘字节**重算 |
| 两个线程分别**提交 / 吊销** | `service.DrillService.submit/revoke`；`scenarios.scenario_revoke_preempt` |
| **可控屏障** | `faults.Gate`（单门）、`faults.Rendezvous`（N 方 `Barrier`） |
| **本地故障点** | `faults.FaultPlan`：`after_switch`、`after_receipt_persist`，可注入崩溃/删文件/调包 |
| 覆盖**吊销抢先** | `scenario_revoke_preempt`：提交线程在线性化段前门外等待，吊销线程抢先写 `REVOKED` |
| 覆盖**切换后持久化回执丢失** | `scenario_receipt_crash_before_write`（切换后/回执前“崩溃”）与 `scenario_receipt_deleted_after_persist`（回执写盘后被删） |
| 覆盖**同号异摘要** | 绑定层反例、故障点越界调包、双线程 `Barrier` 同号异摘要分叉竞争 |
| 恢复后用**实际落盘配置 + 决定日志重算最短证据** | `recovery.Recovery.shortest_evidence`：重哈希活动文件、校验哈希链日志、逐份独立复核批准、BFS 求基线→活动摘要最短链 |
| **旧有合法配置不能被并发更新误删** | `configstore` 内容寻址只增不删 + 保护集；`scenario_concurrent_preservation` 8 线程更新/GC 压力 |
| **60000 条**记录，受影响组增量 vs 全量，报告各阶段实际比对数 | `scale_diff.py`、CLI 表格、`tests/test_scale_diff.py` |

密码学为纯标准库实现的 **Ed25519（RFC 8032，见 `ed25519.py`）**，
测试内置 RFC 8032 已知答案向量。它用于演练“可独立验签”，**不是**生产密钥方案；
真实部署应使用经过审计的密码库 + HSM/DPAPI/智能卡保护根密钥。

---

## 2. 磁盘布局（每次演练一个全新目录）

```
<work>/
  trust_anchors.json        两个独立根控制人的公钥锚点
  decisions.jsonl           哈希链决定日志（REVOKED / SUBMIT_* / COMMITTED ...）
  cfg/
    objects/<sha256>.json   内容寻址、不可变的所有配置版本（旧配置永不被覆盖）
    active/<group>.json     每组当前“实际生效”的配置文件（os.replace 原子切换）
    baselines.json          受信旧基线摘要
  approvals/<APR-…>.json     双签批准书（可拷给离线复核人独立验证）
  receipts/<APR-…>.receipt.json
  evidence/<group>.shortest.json  恢复时重算出的最短证据报告
  scenarios/<scenario>/...  各故障场景独立工作目录
  report.json / REPORT.md   总报告
```

---

## 3. 并发正确性要点

- 提交与吊销共用同一把 `commit_lock`，使“吊销决定”和“提交线性化段”有确定先后；
  编排用 `Gate/Barrier` **确定性**排出“吊销抢先”，不靠 `sleep` 碰运气。
- 门放在锁外等待，避免“持锁等门 → 吊销线程进不来”的死锁。
- 线性化点依次做：吊销裁决 → **前驱 CAS**（活动摘要必须仍是本批准绑定的前驱）
  → 原子切换 → **从磁盘重读并比对摘要** → 写回执。
  因此“同号异摘要”的并发分叉只有一个能提交；越界调包会被重读拦截，且不会写出假回执。
- 吊销状态的唯一来源是哈希链决定日志中的 `REVOKED` 记录，重启后重放得到。

---

## 4. 最短证据是怎么“重算”的

恢复器不相信任何内存态或回执，只做：

1. 重开并校验 `decisions.jsonl` 哈希链，重放吊销集合；
2. 直接哈希 `cfg/active/<g>.json` 得到“当前实际摘要”；
3. 逐份独立复核 `approvals/*.json`（Ed25519、证书锚定、异根、吊销），并要求
   目标对象在 `cfg/objects/` 真实存在且重算摘要一致、决定日志中有其记录，
   才形成 `predecessor → target` 证据边；
4. 从受信基线 BFS 到当前实际摘要，边数最少的链即**最短证据**；
5. 标注丢失的原始回执（**不伪造**），另写 `evidence/<g>.shortest.json`；
6. 用重算出的合法端点重新武装保留保护，阻止 GC 删除旧合法配置。

---

## 5. 60000 条比对：口径与确定数量

20 个组按块均分 60000 条 = **3000 条/组**；两个受影响组即 `grp-bench-01/02` = **6000 条**。
只在这两个组内各改 120 条，共 **240** 条变更，组外零变更。

“比对”按实际比较次数计数（不是扫描条数）：

| 阶段 | 实际比对数量 |
|---|---:|
| 增量·阶段1 组聚合根比对（20 组各 1 次） | **20** |
| 增量·阶段2 受影响组内记录摘要比对（2×3000） | **6000** |
| 全量·逐条记录摘要比对 | **60000** |

两种方法得到的变更集合经断言**完全等价**（均为那 240 条）。
小样本（2000 条 = 100/组）的对应数量是 20 次根比对、200 次增量记录比对、2000 次全量比对。

---

## 6. 目录与退出码

- `python run_drill.py --work artifacts/run [--scale 60000]`
  运行 8 个场景 + 规模比对，生成 `report.json` / `REPORT.md`；全过退出码 0，否则 1。
- `python run_tests.py`：标准库 `unittest`（含 RFC 8032 向量、绑定篡改、日志篡改、
  全部场景、并发保留、60k 计数）。
- `python scratch_ed_check.py`：单独打印 Ed25519 向量与耗时。

> 说明：`artifacts/` 已在 `.gitignore` 中，运行产物不会入库。
