"""隔离工作站保护配置迁移：双凭据批准、并发提交/吊销、故障恢复取证与增量比对演练工具。

仅使用 Python 3.12 标准库，离线运行，只处理合成数据。

模块划分：
- ed25519:   纯标准库 Ed25519(RFC 8032) 非对称签名，席位公钥可独立复核
- encoding:  规范化 JSON / 实际文件摘要 / 原子落盘
- pki:       根控制人 -> 席位证书体系，强制两席根控制人不同
- configstore: 合成保护配置 + 内容寻址对象库 + 原子切换 + 合法配置保留
- approval:  绑定(实际摘要, 目标设备组, 策略代, 前驱摘要)的双签批准与链
- journal:   哈希链决定日志(JSONL)
- faults:    可控屏障 / 故障注入点
- service:   提交/吊销两线程共用的迁移服务(确定性竞争编排)
- recovery:  从实际落盘配置 + 决定日志重算最短证据(BFS)
- world:     合成 PKI / 两组工作站 / 两中间版本链的装配工厂
- scale_diff: 60000 条记录的受影响组增量 vs 全量比对与计数
- scenarios: 三个必盖故障场景 + 完整演练编排
- cli:       `python run_drill.py` / `python -m iso_drill`
"""

__version__ = "1.0.0"

# 两个隔离工作站组（题面中的“两组隔离工作站”）
GROUP_BENCH_01 = "grp-bench-01"
GROUP_BENCH_02 = "grp-bench-02"
DRILL_GROUPS = (GROUP_BENCH_01, GROUP_BENCH_02)

# 两个席位角色
ROLE_PROCUREMENT = "procurement_issuer"
ROLE_SAFETY = "device_safety_officer"

ROLE_LABELS_ZH = {
    ROLE_PROCUREMENT: "采购签发者",
    ROLE_SAFETY: "设备安全员",
}
