# 新数据集基线适配指南

更新：2026-09-21。适用于 TFE-GNN、Pandora_NDSS_2026、TFusion-newData&Processing。

## 1. 实验范围

任务为跨数据集、闭集五分类：正常流量 + 四类攻击。主实验采用目标域 **每类 10-shot**，不做 zero-shot 或新增攻击类识别。本轮先完成以下两个方向，不先在各模型原论文数据集上重复训练。

| 实验 | 源域 A | 目标域 B |
|---|---|---|
| 2017 → 2018 | CICIDS2017 | CSE-CIC-IDS2018（已下载的主机子集） |
| 2018 → 2017 | CSE-CIC-IDS2018（同一子集） | CICIDS2017 |

| 统一 ID | 统一类别 | CICIDS2017 对应攻击/日期 | CSE-CIC-IDS2018 对应攻击/日期 |
|---|---|---|---|
| 0 | Benign | 所选日期中确认正常的流量 | 所选日期中确认正常的流量 |
| 1 | SSH-BruteForce | SSH-Patator；7 月 4 日（周二） | SSH-Bruteforce；2 月 14 日 |
| 2 | DoS-GoldenEye | DoS GoldenEye；7 月 5 日（周三） | DoS attacks-GoldenEye；2 月 15 日 |
| 3 | DoS-Slowloris | DoS slowloris；7 月 5 日（周三） | DoS attacks-Slowloris；2 月 15 日 |
| 4 | Botnet-Ares | Bot 中的 Ares 通信；7 月 7 日（周五） | Bot 中的 Ares 通信；3 月 2 日 |

只保留上述共享类别。其他攻击及无法确定标签的流量剔除，不能归为 Benign，也不进入无标签适配数据。Infiltration-Nmap 尚为候选、原始数据未补齐，本轮不加入；HyperVision、DoH2020 也不纳入本轮。所选数据不能整体称为“加密流量数据集”。

## 2. 服务器数据位置与状态

连接：`ssh -p 28085 root@cpod-1tkwezgklh5r.podtcp.compshare.cn`

CICIDS2017、CSE-CIC-IDS2018 已下载并存放在服务器的共用目录 `ETC-datasets` 中，与本地采用相同的共用源数据组织方式。TFE-GNN、Pandora_NDSS_2026、TFusion-newData&Processing 均从该目录读取，不再分别下载或复制原始数据。

各项目通过 `DATASET_ROOT` 配置服务器上 `ETC-datasets` 的实际绝对路径；本文件不假定其父目录。下表用于定位所需文件，具体子目录以 `ETC-datasets` 当前布局为准。

| 数据 | 所需文件名 / 路径后缀 | 用途 |
|---|---|---|
| 2017 周二 | `CICIDS2017-Tuesday-WorkingHours.pcap` | SSH + 正常流量 |
| 2017 周三 | `CICIDS2017-Wednesday-workingHours.pcap` | GoldenEye、Slowloris + 正常流量 |
| 2017 周五 | `CICIDS2017-Friday-WorkingHours.pcap` | Ares + 正常流量 |
| 2018 2 月 14 日 | `CICIDS2018_selected/Wednesday-14-02-2018/UCAP172.31.69.25.pcap` | SSH + 正常流量 |
| 2018 2 月 15 日 | `CICIDS2018_selected/Thursday-15-02-2018/UCAP172.31.69.25.pcap` | GoldenEye、Slowloris + 正常流量 |
| 2018 3 月 2 日 | `CICIDS2018_selected/Friday-02-03-2018/*.pcap` | 10 台感染主机的 11 份文件；Ares + 正常流量 |

2018 的 11 个文件名均以 `capEC2AMAZ-O4EL3NG-172.31.69.` 开头，后缀为 `6、8、10、12、14、17、23、26、26a、29、30`，扩展名为 `.pcap`；`26a` 是分片，不是额外主机。

当前状态：两个数据集所需原始数据均已在服务器 `ETC-datasets` 就绪。此前下载的 2018 核心子集为 13 份 PCAP，约 1.93 GB，已通过原 ZIP 成员大小与 CRC 校验。**这是原始文件就绪，不代表标签、切流和训练输入已经就绪。** 这些主机文件包含背景及其他流量，不能按文件名直接赋攻击标签。

2017 原始 CSV 从共用数据目录中定位 `MachineLearningCVE`，仅作辅助核对，不能按 CSV 行号与重新切分的流直接对齐。原始文件保持不变，各模型的编码缓存、检查点和结果存入各自项目的输出目录。

## 3. 数据适配流程：统一清单，分别生成模型输入

1. **切流与标签统一。** 从 PCAP 建立双向连接/流，统一超时、时间单位和时区；保存五元组、起止时间、来源和稳定的 `flow_id`。结合攻击主机、时间与连接行为标注，参考已发表的修正标签规则，尤其核对 Ares；不要仅按攻击时间段给全部流量打标签。
2. **对齐有效样本。** 先检查三个模型的输入要求，再冻结共同可用的流集合。TFE-GNN 需要真实报文头/载荷，且原实现会过滤无载荷流；记录每类过滤前后数量。不能用统计 CSV 伪造报文字节，也不能让各模型静默使用不同测试样本。
3. **保存关联信息。** 对 2018 多主机 PCAP 对齐同场景时间并去重，保留真实 IP、端口和时间供关系构建；不要让文件边界切断跨主机关系。标签不作为输入特征。
4. **一次生成公共划分。** 按完整连接和时间块划分，避免同一连接的片段或重复包跨集合。每个方向保存源域训练/验证集、目标域 support/query 清单；所有模型直接读取这些清单，不重新随机划分。若限量采样以节省训练时间，公共清单统一限量。
5. **各模型独立编码。** 同一 `flow_id` 可以生成不同的原生输入：报文字节、序列、图等。缓存预处理结果，避免重复切流。具体编码遵循各模型原实现。

修正标签参考入口：[CICIDS2017 审计](https://intrusion-detection.distrinet-research.be/CNS2022/CICIDS2017.html)、[CSE-CIC-IDS2018 审计](https://intrusion-detection.distrinet-research.be/CNS2022/CSECICIDS2018.html)、[修正标注代码](https://github.com/GintsEngelen/CNS2022_Code/tree/main/Labelling)。实现时记录实际采用的规则及版本。

## 4. 统一训练与测试协议

**所有有监督基线先在源域训练集上训练，再从该检查点出发，使用完全相同的目标域 10-shot 标注样本进行监督微调，最后在同一目标域 query 集上测试。**

- 10-shot 指每类 10 条独立流，包含 Benign，即五类共 50 条目标域标注流；同一连接切出的多个片段不能重复计作多个 shot。support 与 query 不重叠。
- 保留模型原有主干、网络结构、输入编码与核心损失；分类输出统一为 5 类。只做数据接口、类别数和两阶段训练入口所需的适配，不引入 HyperTraffic 的超图模块。若原任务不支持此多分类微调，先说明所需改动，不能把另造的网络当作原基线。
- 源域检查点及超参数通过源域验证集选择；微调轮数预先固定，不用目标域 query 标签早停、调参或选最好一轮。归一化等拟合步骤使用源域训练数据；本轮不使用 query 拟合预处理或参与适配训练。
- 默认微调全模型参数；模型原实现若有必要的冻结策略，明确记录。不同 support 种子从同一个源域检查点重新开始，不能接着上一次微调继续训练。
- 主结果建议固定 3 个种子（42、43、44），各模型共享对应种子的 support/query 清单。先完成两个方向各一次完整运行，再补齐重复实验；单次结果不写成多次均值。
- 若后续扩展其他 x-shot，保持 query 固定、support 尽量嵌套，并复用源域检查点；本轮先完成 10-shot。

该流程是本轮基线的统一适配协议。HyperTraffic 若仍采用源域与目标域 support 联合训练，应单独注明训练差异，并保持相同的目标域标注预算和测试集合。

## 5. 交付与结果记录

公共预处理应交付 `label_map.json`、带 `flow_id` 与标签的流索引、两个方向各随机种子的划分清单，以及每类保留/剔除数量。**这些是待生成产物，当前尚不存在统一可训练版本。** 三个项目应复用同一份产物。

每次实验保存数据清单版本、种子、配置、源域/微调检查点、逐流预测与训练耗时。统一报告 Macro-F1（主指标）、每类 Precision/Recall/F1、Accuracy 和混淆矩阵；重复实验报告均值与标准差。类别顺序固定为本文件的 ID 0–4。

本地历史下载记录位于 LHCCA 项目的 `docs/dataset_inventory/server.json`、`server-download-state.json` 和 `transfer-status.json`。其中旧路径可能早于共用目录调整；当前源数据位置以服务器 `ETC-datasets` 为准，不再使用旧的项目内数据路径作为适配默认值。公共流索引和划分清单生成后应集中保存，供三个项目共同引用。
