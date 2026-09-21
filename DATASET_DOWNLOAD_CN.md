# 数据下载与离线记录（2026-09-20）

当前主实验为 CICIDS2017 ↔ CSE-CIC-IDS2018，x-shot，不做 zero-shot。
默认下载的类别范围：Benign、SSH-BruteForce、DoS-GoldenEye、DoS-Slowloris、Botnet-Ares。
Infiltration-Nmap 是候选，不默认下载；需先确认 TFE-GNN 过滤后是否仍有足够样本及扫描结构。

## 已有数据

本地项目和服务器 `/LHCCA/Traffic_datasets` 都有2017周二、周三、周五PCAP，以及 HyperVision 压缩包。
2017周四只有CSV，缺原始PCAP。完整文件路径、大小、观察时间见：

- `docs/dataset_inventory/local.json`：本地盘点。
- `docs/dataset_inventory/server.json`：服务器最近一次盘点的本地副本。
- `docs/dataset_inventory/download-plan.json`：已验证的远端成员目录、偏移、大小、CRC、ETag。

盘点中的 `present_not_content_verified` 只表示文件存在；不代表原始文件内容已校验或数据已经适合训练。
服务器快照是某个时间点的记录，不会在服务器离线时自动更新。

## 文件与下载范围

下载清单：`configs/cicids2018_download.json`。

| 下载组 | 日期与主机 | 用途 | 压缩数据量 |
|---|---|---|---:|
| core | 2月14日，172.31.69.25 | SSH与正常背景 | 419,348,396字节 |
| core | 2月15日，172.31.69.25 | GoldenEye、Slowloris与正常背景 | 120,661,078字节 |
| core | 3月2日，10台感染主机的11份文件 | Ares与正常背景 | 622,089,108字节 |
| infiltration | 2月28日，172.31.69.24的两个分片 | 内网扫描候选 | 388,305,919字节 |
| infiltration_extra | 3月1日，172.31.69.13的三个分片 | 后续扩展 | 258,961,854字节 |

core 共13个文件、1,162,098,582字节压缩数据。不下载整日几十GB的ZIP，不下载2月20日RAR。
清单是主机级采集范围，不是攻击过滤规则。原始PCAP还包含其他流量；后续仍须切流、修正标签、去重和准备模型输入。
若实验需要更多独立正常主机，可以在清单中增加ZIP成员，无需重下已完成成员。
2018按主机采集的PCAP需在后续处理时对齐时间与场景，不能让文件边界切断Ares等跨主机关系。

## 服务器运行

部署目录：`/LHCCA/dataset_download_20260920`，与现有训练代码分开。
原始数据目录：`/LHCCA/Traffic_datasets/CICIDS2018_selected`。
只依赖 Linux/macOS 的 Python 3.9+ 标准库。Windows可在WSL使用。

```bash
cd /LHCCA/dataset_download_20260920

# 只查看所需文件，不下载PCAP
python3 scripts/download_cicids2018.py plan \
  --output /LHCCA/Traffic_datasets/CICIDS2018_selected

# 在后台会话下载；SSH断开仍继续。已有同名会话时先查看它，不重复启动。
tmux new-session -d -s cicids2018-download \
  'CICIDS_DIRECT=1 DATASET_ROOT=/LHCCA/Traffic_datasets bash /LHCCA/dataset_download_20260920/scripts/run_cicids2018_download.sh'

# 查看进度
tail -n 15 logs/cicids2018_download.log
tmux attach -t cicids2018-download
# tmux中按 Ctrl+B，再按 D，离开会话而不停止下载。
```

进程中断/机器重启后，重复上述启动命令恢复。若会话尚在运行，无需重复运行。
也可前台运行：

```bash
CICIDS_DIRECT=1 DATASET_ROOT=/LHCCA/Traffic_datasets bash scripts/run_cicids2018_download.sh

# 仅当决定取候选扫描数据时运行；同时仍需补2017周四PCAP
CICIDS_DIRECT=1 DATASET_ROOT=/LHCCA/Traffic_datasets bash scripts/run_cicids2018_download.sh infiltration
```

## 续传与校验

- `.part` 保存成员的压缩字节；`.part.json` 保存远端对象与成员信息。
- 每次运行读取本地文件实际长度，从该位置继续请求；网络错误自动有限重试，耗尽后保留数据供下次恢复。
- 请求携带ETag条件，远端内容变化则停止，避免拼接不同版本。
- 只接受服务器明确返回的正确范围响应，防止服务器忽略Range而下载整个ZIP。
- 解压后核对成员大小和ZIP CRC，再原子改名为 `.pcap`。CRC检查传输完整性，不是攻击标签校验。
- 成功后删除该成员的临时压缩文件；重新运行会核对并跳过已有正确PCAP。
- 不覆盖已有但校验不符的PCAP。出现这类错误时先检查文件来源。
- `.download.lock` 防止两个脚本同时向同一目录写入。
- 2026-09-20修复：服务器默认代理链路实测只有14–29 KB/s；直连1 MiB测试约353 KB/s。因此服务器启动命令使用 `CICIDS_DIRECT=1`，仅此下载进程忽略环境代理，不修改系统代理。CLI可直接使用 `--direct`。
- 分段从8 MiB缩小为1 MiB；读取采用小块并检查60秒传输预算，单次阻塞I/O超时15秒，避免持续慢速返回导致请求无限拖长。预算检查最多受一次阻塞I/O延后约15秒；旧 `.part` 兼容新脚本。
- `download-state.json` 每完成一段数据就更新。`logs/download.exit-code` 为0表示本次命令成功，非0表示需查看日志；运行中该文件不存在。

## 本地下载后中转（当前采用）

2026-09-20 23时排查结果：AWS返回206，无验证码或登录等待；服务器默认代理慢，直连约353 KB/s；本地8 MiB试传下载约3.4 MB/s，上传8 MiB约10秒。因此停止旧服务器下载，保留断点，改为本地下载剩余12个文件再上传。
`docs/dataset_inventory/local-transfer-manifest.json` 是这次生成的剩余清单，不包含服务器已校验完成的2月14日SSH文件。

```bash
# 本地运行；需使用配置了CA证书的Python。以下为本机的可用解释器。
/Users/wendyc/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/bin/python3 \
  scripts/download_cicids2018.py download \
  --manifest docs/dataset_inventory/local-transfer-manifest.json --chunk-mib 8

# 本地运行，可重复执行。只传已完成PCAP，不传下载状态或.part。
bash scripts/sync_cicids2018_to_server.sh

# 上传结束后，在服务器离线校验原来核心组的13个文件，不再访问AWS。
python3 /LHCCA/dataset_download_20260920/scripts/download_cicids2018.py verify \
  --output /LHCCA/Traffic_datasets/CICIDS2018_selected
```

rsync使用压缩传输；上传中断会保存 `.rsync-partial`，下次运行恢复。旧服务器下载的 `.pcap.part` 是另一种压缩流，不与rsync的临时文件混用。`--ignore-existing` 不覆盖已有最终PCAP，最终仍必须运行CRC校验。

## 更新本地离线快照（操作）

先在服务器生成最新盘点，再从本地取回小型JSON；无需同步PCAP：

```bash
ssh -p 28085 root@cpod-1tkwezgklh5r.podtcp.compshare.cn \
  'python3 /LHCCA/dataset_download_20260920/scripts/download_cicids2018.py inventory --scan-root /LHCCA/Traffic_datasets --output /LHCCA/Traffic_datasets/CICIDS2018_selected --report /LHCCA/dataset_download_20260920/docs/dataset_inventory/server.json'

# 在本地LHCCA项目根目录执行
scp -P 28085 root@cpod-1tkwezgklh5r.podtcp.compshare.cn:/LHCCA/dataset_download_20260920/docs/dataset_inventory/server.json \
  docs/dataset_inventory/server.json
scp -P 28085 root@cpod-1tkwezgklh5r.podtcp.compshare.cn:/LHCCA/Traffic_datasets/CICIDS2018_selected/download-state.json \
  docs/dataset_inventory/server-download-state.json
```

## 验证与范围限制

`python3 tests/test_cicids2018_download.py` 启动仅监听本机的临时HTTP服务，检查ZIP64成员头、deflate/stored解压、中断续传、完整文件跳过、拒绝覆盖错误文件、拒绝忽略Range的服务器。

脚本不下载2017周四、DoH2020，也不清洗标签或开始训练。2017核心原始数据已存在，因此不重复下载。
如需本地运行，使用具有有效CA证书配置的Python；不要关闭TLS证书验证来绕过环境问题。

数据源：https://registry.opendata.aws/cse-cic-ids2018/
