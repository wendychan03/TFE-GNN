"""Stream CICIDS2017/2018 PCAPs into the shared five-class TFE input."""

from __future__ import annotations

import argparse
import hashlib
import heapq
import json
import os
import random
from collections import Counter, OrderedDict, defaultdict
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np

from preprocessing_utils import sanitize_tcp_header


LABELS = {
    0: "Benign",
    1: "SSH-BruteForce",
    2: "DoS-GoldenEye",
    3: "DoS-Slowloris",
    4: "Botnet-Ares",
}
RULE_SOURCES = {
    "version": "CNS2022 corrected CICFlowMeter labelling, accessed 2026-09-21",
    "cicids2017": "https://github.com/GintsEngelen/CNS2022_Code/blob/main/Labelling/CICIDS2017_labelling_fixed_CICFlowMeter.ipynb",
    "cicids2018": "https://github.com/GintsEngelen/CNS2022_Code/blob/main/Labelling/CICIDS2018_labelling_fixed_CICFlowMeter.ipynb",
    "attempted_flows": "excluded",
    "other_attacks": "excluded",
}
MAX_PACKETS = 50
HEADER_BYTES = 40
PAYLOAD_BYTES = 150
PAD = 256
INFECTED_2017 = {"192.168.10.15", "192.168.10.9", "192.168.10.14", "192.168.10.5", "192.168.10.8"}


@dataclass(frozen=True, slots=True)
class PacketBytes:
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    flags: int
    header: bytes
    payload: bytes
    digest: bytes
    source: str
    capture: str


@dataclass(slots=True)
class Flow:
    key: tuple
    start: float
    end: float
    first_src: str
    first_dst: str
    first_sport: int
    first_dport: int
    capture: str
    sources: set[str] = field(default_factory=set)
    headers: list[bytes] = field(default_factory=list)
    payloads: list[bytes] = field(default_factory=list)
    fwd_payload: int = 0
    bwd_payload: int = 0
    fwd_rst: int = 0
    bwd_rst: int = 0
    fwd_packets: int = 0
    bwd_packets: int = 0

    def append(self, packet: PacketBytes) -> None:
        self.end = packet.timestamp
        self.sources.add(packet.source)
        forward = (packet.src_ip, packet.src_port) == (self.first_src, self.first_sport)
        if forward:
            self.fwd_payload += len(packet.payload)
            self.fwd_rst += int(bool(packet.flags & 0x04))
            self.fwd_packets += 1
        else:
            self.bwd_payload += len(packet.payload)
            self.bwd_rst += int(bool(packet.flags & 0x04))
            self.bwd_packets += 1
        if packet.payload and len(self.payloads) < MAX_PACKETS:
            self.headers.append(packet.header[:HEADER_BYTES])
            self.payloads.append(packet.payload[:PAYLOAD_BYTES])

    @property
    def duration(self) -> float:
        return self.end - self.start


def canonical_key(packet: PacketBytes) -> tuple:
    return tuple(sorted(((packet.src_ip, packet.src_port), (packet.dst_ip, packet.dst_port))))


def _forward(flow: Flow, src: str, dst: str, port: int | None = None) -> bool:
    return (
        flow.first_src == src
        and flow.first_dst == dst
        and (port is None or flow.first_dport == port)
    )


def classify_2018(flow: Flow) -> tuple[int, str]:
    start = flow.start
    if _forward(flow, "18.221.219.4", "172.31.69.25") and 1518618806 <= start <= 1518624631:
        return -1, "FTP brute-force attempted"
    if _forward(flow, "13.58.98.64", "172.31.69.25") and 1518631281.199541 <= start <= 1518631281.502585:
        return -1, "FTP-mode launch artefact"
    if _forward(flow, "13.58.98.64", "172.31.69.25", 22) and 1518631310 <= start <= 1518636750:
        return (1, "audited SSH endpoint/port/time") if flow.fwd_payload else (-1, "SSH attempted: empty forward payload")

    if _forward(flow, "18.219.211.138", "172.31.69.25") and 1518701262 <= start <= 1518703905:
        if not flow.fwd_payload:
            return -1, "GoldenEye attempted: empty forward payload"
        if flow.fwd_rst and flow.duration < 5.05:
            return -1, "GoldenEye attempted: reset before 5.05 seconds"
        if flow.bwd_rst == 1 and not flow.bwd_payload and flow.duration > 100:
            return -1, "GoldenEye attempted: target unresponsive"
        return 2, "audited GoldenEye endpoint/time/flow conditions"

    if _forward(flow, "18.217.165.70", "172.31.69.25") and 1518706812 <= start <= 1518709321:
        return (3, "audited Slowloris endpoint/time") if flow.fwd_payload else (-1, "Slowloris attempted: empty forward payload")

    if 1520000008 <= start <= 1520020492 and "18.219.211.138" in (flow.first_src, flow.first_dst):
        if not (flow.fwd_payload or flow.bwd_payload):
            return -1, "Ares attempted: empty flow"
        if start >= 1520020424 and flow.first_dst == "18.219.211.138" and flow.fwd_payload and flow.bwd_rst:
            return -1, "Ares attempted: teardown artefact"
        return 4, "audited Ares endpoint/time"

    return 0, "outside audited attack rules"


def classify_2017(flow: Flow) -> tuple[int, str]:
    start = flow.start
    if flow.capture.startswith("CICIDS2017-Tuesday"):
        if _forward(flow, "172.16.0.1", "192.168.10.50", 21) and 1499170672.838272 <= start <= 1499174416.931403:
            return -1, "other attack: FTP-Patator"
        if _forward(flow, "172.16.0.1", "192.168.10.50", 22) and 1499188141.049616 <= start <= 1499195059.018486:
            if not flow.fwd_payload or (flow.fwd_payload <= 32 and not flow.bwd_payload):
                return -1, "SSH-Patator attempted"
            return 1, "audited SSH-Patator endpoint/port/time"

    if flow.capture.startswith("CICIDS2017-Wednesday"):
        attack_path = _forward(flow, "172.16.0.1", "192.168.10.50", 80)
        if attack_path and 1499258926.211817 <= start < 1499258934.539220:
            return -1, "Slowloris launch artefact"
        if attack_path and 1499258934.539220 <= start <= 1499260278.500956:
            if flow.first_sport in {33358, 33360, 33362, 54114} or not flow.fwd_payload:
                return -1, "Slowloris attempted or teardown"
            return 3, "audited Slowloris endpoint/port/time"
        if attack_path and 1499260537.936810 <= start <= 1499261869.331517:
            return -1, "other attack: Slowhttptest"
        if attack_path and 1499262203.194704 <= start <= 1499263641.326171:
            return -1, "other attack: Hulk"
        if attack_path and 1499263803.231753 <= start <= 1499264408.915718:
            return (2, "audited GoldenEye endpoint/port/time") if flow.fwd_payload else (-1, "GoldenEye attempted: empty forward payload")
        if _forward(flow, "172.16.0.1", "192.168.10.51", 444) and 1499278335.650811 <= start <= 1499279563.294455:
            return -1, "other attack: Heartbleed"

    if flow.capture.startswith("CICIDS2017-Friday"):
        bot_path = flow.first_src in INFECTED_2017 and flow.first_dst == "205.174.165.73"
        if bot_path and 1499432653.990571 <= start <= 1499436122.903736:
            return (4, "audited Ares endpoint/time") if flow.fwd_payload else (-1, "Ares attempted: empty forward payload")
        if bot_path and 1499436180 <= start <= 1499457684.606663:
            return -1, "Ares attempted after active interval"
        if _forward(flow, "172.16.0.1", "192.168.10.50") and (
            1499446532.117090 <= start <= 1499447948.582083
            or 1499449905.450532 <= start <= 1499451841.699238
        ):
            return -1, "other attack: PortScan"
        if _forward(flow, "172.16.0.1", "192.168.10.50") and 1499453791.796937 <= start <= 1499454972.216560:
            return -1, "other attack: DDoS"

    return 0, "outside audited attack rules"


class FlowBuilder:
    def __init__(self, inactive_timeout: float = 30.0, active_timeout: float = 300.0):
        self.inactive_timeout = inactive_timeout
        self.active_timeout = active_timeout
        self.active: OrderedDict[tuple, Flow] = OrderedDict()

    def add(self, packet: PacketBytes) -> list[Flow]:
        completed = []
        cutoff = packet.timestamp - self.inactive_timeout
        while self.active:
            key, oldest = next(iter(self.active.items()))
            if oldest.end > cutoff:
                break
            completed.append(self.active.pop(key))

        key = canonical_key(packet)
        flow = self.active.get(key)
        if flow is not None and packet.timestamp - flow.start >= self.active_timeout:
            completed.append(self.active.pop(key))
            flow = None
        if flow is None:
            flow = Flow(
                key, packet.timestamp, packet.timestamp, packet.src_ip, packet.dst_ip,
                packet.src_port, packet.dst_port, packet.capture,
            )
            self.active[key] = flow
        else:
            self.active.move_to_end(key)
        flow.append(packet)
        return completed

    def finish(self) -> list[Flow]:
        completed = list(self.active.values())
        self.active.clear()
        return completed


def _packet_stream(path: Path):
    try:
        from scapy.all import IP, TCP, PcapReader
    except ImportError as exc:
        raise SystemExit("Scapy is required") from exc

    with PcapReader(str(path)) as reader:
        for packet in reader:
            if not packet.haslayer(IP) or not packet.haslayer(TCP):
                continue
            ip, tcp = packet[IP], packet[TCP]
            network_packet = bytes(ip)
            tcp_segment = bytes(tcp)
            tcp_header_length = (tcp.dataofs or 5) * 4
            yield PacketBytes(
                float(packet.time), ip.src, ip.dst, int(tcp.sport), int(tcp.dport), int(tcp.flags),
                bytes(sanitize_tcp_header(network_packet, tcp_segment, 4, tcp_header_length)),
                bytes(tcp.payload), hashlib.blake2b(network_packet, digest_size=16).digest(),
                path.name, path.name,
            )


def _ordered(stream, window: float = 1.0):
    heap = []
    latest = float("-inf")
    sequence = 0
    for packet in stream:
        latest = max(latest, packet.timestamp)
        heapq.heappush(heap, (packet.timestamp, sequence, packet))
        sequence += 1
        while heap and heap[0][0] <= latest - window:
            yield heapq.heappop(heap)[2]
    while heap:
        yield heapq.heappop(heap)[2]


def iter_packets(paths: list[Path], deduplicate: bool):
    streams = [_ordered(_packet_stream(path)) for path in paths]
    merged = heapq.merge(*streams, key=lambda packet: packet.timestamp)
    recent: dict[bytes, tuple[float, str]] = {}
    for packet in merged:
        previous = recent.get(packet.digest)
        if deduplicate and previous and previous[1] != packet.source and packet.timestamp - previous[0] <= 0.01:
            continue
        recent[packet.digest] = (packet.timestamp, packet.source)
        if len(recent) > 100_000:
            cutoff = packet.timestamp - 1.0
            recent = {key: value for key, value in recent.items() if value[0] >= cutoff}
        yield packet


class DatasetWriter:
    def __init__(self, output: Path, dataset: str, max_per_class: int, shard_size: int, seed: int):
        if output.exists() and any(output.iterdir()):
            raise FileExistsError(f"Refusing to overwrite non-empty output: {output}")
        output.mkdir(parents=True, exist_ok=True)
        self.output, self.dataset = output, dataset
        self.max_per_class, self.shard_size = max_per_class, shard_size
        self.rng = random.Random(seed)
        self.seen = Counter()
        self.selected: dict[int, list[tuple[Flow, str, str]]] = defaultdict(list)
        self.counts = {"classified": Counter(), "eligible": Counter(), "selected": Counter(), "no_payload": 0}
        self.index = (output / "flow_index.jsonl").open("w", encoding="utf-8")

    def add(self, flow: Flow) -> None:
        label, reason = classify_2018(flow) if self.dataset == "cicids2018" else classify_2017(flow)
        name = LABELS.get(label, "Excluded")
        flow_id = hashlib.blake2b(
            repr((self.dataset, flow.key, round(flow.start, 6))).encode(), digest_size=12
        ).hexdigest()
        eligible = label >= 0 and bool(flow.payloads)
        self.counts["classified"][name] += 1
        if not flow.payloads:
            self.counts["no_payload"] += 1
        if eligible:
            self.counts["eligible"][name] += 1
        self.index.write(json.dumps({
            "flow_id": flow_id,
            "dataset": self.dataset,
            "capture": flow.capture,
            "sources": sorted(flow.sources),
            "protocol": 6,
            "src_ip": flow.first_src,
            "src_port": flow.first_sport,
            "dst_ip": flow.first_dst,
            "dst_port": flow.first_dport,
            "start": flow.start,
            "end": flow.end,
            "label": label,
            "label_name": name,
            "eligible": eligible,
            "reason": reason if flow.payloads else "no TCP payload",
        }, ensure_ascii=False) + "\n")
        if not eligible:
            return
        self.seen[label] += 1
        bucket = self.selected[label]
        item = (flow, flow_id, reason)
        if len(bucket) < self.max_per_class:
            bucket.append(item)
        else:
            replacement = self.rng.randrange(self.seen[label])
            if replacement < self.max_per_class:
                bucket[replacement] = item

    def close(self) -> None:
        self.index.close()
        rows = sorted((item for bucket in self.selected.values() for item in bucket), key=lambda item: (item[0].start, item[1]))
        encoded = (self.output / "encoded_index.jsonl").open("w", encoding="utf-8")
        for shard_number, offset in enumerate(range(0, len(rows), self.shard_size)):
            shard_rows = rows[offset:offset + self.shard_size]
            headers = np.full((len(shard_rows), MAX_PACKETS, HEADER_BYTES), PAD, dtype=np.uint16)
            payloads = np.full((len(shard_rows), MAX_PACKETS, PAYLOAD_BYTES), PAD, dtype=np.uint16)
            labels = np.empty(len(shard_rows), dtype=np.int64)
            flow_ids = []
            for row, (flow, flow_id, reason) in enumerate(shard_rows):
                labels[row] = classify_2018(flow)[0] if self.dataset == "cicids2018" else classify_2017(flow)[0]
                flow_ids.append(flow_id)
                for packet, (header, payload) in enumerate(zip(flow.headers, flow.payloads)):
                    headers[row, packet, :len(header)] = np.frombuffer(header, dtype=np.uint8)
                    payloads[row, packet, :len(payload)] = np.frombuffer(payload, dtype=np.uint8)
                encoded.write(json.dumps({
                    "flow_id": flow_id, "dataset": self.dataset, "capture": flow.capture,
                    "start": flow.start, "end": flow.end, "label": int(labels[row]),
                    "label_name": LABELS[int(labels[row])], "shard": f"flows-{shard_number:05d}.npz", "row": row,
                }) + "\n")
            np.savez_compressed(
                self.output / f"flows-{shard_number:05d}.npz", header=headers, payload=payloads,
                label=labels, flow_id=np.asarray(flow_ids, dtype="U24"),
            )
        encoded.close()
        self.counts["selected"] = Counter({LABELS[label]: len(rows) for label, rows in self.selected.items()})
        (self.output / "summary.json").write_text(json.dumps({
            key: dict(value) if isinstance(value, Counter) else value for key, value in self.counts.items()
        }, indent=2) + "\n")


def dataset_groups(dataset_root: Path, dataset: str) -> list[tuple[list[Path], bool]]:
    if dataset == "cicids2018":
        paths = sorted((dataset_root / "raw/CICIDS2018/selected").glob("*/*.pcap"))
        if len(paths) != 13:
            raise SystemExit(f"Expected 13 CICIDS2018 PCAPs, found {len(paths)}")
        return [(paths, True)]
    raw = dataset_root / "raw/CICIDS2017/pcap"
    names = [
        "CICIDS2017-Tuesday-WorkingHours.pcap",
        "CICIDS2017-Wednesday-workingHours.pcap",
        "CICIDS2017-Friday-WorkingHours.pcap",
    ]
    paths = [raw / name for name in names]
    missing = [str(path) for path in paths if not path.is_file()]
    if missing:
        raise SystemExit(f"Missing CICIDS2017 PCAPs: {missing}")
    return [([path], False) for path in paths]


def process_dataset(dataset_root: Path, output_root: Path, dataset: str, args) -> None:
    output = output_root / dataset
    writer = DatasetWriter(output, dataset, args.max_per_class, args.shard_size, args.seed)
    completed = 0
    try:
        for paths, deduplicate in dataset_groups(dataset_root, dataset):
            builder = FlowBuilder(args.inactive_timeout, args.active_timeout)
            for packet in iter_packets(paths, deduplicate):
                for flow in builder.add(packet):
                    writer.add(flow)
                    completed += 1
                    if completed % args.progress_every == 0:
                        print(f"{dataset}: completed flows {completed:,}", flush=True)
                    if args.max_flows and completed >= args.max_flows:
                        writer.close()
                        return
            for flow in builder.finish():
                writer.add(flow)
                completed += 1
        writer.close()
    finally:
        if not writer.index.closed:
            writer.index.close()


def _read_encoded(path: Path) -> list[dict]:
    with path.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle]


def _block(row: dict) -> str:
    return f"{row['capture']}:{int(row['start']) // 300}"


def _write_json(path: Path, rows: list[dict]) -> None:
    path.write_text(json.dumps(rows, indent=2) + "\n")


def write_splits(output_root: Path, seeds=(42, 43, 44)) -> None:
    datasets = {name: _read_encoded(output_root / name / "encoded_index.jsonl") for name in ("cicids2017", "cicids2018")}
    splits_root = output_root / "splits"
    splits_root.mkdir(exist_ok=True)
    for source_name, target_name in (("cicids2017", "cicids2018"), ("cicids2018", "cicids2017")):
        direction = splits_root / f"{source_name}_to_{target_name}"
        direction.mkdir(exist_ok=True)
        source = datasets[source_name]
        train = [row for row in source if int(hashlib.sha256(_block(row).encode()).hexdigest(), 16) % 5]
        validation = [row for row in source if not int(hashlib.sha256(_block(row).encode()).hexdigest(), 16) % 5]
        for label in LABELS:
            if not any(row["label"] == label for row in train) or not any(row["label"] == label for row in validation):
                raise RuntimeError(f"source time-block split lost class {label} in {source_name}")
        _write_json(direction / "source_train.json", [{"flow_id": row["flow_id"], "label": row["label"]} for row in train])
        _write_json(direction / "source_validation.json", [{"flow_id": row["flow_id"], "label": row["label"]} for row in validation])

        target = datasets[target_name]
        by_label_block: dict[int, dict[str, list[dict]]] = defaultdict(lambda: defaultdict(list))
        for row in target:
            by_label_block[row["label"]][_block(row)].append(row)
        for seed in seeds:
            rng = random.Random(seed)
            support_blocks = set()
            for label in LABELS:
                blocks = list(by_label_block[label])
                rng.shuffle(blocks)
                available = []
                for block in blocks:
                    support_blocks.add(block)
                    available.extend(by_label_block[label][block])
                    if len(available) >= 10:
                        break
                if len(available) < 10:
                    raise RuntimeError(f"not enough target samples for class {label} in {target_name}")
            support, query = [], [row for row in target if _block(row) not in support_blocks]
            for label in LABELS:
                candidates = [row for row in target if row["label"] == label and _block(row) in support_blocks]
                support.extend(rng.sample(candidates, 10))
                if not any(row["label"] == label for row in query):
                    raise RuntimeError(f"target query lost class {label} in {target_name}, seed {seed}")
            seed_dir = direction / f"seed_{seed}"
            seed_dir.mkdir(exist_ok=True)
            _write_json(seed_dir / "target_support.json", [{"flow_id": row["flow_id"], "label": row["label"]} for row in support])
            _write_json(seed_dir / "target_query.json", [{"flow_id": row["flow_id"], "label": row["label"]} for row in query])


def main() -> None:
    default_root = Path(os.environ.get("DATASET_ROOT", Path(__file__).resolve().parents[1] / "ETC-datasets"))
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset-root", type=Path, default=default_root)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--dataset", choices=("cicids2017", "cicids2018", "all"), default="all")
    parser.add_argument("--max-per-class", type=int, default=10_000)
    parser.add_argument("--shard-size", type=int, default=1000)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--inactive-timeout", type=float, default=30.0)
    parser.add_argument("--active-timeout", type=float, default=300.0)
    parser.add_argument("--progress-every", type=int, default=100_000)
    parser.add_argument("--max-flows", type=int, default=0, help="smoke test only; 0 means all flows")
    args = parser.parse_args()
    output_root = args.output or args.dataset_root / "processed/TFE-GNN/npz"
    datasets = ("cicids2017", "cicids2018") if args.dataset == "all" else (args.dataset,)
    for dataset in datasets:
        process_dataset(args.dataset_root, output_root, dataset, args)
    (output_root / "label_map.json").write_text(json.dumps({str(key): value for key, value in LABELS.items()}, indent=2) + "\n")
    (output_root / "preprocessing_manifest.json").write_text(json.dumps({
        "rules": RULE_SOURCES,
        "inactive_timeout_seconds": args.inactive_timeout,
        "active_timeout_seconds": args.active_timeout,
        "max_packets_per_flow": MAX_PACKETS,
        "header_bytes_per_packet": HEADER_BYTES,
        "payload_bytes_per_packet": PAYLOAD_BYTES,
        "max_encoded_flows_per_class_per_dataset": args.max_per_class,
        "sampling_seed": args.seed,
        "split_seeds": [42, 43, 44],
        "time_block_seconds": 300,
    }, indent=2) + "\n")
    if all((output_root / name / "encoded_index.jsonl").is_file() for name in ("cicids2017", "cicids2018")):
        write_splits(output_root)


if __name__ == "__main__":
    main()
