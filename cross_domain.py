"""Manifest-driven CICIDS2017/2018 training for the five-class TFE-GNN baseline."""

import argparse
import json
import math
import random
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np


LABELS = ["Benign", "SSH-BruteForce", "DoS-GoldenEye", "DoS-Slowloris", "Botnet-Ares"]
FLOW_LENGTH = 50
SEED = 42


def read_json(path):
    return json.loads(Path(path).read_text())


def read_jsonl(path):
    with Path(path).open() as handle:
        return [json.loads(line) for line in handle]


def write_json(path, value):
    Path(path).write_text(json.dumps(value, indent=2) + "\n")


def limited_per_class(rows, limit):
    counts = Counter()
    selected = []
    for row in rows:
        label = int(row["label"])
        if counts[label] < limit:
            selected.append(row)
            counts[label] += 1
    return selected


def direction_parts(direction):
    source, target = direction.split("_to_")
    if {source, target} != {"cicids2017", "cicids2018"}:
        raise ValueError(f"unsupported direction: {direction}")
    return source, target


def smoke_flow_ids(split_root, dataset):
    other = "cicids2018" if dataset == "cicids2017" else "cicids2017"
    source_dir = Path(split_root) / f"{dataset}_to_{other}"
    target_dir = Path(split_root) / f"{other}_to_{dataset}"
    rows = []
    rows += limited_per_class(read_json(source_dir / "source_train.json"), 100)
    rows += limited_per_class(read_json(source_dir / "source_validation.json"), 20)
    rows += read_json(target_dir / "seed_42/target_support.json")
    rows += limited_per_class(read_json(target_dir / "seed_42/target_query.json"), 100)
    return {row["flow_id"] for row in rows}


def selected_index_rows(npz_root, dataset, smoke):
    rows = read_jsonl(Path(npz_root) / dataset / "encoded_index.jsonl")
    if not smoke:
        return rows
    selected = smoke_flow_ids(Path(npz_root) / "splits", dataset)
    result = [row for row in rows if row["flow_id"] in selected]
    missing = selected - {row["flow_id"] for row in result}
    if missing:
        raise ValueError(f"{dataset}: {len(missing)} smoke flow_ids are missing from encoded_index")
    return result


def _require_empty(path):
    path = Path(path)
    if path.exists() and any(path.iterdir()):
        raise FileExistsError(f"refusing to overwrite non-empty output: {path}")
    path.mkdir(parents=True, exist_ok=True)


def _safe_graph(values, dgl, torch, construct_graph):
    graph = construct_graph(values.tolist(), w_size=5, k=1)
    if graph.num_nodes() == 0:
        value = int(values[0]) if len(values) else 256
        graph = dgl.graph(([0], [0]))
        graph.ndata["feat"] = torch.tensor([[value]], dtype=torch.float32)
    return graph


def build_cache(dataset_root, cache_root, dataset, smoke=False, flows_per_shard=100):
    import dgl
    import torch
    from utils import construct_graph

    npz_root = Path(dataset_root) / "processed/TFE-GNN/npz"
    source_root = npz_root / dataset
    output = Path(cache_root) / dataset
    _require_empty(output)
    rows = selected_index_rows(npz_root, dataset, smoke)
    index_path = output / "graph_index.jsonl"
    labels = Counter()
    bytes_written = 0

    current_npz_name = None
    current_npz = None
    shard_rows = []
    header_graphs = []
    payload_graphs = []
    shard_number = 0

    def flush():
        nonlocal shard_rows, header_graphs, payload_graphs, shard_number, bytes_written
        if not shard_rows:
            return
        name = f"{shard_number:05d}"
        graph_labels = torch.tensor([row["label"] for row in shard_rows], dtype=torch.long)
        header_path = output / f"header-{name}.dgl"
        payload_path = output / f"payload-{name}.dgl"
        dgl.save_graphs(str(header_path), header_graphs, {"glabel": graph_labels})
        dgl.save_graphs(str(payload_path), payload_graphs, {"glabel": graph_labels})
        bytes_written += header_path.stat().st_size + payload_path.stat().st_size
        with index_path.open("a") as handle:
            for cache_row, row in enumerate(shard_rows):
                handle.write(json.dumps({
                    "flow_id": row["flow_id"], "label": int(row["label"]),
                    "cache_shard": shard_number, "row": cache_row,
                }) + "\n")
        print(f"{dataset}: cached {sum(labels.values()):,}/{len(rows):,} flows", flush=True)
        shard_number += 1
        shard_rows, header_graphs, payload_graphs = [], [], []

    try:
        for row in rows:
            if row["shard"] != current_npz_name:
                if current_npz is not None:
                    current_npz.close()
                current_npz_name = row["shard"]
                current_npz = np.load(source_root / current_npz_name)
            source_row = int(row["row"])
            if str(current_npz["flow_id"][source_row]) != row["flow_id"]:
                raise ValueError(f"flow_id mismatch for {row['flow_id']}")
            header_graphs.extend(
                _safe_graph(packet, dgl, torch, construct_graph) for packet in current_npz["header"][source_row]
            )
            payload_graphs.extend(
                _safe_graph(packet, dgl, torch, construct_graph) for packet in current_npz["payload"][source_row]
            )
            shard_rows.append(row)
            labels[int(row["label"])] += 1
            if len(shard_rows) == flows_per_shard:
                flush()
        flush()
    finally:
        if current_npz is not None:
            current_npz.close()

    summary = {
        "dataset": dataset,
        "smoke": smoke,
        "flow_count": len(rows),
        "graph_count": len(rows) * FLOW_LENGTH * 2,
        "cache_shards": shard_number,
        "labels": {LABELS[label]: labels[label] for label in range(5)},
        "bytes": bytes_written,
        "bytes_per_flow": bytes_written / len(rows) if rows else 0,
    }
    write_json(output / "summary.json", summary)
    return summary


def load_split(npz_root, direction, name, smoke):
    base = Path(npz_root) / "splits" / direction
    path = base / (f"seed_42/{name}.json" if name.startswith("target_") else f"{name}.json")
    rows = read_json(path)
    if not smoke or name == "target_support":
        return rows
    limit = 20 if name == "source_validation" else 100
    return limited_per_class(rows, limit)


def make_dataset(cache_root, manifest, shuffle, seed, dgl, torch):
    cache_root = Path(cache_root)
    index = {row["flow_id"]: row for row in read_jsonl(cache_root / "graph_index.jsonl")}
    missing = [row["flow_id"] for row in manifest if row["flow_id"] not in index]
    if missing:
        raise ValueError(f"{len(missing)} manifest flow_ids are missing from graph cache")
    grouped = defaultdict(list)
    for row in manifest:
        cached = index[row["flow_id"]]
        if int(cached["label"]) != int(row["label"]):
            raise ValueError(f"label mismatch for {row['flow_id']}")
        grouped[int(cached["cache_shard"])].append((int(cached["row"]), row))

    class Dataset(torch.utils.data.IterableDataset):
        def __init__(self):
            super().__init__()
            self.epoch = 0

        def __len__(self):
            return len(manifest)

        def set_epoch(self, epoch):
            self.epoch = epoch

        def __iter__(self):
            rng = random.Random(seed + self.epoch)
            shards = list(grouped)
            if shuffle:
                rng.shuffle(shards)
            for shard in shards:
                rows = list(grouped[shard])
                if shuffle:
                    rng.shuffle(rows)
                header, header_meta = dgl.load_graphs(str(cache_root / f"header-{shard:05d}.dgl"))
                payload, payload_meta = dgl.load_graphs(str(cache_root / f"payload-{shard:05d}.dgl"))
                if not header_meta["glabel"].equal(payload_meta["glabel"]):
                    raise ValueError(f"header/payload labels differ in cache shard {shard}")
                for cache_row, row in rows:
                    start = cache_row * FLOW_LENGTH
                    end = start + FLOW_LENGTH
                    yield header[start:end], payload[start:end], int(row["label"]), row["flow_id"]

    return Dataset()


def collate(batch, dgl, torch):
    headers, payloads, labels, flow_ids = zip(*batch)
    return (
        dgl.batch([graph for flow in headers for graph in flow]),
        dgl.batch([graph for flow in payloads for graph in flow]),
        torch.tensor(labels, dtype=torch.long),
        list(flow_ids),
    )


def seed_everything(torch, dgl):
    random.seed(SEED)
    np.random.seed(SEED)
    torch.manual_seed(SEED)
    torch.cuda.manual_seed_all(SEED)
    dgl.seed(SEED)
    dgl.random.seed(SEED)
    torch.backends.cudnn.deterministic = True
    torch.backends.cudnn.benchmark = False


def evaluate(model, loader, device, sklearn_metrics, torch):
    model.eval()
    truth, predictions, flow_ids = [], [], []
    with torch.no_grad():
        for header, payload, labels, ids in loader:
            labels = labels.to(device)
            logits = model(header.to(device), payload.to(device), labels)
            truth.extend(labels.cpu().tolist())
            predictions.extend(logits.argmax(1).cpu().tolist())
            flow_ids.extend(ids)
    report = sklearn_metrics.classification_report(
        truth, predictions, labels=list(range(5)), target_names=LABELS,
        digits=6, zero_division=0, output_dict=True,
    )
    metrics = {
        "accuracy": sklearn_metrics.accuracy_score(truth, predictions),
        "macro_f1": sklearn_metrics.f1_score(truth, predictions, average="macro", zero_division=0),
        "per_class": {label: report[label] for label in LABELS},
        "confusion_matrix": sklearn_metrics.confusion_matrix(truth, predictions, labels=list(range(5))).tolist(),
    }
    return metrics, [
        {"flow_id": flow_id, "label": label, "prediction": prediction}
        for flow_id, label, prediction in zip(flow_ids, truth, predictions)
    ]


def train_source(model, train_loader, validation_loader, output, device, epochs, torch, sklearn_metrics):
    criterion = torch.nn.CrossEntropyLoss()
    optimizer = torch.optim.Adam(model.parameters(), lr=1e-2)
    updates_per_epoch = max(1, math.ceil(len(train_loader) / 16))
    total_updates = max(1, updates_per_epoch * epochs)
    warmup = max(1, int(total_updates * 0.1))

    def lr_scale(step):
        if step < warmup:
            return (step + 1) / warmup
        progress = (step - warmup) / max(1, total_updates - warmup)
        return max(0.01, 0.5 * (1 + math.cos(math.pi * progress)))

    scheduler = torch.optim.lr_scheduler.LambdaLR(optimizer, lr_scale)
    best = -1.0
    optimizer.zero_grad()
    for epoch in range(epochs):
        model.train()
        train_loader.dataset.set_epoch(epoch)
        for batch, (header, payload, labels, _) in enumerate(train_loader):
            labels = labels.to(device)
            loss = criterion(model(header.to(device), payload.to(device), labels), labels) / 16
            loss.backward()
            if (batch + 1) % 16 == 0 or batch + 1 == len(train_loader):
                optimizer.step()
                optimizer.zero_grad()
                scheduler.step()
        metrics, _ = evaluate(model, validation_loader, device, sklearn_metrics, torch)
        print(f"source epoch {epoch + 1}/{epochs}: validation macro_f1={metrics['macro_f1']:.6f}", flush=True)
        if metrics["macro_f1"] > best:
            best = metrics["macro_f1"]
            torch.save({"model": model.state_dict(), "epoch": epoch + 1, "validation": metrics}, output)
    return best


def finetune(model, loader, device, epochs, torch):
    criterion = torch.nn.CrossEntropyLoss()
    optimizer = torch.optim.Adam(model.parameters(), lr=1e-4)
    for epoch in range(epochs):
        model.train()
        loader.dataset.set_epoch(epoch)
        optimizer.zero_grad()
        for header, payload, labels, _ in loader:
            labels = labels.to(device)
            criterion(model(header.to(device), payload.to(device), labels), labels).backward()
            optimizer.step()
            optimizer.zero_grad()
        print(f"finetune epoch {epoch + 1}/{epochs}", flush=True)


def run_experiment(dataset_root, cache_root, output_root, direction, cuda, smoke=False):
    import dgl
    import torch
    from sklearn import metrics as sklearn_metrics
    from model import MixTemporalGNN

    seed_everything(torch, dgl)
    source, target = direction_parts(direction)
    npz_root = Path(dataset_root) / "processed/TFE-GNN/npz"
    output = Path(output_root) / direction / "seed_42"
    _require_empty(output)
    manifests = {
        name: load_split(npz_root, direction, name, smoke)
        for name in ("source_train", "source_validation", "target_support", "target_query")
    }
    support_counts = Counter(int(row["label"]) for row in manifests["target_support"])
    if support_counts != Counter({label: 10 for label in range(5)}):
        raise ValueError(f"target support is not 10-shot: {dict(support_counts)}")

    device = torch.device(f"cuda:{cuda}" if torch.cuda.is_available() else "cpu")
    if device.type == "cuda":
        torch.cuda.reset_peak_memory_stats()
    batch_size = 32
    loaders = {}
    for name, manifest in manifests.items():
        dataset = make_dataset(
            Path(cache_root) / (source if name.startswith("source_") else target),
            manifest, shuffle=name in {"source_train", "target_support"}, seed=SEED, dgl=dgl, torch=torch,
        )
        loaders[name] = torch.utils.data.DataLoader(
            dataset, batch_size=min(batch_size, len(manifest)), num_workers=0,
            collate_fn=lambda batch: collate(batch, dgl, torch),
        )

    model = MixTemporalGNN(num_classes=5, embedding_size=64, h_feats=128, dropout=0.2, downstream_dropout=0.0).to(device)
    source_checkpoint = output / "source_checkpoint.pt"
    source_epochs = 1 if smoke else 120
    finetune_epochs = 1 if smoke else 20
    best = train_source(
        model, loaders["source_train"], loaders["source_validation"], source_checkpoint,
        device, source_epochs, torch, sklearn_metrics,
    )
    checkpoint = torch.load(source_checkpoint, map_location=device, weights_only=False)
    model.load_state_dict(checkpoint["model"])
    finetune(model, loaders["target_support"], device, finetune_epochs, torch)
    torch.save({"model": model.state_dict(), "epochs": finetune_epochs}, output / "finetuned_checkpoint.pt")
    metrics, predictions = evaluate(model, loaders["target_query"], device, sklearn_metrics, torch)
    with (output / "predictions.jsonl").open("w") as handle:
        for row in predictions:
            handle.write(json.dumps(row) + "\n")
    write_json(output / "metrics.json", metrics)
    write_json(output / "run.json", {
        "direction": direction, "seed": SEED, "smoke": smoke, "device": str(device),
        "source_epochs": source_epochs, "finetune_epochs": finetune_epochs,
        "source_validation_best_macro_f1": best,
        "peak_gpu_memory_bytes": torch.cuda.max_memory_allocated() if device.type == "cuda" else 0,
        "counts": {name: len(rows) for name, rows in manifests.items()},
    })
    print(json.dumps(metrics, indent=2), flush=True)
    return metrics


def main():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    cache = subparsers.add_parser("build-cache")
    cache.add_argument("--dataset-root", type=Path, default=Path("/ETC-datasets"))
    cache.add_argument("--cache-root", type=Path, required=True)
    cache.add_argument("--dataset", choices=("cicids2017", "cicids2018"), required=True)
    cache.add_argument("--smoke", action="store_true")
    run = subparsers.add_parser("run")
    run.add_argument("--dataset-root", type=Path, default=Path("/ETC-datasets"))
    run.add_argument("--cache-root", type=Path, required=True)
    run.add_argument("--output-root", type=Path, default=Path("/TFE-GNN/outputs"))
    run.add_argument("--direction", choices=("cicids2017_to_cicids2018", "cicids2018_to_cicids2017"), required=True)
    run.add_argument("--cuda", default="0")
    run.add_argument("--smoke", action="store_true")
    args = parser.parse_args()
    if args.command == "build-cache":
        print(json.dumps(build_cache(args.dataset_root, args.cache_root, args.dataset, args.smoke), indent=2))
    else:
        run_experiment(args.dataset_root, args.cache_root, args.output_root, args.direction, args.cuda, args.smoke)


if __name__ == "__main__":
    main()
