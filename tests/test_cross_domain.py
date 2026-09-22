import json
import tempfile
import unittest
from pathlib import Path

from cross_domain import direction_parts, limited_per_class, smoke_flow_ids


class CrossDomainTest(unittest.TestCase):
    def test_limited_per_class_preserves_order(self):
        rows = [{"flow_id": str(i), "label": i % 2} for i in range(8)]
        self.assertEqual([row["flow_id"] for row in limited_per_class(rows, 2)], ["0", "1", "2", "3"])

    def test_direction_validation(self):
        self.assertEqual(direction_parts("cicids2017_to_cicids2018"), ("cicids2017", "cicids2018"))
        with self.assertRaises(ValueError):
            direction_parts("cicids2017_to_other")

    def test_smoke_ids_include_all_four_splits(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "cicids2017_to_cicids2018"
            target = root / "cicids2018_to_cicids2017/seed_42"
            source.mkdir(parents=True)
            target.mkdir(parents=True)
            (source / "source_train.json").write_text(json.dumps([{"flow_id": "train", "label": 0}]))
            (source / "source_validation.json").write_text(json.dumps([{"flow_id": "validation", "label": 0}]))
            (target / "target_support.json").write_text(json.dumps([{"flow_id": "support", "label": 0}]))
            (target / "target_query.json").write_text(json.dumps([{"flow_id": "query", "label": 0}]))
            self.assertEqual(smoke_flow_ids(root, "cicids2017"), {"train", "validation", "support", "query"})


if __name__ == "__main__":
    unittest.main()
