import unittest

from baseline_preprocess import (
    FlowBuilder,
    MAX_PACKETS,
    PacketBytes,
    classify_2017,
    classify_2018,
)


def packet(timestamp, src, dst, sport=50000, dport=80, payload=b"x", flags=0, capture="test"):
    return PacketBytes(timestamp, src, dst, sport, dport, flags, b"header", payload, b"hash", capture, capture)


def flow_of(*packets):
    builder = FlowBuilder()
    for item in packets:
        builder.add(item)
    return builder.finish()[0]


class BaselinePreprocessTest(unittest.TestCase):
    def test_retains_only_model_packet_limit(self):
        flow = flow_of(*(packet(index / 10, "1.1.1.1", "2.2.2.2") for index in range(MAX_PACKETS + 25)))
        self.assertEqual(len(flow.payloads), MAX_PACKETS)

    def test_2018_ssh_label_and_attempted_filter(self):
        attack = flow_of(packet(1518631311, "13.58.98.64", "172.31.69.25", dport=22))
        attempted = flow_of(packet(1518631311, "13.58.98.64", "172.31.69.25", dport=22, payload=b""))
        self.assertEqual(classify_2018(attack)[0], 1)
        self.assertEqual(classify_2018(attempted)[0], -1)

    def test_2018_ares_teardown_requires_reset_pattern(self):
        normal = flow_of(packet(1520020450, "172.31.69.6", "18.219.211.138"))
        teardown = flow_of(
            packet(1520020450, "172.31.69.6", "18.219.211.138"),
            packet(1520020451, "18.219.211.138", "172.31.69.6", sport=80, dport=50000, payload=b"", flags=4),
        )
        self.assertEqual(classify_2018(normal)[0], 4)
        self.assertEqual(classify_2018(teardown)[0], -1)

    def test_2017_shared_labels_and_other_attack_exclusion(self):
        ssh = flow_of(packet(1499188142, "172.16.0.1", "192.168.10.50", dport=22, payload=b"x" * 33, capture="CICIDS2017-Tuesday-WorkingHours.pcap"))
        hulk = flow_of(packet(1499262300, "172.16.0.1", "192.168.10.50", dport=80, capture="CICIDS2017-Wednesday-workingHours.pcap"))
        ares = flow_of(packet(1499433000, "192.168.10.15", "205.174.165.73", capture="CICIDS2017-Friday-WorkingHours.pcap"))
        self.assertEqual(classify_2017(ssh)[0], 1)
        self.assertEqual(classify_2017(hulk)[0], -1)
        self.assertEqual(classify_2017(ares)[0], 4)


if __name__ == "__main__":
    unittest.main()
