import unittest

from preprocessing_utils import (
    deterministic_train_test_split,
    filter_aligned_packets,
    sanitize_tcp_header,
)


class SanitizeTcpHeaderTest(unittest.TestCase):
    def test_ipv4_removes_addresses_and_ports_but_keeps_options(self):
        ipv4_header = bytes(range(24))
        tcp_header = bytes(range(100, 124))
        payload = b"payload"

        result = sanitize_tcp_header(
            ipv4_header + tcp_header + payload,
            tcp_header + payload,
            ip_version=4,
            tcp_header_length=24,
        )

        self.assertEqual(result, list(ipv4_header[:12] + ipv4_header[20:] + tcp_header[4:]))

    def test_ipv6_keeps_extension_header(self):
        ipv6_header = bytes(range(40))
        extension_header = bytes(range(40, 48))
        tcp_header = bytes(range(100, 120))

        result = sanitize_tcp_header(
            ipv6_header + extension_header + tcp_header,
            tcp_header,
            ip_version=6,
            tcp_header_length=20,
        )

        self.assertEqual(result, list(ipv6_header[:8] + extension_header + tcp_header[4:]))


class DeterministicSplitTest(unittest.TestCase):
    def test_split_is_reproducible_and_disjoint(self):
        samples = list(range(20))
        first = deterministic_train_test_split(samples, seed=32, max_samples=12)
        second = deterministic_train_test_split(samples, seed=32, max_samples=12)

        self.assertEqual(first, second)
        train, test = first
        self.assertEqual(len(train), 11)
        self.assertEqual(len(test), 1)
        self.assertFalse(set(train) & set(test))


class AlignedPacketFilterTest(unittest.TestCase):
    def test_header_uses_payload_mask(self):
        headers = [[10], [20], [30]]
        payloads = [[], [2], []]

        self.assertEqual(filter_aligned_packets(headers, payloads), [[20]])

    def test_mismatched_counts_fail_fast(self):
        with self.assertRaises(ValueError):
            filter_aligned_packets([[10], [20]], [[1]])


if __name__ == "__main__":
    unittest.main()
