import random


def sanitize_tcp_header(network_packet, tcp_segment, ip_version, tcp_header_length):
    """移除链路层、IP 地址和 TCP 端口，同时保留其余协议头字段。"""
    if len(tcp_segment) > len(network_packet):
        raise ValueError("TCP segment is longer than the network packet")
    if tcp_header_length < 20 or tcp_header_length > len(tcp_segment):
        raise ValueError("Invalid TCP header length")

    network_header_length = len(network_packet) - len(tcp_segment)
    network_header = list(network_packet[:network_header_length])
    tcp_header = list(tcp_segment[:tcp_header_length])

    if ip_version == 4:
        if len(network_header) < 20:
            raise ValueError("Invalid IPv4 header")
        # IPv4 源/目的地址固定在 12:20；options（若存在）继续保留。
        network_header = network_header[:12] + network_header[20:]
    elif ip_version == 6:
        if len(network_header) < 40:
            raise ValueError("Invalid IPv6 header")
        # IPv6 源/目的地址位于 8:40，后续扩展头继续保留。
        network_header = network_header[:8] + network_header[40:]
    else:
        raise ValueError("Only IPv4 and IPv6 are supported")

    # TCP 的前四个字节是源端口和目的端口。
    return network_header + tcp_header[4:]


def filter_aligned_packets(packets, payloads=None, allow_empty=False):
    """过滤空 payload 时，对 header 和 payload 使用完全相同的下标。"""
    if payloads is not None and len(packets) != len(payloads):
        raise ValueError("Header and payload counts do not match")
    if allow_empty:
        return [list(packet) for packet in packets]
    if payloads is None:
        return [list(packet) for packet in packets if len(packet) != 0]
    return [list(packet) for packet, payload in zip(packets, payloads) if len(payload) != 0]


def deterministic_train_test_split(samples, seed, max_samples, test_ratio=0.1):
    """按固定种子打乱并划分，避免 os.listdir 顺序改变实验结果。"""
    if not 0 < test_ratio < 1:
        raise ValueError("test_ratio must be between 0 and 1")

    selected = list(samples)
    random.Random(seed).shuffle(selected)
    selected = selected[:max_samples]
    if len(selected) < 2:
        raise ValueError("Each category needs at least two flows")

    test_count = min(max(1, int(len(selected) * test_ratio)), len(selected) - 1)
    return selected[test_count:], selected[:test_count]
