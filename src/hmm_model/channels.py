"""
channels.py — Physical channel models for the HMM-guided hybrid steganography.

Both channels accept bit sequences as strings, lists of chars, or lists of
ints. The type normalization happens at the boundary so downstream code
never has to guess.
"""


def _normalize_bits(bit_chunk) -> str:
    """Coerce any iterable of 0/1 (int, str, bytes) into a bit string."""
    if isinstance(bit_chunk, str):
        bits = bit_chunk
    else:
        bits = ''.join(str(b) for b in bit_chunk)
    for c in bits:
        if c not in ('0', '1'):
            raise ValueError(f"invalid bit character: {c!r} in {bit_chunk!r}")
    return bits


class StorageChannel:
    """Layer 3/4 header storage channel via IPv4 ID parity."""

    def embed_in_ip_id(self, bit_chunk, base_id: int = 10000) -> list:
        bits = _normalize_bits(bit_chunk)
        headers = []
        for i, c in enumerate(bits):
            target_id = base_id + i * 10
            if target_id % 2 != int(c):
                target_id += 1
            headers.append({"ip_id": target_id, "payload_type": "DATA"})
        return headers

    def extract_from_ip_id(self, packet_headers: list) -> str:
        return ''.join(str(pkt["ip_id"] % 2) for pkt in packet_headers)


class TimingChannel:
    """Layer 4 IPD timing channel with two-level modulation."""

    def __init__(self, t0: float = 0.05, delta_t: float = 0.10):
        self.t0 = t0
        self.delta_t = delta_t
        self.threshold = t0 + (delta_t / 2.0)

    def encode_ipds(self, bit_chunk) -> list:
        bits = _normalize_bits(bit_chunk)
        return [self.t0 if c == '0' else self.t0 + self.delta_t for c in bits]

    def decode_ipds(self, observed_delays: list) -> str:
        return ''.join('1' if d >= self.threshold else '0'
                       for d in observed_delays)