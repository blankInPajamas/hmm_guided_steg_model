class StorageChannel:
    """
    Layer 3/4 Header Storage Channel.
    Uses IPv4 Identification (IP ID) modulus/parity scheme.
    """
    def embed_in_ip_id(self, bit_chunk: str, base_id: int = 10000) -> list:
        packet_headers = []
        for i, bit in enumerate(bit_chunk):
            bit_val = int(bit)
            target_id = base_id + i * 10
            if target_id % 2 != bit_val:
                target_id += 1  # Adjust header field parity
            packet_headers.append({"ip_id": target_id, "payload_type": "DATA"})
        return packet_headers

    def extract_from_ip_id(self, packet_headers: list) -> str:
        extracted_bits = []
        for pkt in packet_headers:
            bit_val = str(pkt["ip_id"] % 2)
            extracted_bits.append(bit_val)
        return ''.join(extracted_bits)


class TimingChannel:
    """
    Layer 4 Inter-Packet Delay (IPD) Timing Channel.
    Modulates transmission intervals:
      Bit '0' -> Base delay t0 (50ms)
      Bit '1' -> Extended delay t0 + delta_t (150ms)
    """
    def __init__(self, t0: float = 0.05, delta_t: float = 0.10):
        self.t0 = t0
        self.delta_t = delta_t
        self.threshold = t0 + (delta_t / 2.0)

    def encode_ipds(self, bit_chunk: str) -> list:
        delays = []
        for bit in bit_chunk:
            delays.append(self.t0 if bit == '0' else self.t0 + self.delta_t)
        return delays

    def decode_ipds(self, observed_delays: list) -> str:
        extracted_bits = []
        for delay in observed_delays:
            extracted_bits.append('1' if delay >= self.threshold else '0')
        return ''.join(extracted_bits)