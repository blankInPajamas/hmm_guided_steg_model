class PayloadSplitter:
    """
    Splits binary secret payload into Storage and Timing streams
    based on HMM-derived allocation ratios (alpha, beta).
    """
    def __init__(self, secret_data: str):
        self.raw_data = secret_data
        self.binary_payload = ''.join(format(ord(char), '08b') for char in secret_data)
        self.pointer = 0

    def is_complete(self):
        return self.pointer >= len(self.binary_payload)

    def get_remaining_bits(self):
        return len(self.binary_payload) - self.pointer

    def fetch_next_chunk(self, chunk_size: int, alpha: float, beta: float):
        """
        Splits the next `chunk_size` bits into storage_bits and timing_bits
        according to ratio (alpha, beta).
        """
        if self.is_complete():
            return "", ""

        available_bits = min(chunk_size, self.get_remaining_bits())
        bits_to_process = self.binary_payload[self.pointer : self.pointer + available_bits]
        self.pointer += available_bits

        storage_count = int(round(available_bits * alpha))
        storage_bits = bits_to_process[:storage_count]
        timing_bits = bits_to_process[storage_count:]

        return storage_bits, timing_bits

    @staticmethod
    def binary_to_string(binary_str: str) -> str:
        chars = []
        for i in range(0, len(binary_str), 8):
            byte = binary_str[i:i+8]
            if len(byte) == 8:
                chars.append(chr(int(byte, 2)))
        return ''.join(chars)

