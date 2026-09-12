# Dataset Documentation & Protocol Map
This repository uses a combination of high-speed commercial backbone traffic samples and targeted Wireshark protocol captures to calibrate, train, and test the HMM-Guided Hybrid Network Steganography protocol.

> Note: The dataset/ directory is excluded from version control via .gitignore due to large binary PCAP file sizes.

## Directory Structure

```text
dataset/
│   
├── mawi
│   ├── 2026-08-29-mawi_sample300k.pcap
│   ├── 2026-08-30-mawi_sample300k.pcap
│   └── 2026-08-31-mawi_sample300k.pcap
│   
└── wireshark
    ├── 200722_win_scale_examples_anon.pcapng
    ├── dns-icmp.pcapng.gz
    ├── FTPv6-1.cap
    ├── ipv4frags.pcap
    └── uaudp_ipv6.pcap
```

---

## 1. MAWI Backbone Traffic Dataset (`dataset/mawi/`)

* **Source:** MAWI Working Group (WIDE Project, Samplepoint F — Trans-Pacific 150Mbps backbone link between Japan and the US).
* **Sampling Method:** Streamed traffic sliced at 300,000 packets per daily capture window (~22–27 MB per PCAP).
* **Primary Purpose:** Empirical Inter-Packet Delay (IPD) extraction, Gaussian Mixture Model (GMM) distribution fitting, and HMM baseline observation generation.

| Filename | Trace Date | Size | Primary Protocols | Usage in Research |
|---|---|---|---|---|
| `2026-08-29-mawi_sample300k.pcap` | 2026-08-29 | 27 MB | IPv4, IPv6, TCP, UDP, TLS | Baseline weekend IPD distribution extraction & GMM curve fitting |
| `2026-08-30-mawi_sample300k.pcap` | 2026-08-30 | 23 MB | IPv4, IPv6, TCP, UDP, TLS | Cross-day timing stability validation & jitter profile fitting |
| `2026-08-31-mawi_sample300k.pcap` | 2026-08-31 | 22 MB | IPv4, IPv6, TCP, UDP, TLS | Weekday traffic density baseline & KL Divergence evaluation |

---

## 2. Wireshark Protocol Test Suite (`dataset/wireshark/`)

* **Source:** Wireshark Sample Captures Repository.
* **Primary Purpose:** Unit testing, protocol field extraction, and storage channel trapdoor validation (`ScapyStorageChannel`).

| Filename | Protocol Stack | Covered Fields & Features | Target Covert Channel |
|---|---|---|---|
| `ipv4frags.pcap` | IPv4 / IP Fragmentation | IPv4 Header, `IP.id`, Flags, Frag Offset | **IPv4 Storage Channel:** IP ID parity (`IP.id % 2`) and modulus bit embedding. |
| `200722_win_scale_examples_anon.pcapng` | TCP / IPv4 | TCP Headers, Options, Window Scale, Timestamps | **TCP Storage Channel:** TCP Timestamp LSB replacement and Initial Sequence Number modulo encoding. |
| `FTPv6-1.cap` | FTP / TCP / IPv6 | IPv6 Header, TCP Options, FTP Command Control | **IPv6 Storage Channel:** Extension headers, Flow Label fields, and control stream interaction. |
| `uaudp_ipv6.pcap` | UDP / IPv6 | IPv6 Header, Flow Label, UDP Length / Checksum | **IPv6/UDP Timing & Storage Channel:** UDP packet streams over IPv6. |
| `dns-icmp.pcapng.gz` | DNS / ICMP / UDP / IPv4 | UDP Port 53, DNS Queries, ICMP Echo | **Feedback / Out-of-Band Channel:** Auxiliary reverse feedback testing and control signaling. |

---

## 3. Protocol Matrix Summary

```text
+-----------------------------------------------------------------------------------+
|                            PROTOCOL COVERAGE MATRIX                               |
+-----------------------------------------------------------------------------------+
| Network Layer    --> IPv4 (IP ID Parity), IPv6 (Flow Label, Ext Headers)           |
| Transport Layer  --> TCP (Sequence No., Timestamp LSB), UDP (Timing Modulation)    |
| Application/Aux  --> DNS, ICMP, FTP, TLS 1.2/1.3 (Benign Background Streams)      |
+-----------------------------------------------------------------------------------+