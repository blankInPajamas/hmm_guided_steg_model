#!/usr/bin/env python3
"""
live_warden.py - State-Based Active Warden running on Node h2
Sniffs on h2-eth0 -> Modifies IP.id based on threat state -> Forwards on h2-eth1
"""

import time
import threading
import numpy as np
from scapy.all import sniff, sendp, IP, TCP

# State machine vigilance configuration:
# State 0: Clean / Low Vigilance (0% scrub)
# State 1: Degraded / Medium Vigilance (20% scrub)
# State 2: Active Scrubbing / High Vigilance (70% scrub)
CURRENT_STATE = 0

# Epoch sequence to simulate Warden behavior across 12 epochs (e.g., 5 seconds per epoch)
EPOCH_THREAT_SCHEDULE = [0, 0, 1, 2, 2, 2, 1, 0, 0, 0, 1, 0]

def state_scheduler():
    global CURRENT_STATE
    time.sleep(2) # Initial boot delay
    for epoch, state in enumerate(EPOCH_THREAT_SCHEDULE):
        CURRENT_STATE = state
        print(f"\n[WARDEN STATE SWITCH] Epoch {epoch + 1}/12 | Threat State: {CURRENT_STATE}")
        time.sleep(5) # 5 seconds per epoch execution window

def process_and_forward(packet):
    if not packet.haslayer(IP):
        return

    # Filter strictly for h1 -> h3 traffic
    if packet[IP].src == "10.0.1.2" and packet[IP].dst == "10.0.2.2":
        pkt_mod = packet.copy()

        # Determine whether to scrub based on state probability
        scrub = False
        if CURRENT_STATE == 1:
            if np.random.rand() < 0.20:
                scrub = True
        elif CURRENT_STATE == 2:
            if np.random.rand() < 0.70:
                scrub = True

        if scrub:
            # Corrupt IP.id parity with a random 16-bit integer
            original_id = pkt_mod[IP].id
            pkt_mod[IP].id = int(np.random.randint(1000, 65000))
            print(f"[WARDEN SCRUBBED] State {CURRENT_STATE} | Modified IP.id: {original_id} -> {pkt_mod[IP].id}")
        else:
            print(f"[WARDEN PASSTHROUGH] State {CURRENT_STATE} | Unchanged IP.id: {pkt_mod[IP].id}")

        # Invalidate checksums forcing Scapy to recalculate valid values prior to transmission
        del pkt_mod[IP].chksum
        if pkt_mod.haslayer(TCP):
            del pkt_mod[TCP].chksum

        # Forward out to egress interface h2-eth1
        sendp(pkt_mod, iface="h2-eth1", verbose=False)

def main():
    # Start the state scheduler in a background thread
    scheduler_thread = threading.Thread(target=state_scheduler, daemon=True)
    scheduler_thread.start()

    print("[+] Active Warden active on interface h2-eth0. Sniffing and processing...")
    sniff(iface="h2-eth0", filter="ip src 10.0.1.2 and ip dst 10.0.2.2", prn=process_and_forward)

if __name__ == '__main__':
    main()