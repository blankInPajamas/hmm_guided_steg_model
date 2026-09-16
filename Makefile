.PHONY: all requirement train calibrate carrier bridge eval

# Running `make` with no arguments creates the venv and installs requirements
all: venv requirement

venv:
	python3 -m venv venv

requirement: venv
	venv/bin/pip install -r requirements.txt

train: 
	venv/bin/python experiments/aligned_baum_welch.py

calibrate:
	venv/bin/python src/phase3/pcap_calibrator.py

carrier: 
	venv/bin/python src/phase3/scapy_carrier.py

bridge:
	venv/bin/python src/phase3/hmm_scapy_bridge.py

eval:
	venv/bin/python src/phase3/steganalysis_eval.py