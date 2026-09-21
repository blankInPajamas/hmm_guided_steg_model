.PHONY: all requirement train calibrate carrier bridge eval simulate

# Detect OS: Windows (Windows_NT) vs everything else
ifeq ($(OS),Windows_NT)
    VENV_PY  := venv/Scripts/python.exe
    VENV_PIP := venv/Scripts/pip.exe
    MKDIR    := if not exist venv python -m venv venv
else
    VENV_PY  := venv/bin/python
    VENV_PIP := venv/bin/pip
    MKDIR    := python3 -m venv venv
endif

all: venv requirement

venv:
	python -m venv venv

requirement: venv
	$(VENV_PIP) install -r requirements.txt

train: 
	$(VENV_PY) experiments/aligned_baum_welch.py

calibrate:
	$(VENV_PY) src/phase3/pcap_calibrator.py

carrier: 
	$(VENV_PY) src/phase3/scapy_carrier.py

bridge:
	$(VENV_PY) src/phase3/hmm_scapy_bridge.py

eval:
	$(VENV_PY) src/phase3/steganalysis_eval.py

simulate:
	$(VENV_PY) src/hmm_model/simulator.py