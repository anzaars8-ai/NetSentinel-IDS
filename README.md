# Network Intrusion Detection System

Python-based Network IDS MVP.

## Features

- Live packet capture
- IPv4 packet parsing
- TCP/UDP parsing
- Sliding traffic window
- Port scan detection
- High connection rate detection
- High traffic detection
- SYN flood detection
- Alert deduplication
- SQLite alert storage
- Flask API
- Web dashboard

## Start

```bash
source venv/bin/activate
sudo ./venv/bin/python run_ids.py
cd ~/intrusion-detection-system

# Activate virtual environment
source venv/bin/activate

# Make pytest find project modules
cat > pytest.ini <<'EOF'
[pytest]
pythonpath = .
testpaths = tests
