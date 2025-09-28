# Port-Scanner

A simple, concurrent TCP port scanner written in Python for educational use.  

---

## Features
- TCP connect-style scanning (safe, simple)
- Optional simple banner grabbing for basic service identification
- Plain terminal output; single-file script: `port_scanner.py`

---

## Usage

Scan localhost (safe test):
```bash
python port_scanner.py --host 127.0.0.1 --ports 20-1024
