# PyGuard Architecture

This document describes the recommended folder structure and responsibilities for the PyGuard project.

ASCII overview

```
  Network NICs --> Packet Capture (scapy) --> Packet Queue
                                    |
                                    v
                           Packet Processor (_process_packet)
                                    |
                                    v
                           In-memory store (captured_packets)
                                    |
     +------------------------------+--------------------------+
     |                              |                          |
     v                              v                          v
   UI / Desktop               Storage (CSV/DB)             ML / IDS
 (desktop_app/, pyguard/)  (storage/csv_storage.py)     (Model/, ids_service_manager)
```

Recommended top-level layout

- `desktop_app/` - Full-featured desktop UI and capture implementation (PyQt5).
- `pyguard/` - Core package (lightweight UI, capture manager, processors).
- `scripts/` - Utility scripts and converters (pcap -> flows, CICFlowMeter helpers).
- `storage/` - CSV/DB persisters and helpers.
- `Model/` or `model/` - Machine learning artifacts and model code (weights, scalers).
- `data/` - Example datasets, sample PCAPs, generated CSVs (ignored by Git).
- `docs/` - Documentation (this file, design notes).
- `tests/` - Unit tests.
- `tools/` - Developer tooling (requirements checker, formatters).

Guidelines

- Keep model binary files (PyTorch `.pt`/`.pth`, sklearn `.pkl`) out of version control; place them under `Model/` and include a small `README` explaining what to download and where.
- Use `data/` for example PCAPs and sample CSVs. Add `data/` to `.gitignore` for generated outputs if they are large.
- Keep scripts in `scripts/` and avoid modifying the application packages directly from casual experiments. Use `scripts/` to build example inputs for the ML pipeline.
- Use `storage/` for all persistent-writing logic. The application should call `storage/csv_storage.py` or `storage/database_storage.py` rather than writing CSVs inline.

Quick run pointers

- Desktop UI: `python desktop_app/run_desktop_app.py`
- Lightweight UI: `python pyguard/main.py`
- Convert PCAP -> CICFlowMeter CSV (script): `python scripts/pcap_to_cicflowmeter_csv.py --input capture.pcap --output flows.csv`

Adding new ML artifacts

1. Put model weights under `Model/weights/` and small text metadata under `Model/` (e.g., `model_info.md`).
2. Add a `Model/README.md` explaining where to get pre-trained weights and required versions of PyTorch/PyG.

Contact

- For structural questions, open an issue or ping the repository owner.
