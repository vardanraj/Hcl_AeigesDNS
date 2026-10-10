# AegisDNS Scripts & Testing Instructions

## Running Tests and Scripts

Ensure you run commands from the project root directory (`AegisDNS/`).

### 1. Run Unit Tests
```bash
python -m pytest
```

### 2. Train Machine Learning Models
```bash
# On Linux/macOS
PYTHONPATH=. python models/train_model.py

# On Windows (PowerShell)
$env:PYTHONPATH="."; python models/train_model.py

# On Windows (cmd)
set PYTHONPATH=. && python models/train_model.py
```

### 3. Run Detection Evaluation Engine
```bash
# On Linux/macOS
PYTHONPATH=. python scripts/evaluate.py

# On Windows (PowerShell)
$env:PYTHONPATH="."; python scripts/evaluate.py

# On Windows (cmd)
set PYTHONPATH=. && python scripts/evaluate.py
```

All evaluation results will be saved to `reports/evaluation_report.json` and `reports/evaluation_summary.txt`.
