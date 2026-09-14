"""
load_real_csv.py

Converts a CSV export from the Ubuntu-side tool (like dataset.csv) into the
list-of-JSON-dict format the rest of the pipeline expects
(records_to_feature_df, train_models.py, /analyze, etc. all take that shape).

Usage:
    python3 data/load_real_csv.py path/to/dataset.csv
    -> writes data/real_dataset.json next to this script

Note: pandas' CSV reader already auto-parses the "True"/"False" strings in
the flag_* columns into real Python bools, and numeric columns into
int/float, so minimal cleanup is needed here beyond handling NaN -> None
for JSON compatibility.
"""

import sys
import os
import json
import pandas as pd
import numpy as np


def csv_to_records(csv_path: str) -> list:
    df = pd.read_csv(csv_path)
    # Replace NaN with None so json.dump doesn't emit invalid `NaN` literals
    df = df.where(pd.notnull(df), None)
    records = df.to_dict(orient="records")

    # Coerce numpy scalar types (np.int64, np.bool_, etc.) to plain Python
    # types so json.dump doesn't choke on them.
    def _clean(v):
        if isinstance(v, (np.generic,)):
            return v.item()
        return v

    return [{k: _clean(v) for k, v in row.items()} for row in records]


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 data/load_real_csv.py path/to/dataset.csv")
        sys.exit(1)

    csv_path = sys.argv[1]
    records = csv_to_records(csv_path)

    out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "real_dataset.json")
    with open(out_path, "w") as f:
        json.dump(records, f, indent=2, default=str)

    print(f"Wrote {len(records)} record(s) to {out_path}")

    if records:
        labels = [r.get("label") for r in records if r.get("label") is not None]
        distinct = set(labels)
        print(f"Distinct label values found: {distinct}")
        if len(distinct) < 2:
            print(
                "WARNING: fewer than 2 distinct label values in this file. "
                "You need examples of BOTH secure and vulnerable sessions "
                "(or however your teammates' taxonomy is structured) before "
                "this can replace the synthetic data as the sole training "
                "source. For now, keep training on the synthetic dataset and "
                "treat real rows as validation/spot-checks."
            )
