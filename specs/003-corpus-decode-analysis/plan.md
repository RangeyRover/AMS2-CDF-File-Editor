# Plan: Corpus Decode Analysis

## Architecture

### Single Script: `corpus_analyzer.py`
A standalone Python script in the workspace root that:
1. Loads the XML dictionary
2. Walks `Extracted_CDFs/` to find all CDF files (filtering out Cockpit/Livery dirs)
3. Parses each CDF file
4. Collects per-vehicle and per-signature statistics
5. Performs cross-vehicle pattern analysis
6. Generates reports and proposes speculative identifications

### Output Files
- `reports/corpus_coverage.csv` — per-vehicle decode coverage
- `reports/unknown_catalog.csv` — per-signature aggregation across all vehicles
- `reports/adjacency_context.csv` — unknown fields with their neighbors
- `reports/corpus_analysis_report.md` — summary markdown report

### Parser Integration
Uses existing `cdf_parser.py` functions:
- `load_dictionary(xml_path)` → list of definitions
- `parse_cdfbin(blob, defs)` → list of FieldInstance objects

### Key Data Structures
```python
VehicleResult = {
    'name': str,           # e.g. "BMW_M4_GT3"
    'file_path': str,
    'file_size': int,
    'total_instances': int,
    'known_instances': int,
    'unknown_instances': int,
    'coverage_pct': float,
    'unknowns': [...]      # list of UnknownInstance
}

UnknownInstance = {
    'signature': str,       # hex signature
    'prefix': str,          # '20', '22', etc.
    'values': [...],        # decoded values
    'prev_field': str,      # name of field before
    'next_field': str,      # name of field after
    'position': int,        # byte offset
}
```

## Filtering Logic
- Only process directories that contain `.cdf` files
- Skip `_Cockpit.bff`, `_Livery.bff` directories (no chassis CDF data)
- Within each vehicle directory, process any `.cdf` file found

## Speculative Identification Algorithm
1. Group all unknowns by signature
2. For each signature, compute:
   - Frequency: how many vehicles contain it
   - Value statistics (min, max, mean, unique values)
   - Most common adjacent fields
3. Apply heuristic rules:
   - **Section inference**: if >80% of adjacent fields are from the same section → assign to that section
   - **Type inference**: prefix `20`→byte, `22`→float, `24`→composite
   - **Name proposal**: "{Section}Param_{ShortSig}" with note about value range
4. Confidence levels:
   - **HIGH**: appears in >90% of vehicles, consistent adjacency, known section
   - **MEDIUM**: appears in >50% of vehicles, partial adjacency match
   - **LOW**: sparse or inconsistent patterns
