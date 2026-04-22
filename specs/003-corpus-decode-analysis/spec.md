# Feature: Corpus Decode Analysis

## Overview
Build a framework that scans the entire CDF corpus (~1,405 vehicle directories) against the current `cdf-hex-map.xml` dictionary to measure decode coverage, catalog unknowns, and identify speculative field identifications through cross-vehicle pattern analysis.

## Scope
- **XML-only work** — no changes to the parser or GUI code
- **Analysis tool** — produces reports, not runtime features
- Output updates to `cdf-hex-map.xml` with speculative identifications marked `[SPECULATIVE]`

## Functional Requirements

### FR-1: Per-Vehicle Decode Coverage Report
For each CDF file in the corpus:
- Count total field instances found
- Count named (known) vs unknown instances
- Calculate decode coverage percentage
- Record file size and vehicle name

### FR-2: Unknown Signature Catalog
For each unknown signature encountered across all vehicles:
- Record the hex signature
- Record the data type prefix (`20`=byte, `21`=int16, `22`=float, `24`=multi, `26`=special, `28`=zero)
- Record which vehicles contain this signature
- Record the decoded value(s) from each vehicle

### FR-3: Adjacent Field Context
For each unknown instance:
- Record the named field immediately before it in the binary stream
- Record the named field immediately after it
- This adjacency context often reveals the section/purpose of the unknown

### FR-4: Cross-Vehicle Value Analysis
For each unknown signature:
- Aggregate all values seen across the corpus
- Compute min, max, mean, stddev, unique count
- Flag signatures that have constant values (potential flags/enums)
- Flag signatures with values strongly correlated to known fields (e.g. Mass)

### FR-5: Speculative Identification
Using the patterns above, propose speculative names for unknowns:
- Adjacency-based: "always appears between BrakeOptimumTemp and BrakeWearRate" → likely brake-related
- Value-range-based: values 0-1 → likely a multiplier/coefficient; values 100-2000 → likely a rate
- Section-based: appears only inside corner sections → corner/suspension param
- Mark all speculative identifications with `[SPECULATIVE]` in the XML notes

### FR-6: Summary Report
Generate a markdown report with:
- Overall corpus decode coverage (mean, min, max)
- Top 20 most common unknown signatures
- Top 10 vehicles with lowest decode coverage (problem cases)
- Speculative identification proposals with confidence levels

## Success Criteria
- SC-1: Framework processes all ~1,405 vehicle directories without crashes
- SC-2: Per-vehicle coverage report generated as CSV
- SC-3: Unknown catalog aggregated across all vehicles
- SC-4: At least 10 speculative identifications proposed from pattern analysis
- SC-5: XML updated with speculative identifications (marked appropriately)
- SC-6: Summary report generated as markdown

## Assumptions
- CDF files are found as `*.cdf` within subdirectories of `Extracted_CDFs/`
- Only directories containing `.cdf` files (not `_Cockpit`, `_Livery`) are relevant
- The existing `cdf_parser.py` `load_dictionary()` and `parse_cdfbin()` functions work correctly
- Speculative identifications are advisory hints only — users understand they may be wrong

## Dependencies
- `cdf-hex-map.xml` (current polished version on branch 002)
- `cdf_parser.py` (modular parser with `load_dictionary` and `parse_cdfbin`)
- `Extracted_CDFs/` corpus directory
