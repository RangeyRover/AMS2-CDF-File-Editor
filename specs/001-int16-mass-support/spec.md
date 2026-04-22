# Int16 Mass Support

## Overview
Based on user feedback, the current AMS2 CDF File Editor lacks support for a specific integer-based vehicle mass property. In the CDFbin format, the marker `21 67 0B 57 AB` (often found alongside `22 67 0B 57 AB`) precedes an `Int16` value representing the car's weight in kilograms. Currently, the application mistakenly identifies this marker as `BodyDragBase_Int32` and does not support `Int16` scalar types. This feature will introduce the `int16` data type to the parsing and encoding engine and correct the field definition, enabling users to edit the integer weight value.

## User Scenarios & Testing

### Scenario 1: Viewing the Int16 Mass
- **Given** the user opens a `.cdfbin` file containing the `21 67 0B 57 AB` marker
- **When** the file is parsed by the editor
- **Then** the UI should list `Mass_Int16` under the `GENERAL` section
- **And** the decoded value should display a valid integer representing kilograms

### Scenario 2: Editing the Int16 Mass
- **Given** the user has selected the `Mass_Int16` field
- **When** the user edits the value (e.g., changing `949` to `1000`) and clicks "Apply Edit"
- **Then** the value should be safely packed as a 2-byte signed integer
- **And** the resulting binary payload size must remain exactly the same as the original

## Functional Requirements
- **Comprehensive Field Dictionary**: Expand `CDF_DEFS` to include all ~298 missing hex markers from `Translation_for_ChassisCDFbin_JDougNY_V1.01.txt` (including full Differential, Suspension corners, and Right-side Wings).
- **Int16 Scalar Support**: Introduce the `int16` data type to the parsing and encoding engine.
- **Correct Field Definition**: Re-map `21 67 0B 57 AB` from `BodyDragBase_Int32` to `Mass_Int16` within the `GENERAL` category, utilizing the new `int16` layout.
1. **Int16 Scalar Support**: Extend the application's underlying scalar format dictionary (`_FMT`) to include an `int16` type, utilizing a 2-byte signed integer pack/unpack format (`<h`).
2. **Correct Field Definition**: Modify the `CDF_DEFS` mapping to properly identify the `21 67 0B 57 AB` marker as `Mass_Int16` (or `Mass_Integer`) within the `GENERAL` category, assigning it the `("int16",)` layout.
3. **Remove Incorrect Mapping**: Remove the erroneous mapping of `21 67 0B 57 AB` to `BodyDragBase_Int32` under the `BODY AERO` section.
4. **Validation Stability**: The addition of the 2-byte `int16` type must gracefully integrate with the `encode_payload` and `decode_payload` pipelines without breaking existing file byte-count consistency rules.

## Success Criteria
- The application correctly extracts and displays the `Int16` car weight from `.cdfbin` files containing the marker.
- Users can successfully edit the integer weight and save the file without corrupting the CDF header or altering the file's overall byte geometry.
- The `int16` type is generically available for future CDF field definitions.

## Assumptions
- The `Int16` value is a signed 16-bit integer (little-endian, standard for this binary format).
- Changing the `Int16` mass in the game files does not require an accompanying change in the `float` mass for the game to launch without crashing (user feedback indicates editing the `Int16` field alone achieves the desired effect).
