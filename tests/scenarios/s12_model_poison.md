# S12 — Tampered AI model

> Test sheet. All activity runs **only** in the isolated lab — see [RULES-OF-ENGAGEMENT.md](../../RULES-OF-ENGAGEMENT.md).

| Field | Value |
|---|---|
| **ID / Title** | S12 — Tampered AI model (poisoned artefact substitution) |
| **Run from** | the lab host — `bash tests/run-redteam.sh s12` |
| **Objective** | Verify the Zero Trust control: *signed model manifest* |
| **Tool / method** | `ai/tests/test_registry.py`: load the real bundle, then a modified artefact, then a missing one |
| **MITRE ATT&CK** | ATLAS AML.T0020 (poison training data / model) |
| **Preconditions** | Trained bundle and its `manifest.json` (SHA-256 of every artefact) |
| **Zero Trust control tested** | `ai/registry.py` verifies each artefact against the manifest before loading |
| **Expected result** | Tampered or missing artefact refused |

## Steps

1. Load the trained bundle: every hash matches, the models load.
2. Change one byte of an artefact and load again.
3. Remove an artefact and load again.

## Measurements

- 2026-11-21: 3 tests passed — bundle verifies and loads; tampered artefact refused; missing artefact refused.
- See `tests/evidence/s12_model_poison/` for the logs.

## Result

| | |
|---|---|
| **Actual result** | A modified model is never loaded by the inference service: the sensor keeps running the verified models. |
| **Status** (OK / KO / partial) | OK |
| **Proof** (logs, captures) | `tests/evidence/s12_model_poison/` |
| **Notes / improvements** | This covers the substitution of a trained model. Poisoning of the training data itself is limited by training offline, locally, on a fixed public dataset (CIC-IDS2017); it was not tested. |
