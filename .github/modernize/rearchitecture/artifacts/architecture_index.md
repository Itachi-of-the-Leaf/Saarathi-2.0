# Saarathi architecture index

This index is not the full contract. Do not implement from this file alone;
follow the artifact paths below.

## Global artifacts

- `project-structure.md`: functional areas, layers, entry points, and project type.
- `tech-stack.md`: existing runtime, framework, and dependency facts.
- `data-model.md`: persisted entities and transaction boundaries.
- `unit_graph.yaml`: externally triggered runtime units and dependencies.
- `wire_contracts.yaml`: Switch and GitHub external contracts.
- `shared_modules.yaml`: modules shared across runtime units.
- `cross_unit_state.yaml`: persisted state flows between runtime loops.

## Implementation Guide

### Unit: auditor-runtime

- Trigger: long-running process started by `python -m saarathi` or `python main.py`.
- Read `units/auditor-runtime/behavior.yaml` for preserved side effects and
  failure paths; read `units/auditor-runtime/bindings.yaml` for environment
  configuration; read `units/auditor-runtime/unit_decomposition.yaml` for
  advisory split candidates only.
- Filter `wire_contracts.yaml` by `unit: auditor-runtime`, and shared/state
  rows where `used_by_units`, `writer.unit`, or `reader.unit` includes this unit.
- Completion evidence: package paths read, preserved loops/contracts listed,
  and pytest plus smoke-test results recorded.

### Unit: demo-cli

- Trigger: `python -m scripts.demo_cli` or direct execution of the demo script.
- Read the three files under `units/demo-cli/` for the manual lifecycle contract.
- Filter global contracts by `unit: demo-cli`.
- Completion evidence: demo imports resolve and the smoke test passes.
