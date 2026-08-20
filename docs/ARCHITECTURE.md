# HUNTER v6 Architecture

## Core rule

The LLM is a planner, not the source of truth.

The source of truth is:

1. ScopeGuard
2. HTTP observations
3. Structured Evidence
4. Deterministic Decision Engine
5. Critic consistency checks

## Finding lifecycle

```text
candidate
   ↓
verification attempt
   ↓
evidence
   ↓
decision
   ├── confirmed
   ├── likely
   ├── inconclusive
   └── false_positive
```

## Adding a verifier

A verifier should:

- receive `ctx`
- perform only authorized, non-destructive checks
- return a JSON-serializable dictionary
- expose observable evidence
- never claim final severity by itself

Then add an evidence mapping and deterministic decision rule.
