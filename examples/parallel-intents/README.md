# parallel-intents

Intent A (tasks A/B/C) and Intent D (tasks D/E) with a cross-intent dependency E → B. Two
deterministic local agent executions run in separate packs and link to their own tasks; the
change-graph read model shows the dependency, and E becomes eligible once B completes.
