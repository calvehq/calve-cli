# Multiple Baselines

Baselines are independent compositions, so you can hold several views of accepted work without branching. The [`multi-baseline`](../../examples/multi-baseline) example is the tested version.

```sh
clv baseline create B0 <p0> <p1> <p3>
clv baseline create B1 <p0> <p1> <p2>
clv baseline create B2 <p0> <p2> <p5>
```

None of these derives from another, and shared members are not duplicated.

Compare two:

```sh
clv baseline compare <b0> <b1>
```

Give one a name and make it the active one:

```sh
clv baseline alias set staging <b1>
clv baseline activate staging
```

Aliases and the active Baseline are local pointers. Moving one changes nothing accepted.

Put a Baseline's files in the working tree:

```sh
clv baseline materialize staging            # plan
clv baseline materialize staging --apply --activate
```

`--activate` moves the pointer only once the operation has completed.
