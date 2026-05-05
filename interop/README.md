## Run locally

```sh
cd interop
pnpm install
pnpm start -- -p 50053    # or PORT=50053 pnpm start
```

Logs `[ts-mls interop] listening on 0.0.0.0:50053` when ready.

### Against OpenMLS

From a checkout of [mls-implementations](https://github.com/mlswg/mls-implementations):

```sh
# terminal 1 — OpenMLS on :50051
cd mls-implementations/interop && make run-rs

# terminal 2 — ts-mls on :50053
cd ts-mls/interop && pnpm start -- -p 50053

# terminal 3 — runner
cd mls-implementations/interop/test-runner
go run main.go \
  -client localhost:50051 \
  -client localhost:50053 \
  -config ../configs/welcome_join.json
```

The runner permutes the configured actors across both backends, so a green run
means every script passes in every (openmls, ts-mls) role assignment.
