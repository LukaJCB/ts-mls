# Interoperability tests

The adapter exposes ts-mls through the MLS WG gRPC interface. `pnpm test:interop` starts ts-mls and OpenMLS, runs the MLS WG test runner, and stops both servers on success or failure.

## CI

The `test-interop` job in [CI](../.github/workflows/ci.yml) runs on pull requests and the existing CI push branches. It pins the MLS WG runner and OpenMLS 0.8.0 revisions, Rust dependencies, and protobuf generators. Go and Rust builds are cached. JSON transcripts and server logs are uploaded as `interop-results`, including after a failed test run.

The default [CI scenarios](configs/ci.json) cover:

- Welcome/join with and without a path secret, external ratchet trees, and PSKs.
- Application messages in order, out of order, and across epochs.
- Empty commits, Add/Update/Remove proposals, forced paths, and application messages after membership changes.
- External PSKs by reference and value, and resumption PSKs by value.
- External joins, external joins with PSKs, and replacement of an existing member.

Each script runs in both public and private handshake modes, for every OpenMLS/ts-mls actor assignment, using their shared ciphersuites 1, 2, and 3. The harness rejects empty results, missing role assignments, and runs without mixed-implementation cases.

## Run locally

Install Node.js, pnpm, Go 1.27.4, Rust 1.92.0, and `protoc`, then install the JS dependencies from the repository root:

```sh
pnpm install --frozen-lockfile
pnpm --dir interop install --ignore-workspace --frozen-lockfile --ignore-scripts
```

Build the reference tools (the same revisions and commands used by CI):

```sh
git clone https://github.com/mlswg/mls-implementations.git .interop/mls-implementations
git -C .interop/mls-implementations checkout cfd450286d1bfd9cd2519b95c80f9771f94a5b1a
git clone https://github.com/openmls/openmls.git .interop/openmls
git -C .interop/openmls checkout 6b85f0edc560b4fe0f5b9266092947a774614f3f

go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.33.0
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.3.0
export PATH="$(go env GOPATH)/bin:$PATH"

protoc -I .interop/mls-implementations/interop/proto \
  --go_out=.interop/mls-implementations/interop/proto --go_opt=paths=source_relative \
  --go-grpc_out=.interop/mls-implementations/interop/proto --go-grpc_opt=paths=source_relative \
  .interop/mls-implementations/interop/proto/mls_client.proto
(cd .interop/mls-implementations && go build -mod=mod -o test-runner ./interop/test-runner)

cp interop/openmls.Cargo.lock .interop/openmls/Cargo.lock
cargo +1.92.0 build --locked --manifest-path .interop/openmls/Cargo.toml -p interop_client
```

Then run:

```sh
MLS_INTEROP_RUNNER=.interop/mls-implementations/test-runner \
OPENMLS_INTEROP_CLIENT=.interop/openmls/target/debug/interop_client \
pnpm test:interop
```

Results are written to `interop/results/`. `INTEROP_RESULTS_DIR`, `OPENMLS_PORT`, and `TS_MLS_PORT` override the output directory and default ports 50051/50053. Server readiness and test execution have timeouts; a failing server or runner makes the command fail.

All relative paths in these environment variables are resolved from the ts-mls repository root, including when pnpm launches the script from `interop/`.

To run another configuration, set `MLS_INTEROP_CONFIGS` to its directory and pass its filename without `.json`, for example `pnpm test:interop application`. The upstream `make run-rs` command starts a **mock**, not the OpenMLS implementation.

To run just the ts-mls server for another harness, use `pnpm --dir interop start -- -p 50053`.

## Reference-client limitations

The full upstream scenario collection does not pass against the pinned OpenMLS **interop client**. Its ReInit, Branch, NewMemberAdd, external-signer, and GroupContextExtensions RPCs are unimplemented. The upstream resumption-PSK-by-reference scenario also fails when OpenMLS tries to process its own proposal. These scenarios are not in the CI configuration; resumption PSKs by value are covered. Unexpected failures are never treated as skips.

CI scenarios use at most three actors. The pinned runner's combination generator aliases slices with larger actor sets, producing duplicate assignments and missing others. The harness checks unique assignments in both handshake modes so expanding a scenario cannot silently reduce coverage.

When updating the OpenMLS revision, regenerate `openmls.Cargo.lock` from that checkout and update the CI revision together. The lockfile also pins the Rust gRPC bindings used by OpenMLS.
