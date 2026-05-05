import * as grpc from "@grpc/grpc-js"
import * as protoLoader from "@grpc/proto-loader"
import { fileURLToPath } from "node:url"
import { dirname, resolve } from "node:path"
import { Store } from "./state.js"
import { makeService } from "./service.js"

const __dirname = dirname(fileURLToPath(import.meta.url))
const PROTO_PATH = resolve(__dirname, "../proto/mls_client.proto")

function parsePort(argv: string[]): number {
  const idx = argv.indexOf("-p")
  if (idx !== -1 && argv[idx + 1]) return Number(argv[idx + 1])
  const env = process.env["PORT"]
  if (env) return Number(env)
  return 50053
}

function main() {
  const port = parsePort(process.argv.slice(2))

  const packageDefinition = protoLoader.loadSync(PROTO_PATH, {
    keepCase: true,
    longs: Number,
    enums: Number,
    defaults: true,
    oneofs: true,
  })

  const descriptor = grpc.loadPackageDefinition(packageDefinition) as unknown as {
    mls_client: { MLSClient: grpc.ServiceClientConstructor & { service: grpc.ServiceDefinition } }
  }
  const serviceDef = descriptor.mls_client.MLSClient.service

  const store = new Store()
  const server = new grpc.Server()
  server.addService(serviceDef, makeService(store))

  const bind = `0.0.0.0:${port}`
  server.bindAsync(bind, grpc.ServerCredentials.createInsecure(), (err, boundPort) => {
    if (err) {
      console.error(`[ts-mls interop] bind failed: ${err.message}`)
      process.exit(1)
    }
    console.log(`[ts-mls interop] listening on 0.0.0.0:${boundPort}`)
  })
}

main()
