import { spawn, type ChildProcess } from "node:child_process"
import { closeSync, openSync } from "node:fs"
import { access, mkdir, readFile } from "node:fs/promises"
import { dirname, resolve } from "node:path"
import { fileURLToPath } from "node:url"
import * as grpc from "@grpc/grpc-js"

const root = resolve(dirname(fileURLToPath(import.meta.url)), "../..")
const resultsDir = resolve(root, process.env.INTEROP_RESULTS_DIR ?? "interop/results")
const scenarios = process.argv.slice(2)
const defaults = ["ci"]

interface Exit {
  code: number | null
  signal: NodeJS.Signals | null
  error?: Error
}

interface Running {
  child: ChildProcess
  done: Promise<Exit>
  log: string
}

interface Case {
  actors: Record<string, string>
  encrypt_flag: boolean
  failed_step?: number
  error?: unknown
}

function requiredPath(name: string): string {
  const value = process.env[name]
  if (!value) throw new Error(`Set ${name}; see interop/README.md`)
  return resolve(root, value)
}

function launch(command: string, args: string[], name: string, stdout?: string): Running {
  const log = resolve(resultsDir, `${name}.log`)
  const logFd = openSync(log, "w")
  const outFd = stdout ? openSync(stdout, "w") : logFd
  try {
    const child = spawn(command, args, { cwd: root, stdio: ["ignore", outFd, logFd] })
    const done = new Promise<Exit>((resolve) => {
      child.once("error", (error) => resolve({ code: null, signal: null, error }))
      child.once("close", (code, signal) => resolve({ code, signal }))
    })
    return { child, done, log }
  } finally {
    closeSync(logFd)
    if (outFd !== logFd) closeSync(outFd)
  }
}

function ready(port: number): Promise<void> {
  const client = new grpc.Client(`127.0.0.1:${port}`, grpc.credentials.createInsecure())
  return new Promise((resolve, reject) => {
    client.waitForReady(Date.now() + 30_000, (error) => {
      client.close()
      if (error) reject(error)
      else resolve()
    })
  })
}

async function stop(running: Running): Promise<void> {
  if (running.child.exitCode !== null || running.child.signalCode !== null) return
  running.child.kill("SIGTERM")
  const timer = setTimeout(() => running.child.kill("SIGKILL"), 5_000)
  try {
    await running.done
  } finally {
    clearTimeout(timer)
  }
}

async function main() {
  const runner = requiredPath("MLS_INTEROP_RUNNER")
  const openmls = requiredPath("OPENMLS_INTEROP_CLIENT")
  const configs = resolve(root, process.env.MLS_INTEROP_CONFIGS ?? "interop/configs")
  await Promise.all([access(runner), access(openmls), access(configs)])
  await mkdir(resultsDir, { recursive: true })

  const openmlsPort = Number(process.env.OPENMLS_PORT ?? 50051)
  const tsPort = Number(process.env.TS_MLS_PORT ?? 50053)
  if (
    [openmlsPort, tsPort].some((port) => !Number.isInteger(port) || port < 1 || port > 65535) ||
    openmlsPort === tsPort
  ) {
    throw new Error("OPENMLS_PORT and TS_MLS_PORT must be distinct valid ports")
  }

  const processes: Running[] = []
  const interrupt = () => processes.forEach(({ child }) => child.kill("SIGTERM"))
  process.once("SIGINT", interrupt)
  process.once("SIGTERM", interrupt)
  try {
    const servers = [
      launch(openmls, ["--host", "127.0.0.1", "--port", String(openmlsPort)], "openmls"),
      launch(process.execPath, ["--import", "tsx", "interop/src/server.ts", "-p", String(tsPort)], "ts-mls"),
    ]
    processes.push(...servers)
    const serverFailure = Promise.race(
      servers.map(async (server) => {
        const exit = await server.done
        throw new Error(`Interop server exited (${exit.error?.message ?? exit.code ?? exit.signal}); see ${server.log}`)
      }),
    )
    await Promise.race([Promise.all([ready(openmlsPort), ready(tsPort)]), serverFailure])

    let total = 0
    let mixedTotal = 0
    for (const scenario of scenarios.length > 0 ? scenarios : defaults) {
      if (!/^[a-z_]+$/.test(scenario)) throw new Error(`Invalid scenario: ${scenario}`)
      for (const suite of [1, 2, 3]) {
        const name = `${scenario}-${suite}`
        const output = resolve(resultsDir, `${name}.json`)
        const test = launch(
          runner,
          [
            "-client",
            `127.0.0.1:${openmlsPort}`,
            "-client",
            `127.0.0.1:${tsPort}`,
            "-config",
            resolve(configs, `${scenario}.json`),
            "-suite",
            String(suite),
            "-fail-fast",
          ],
          name,
          output,
        )
        processes.push(test)
        const timer = setTimeout(() => test.child.kill("SIGTERM"), 5 * 60_000)
        let exit: Exit
        try {
          exit = await Promise.race([test.done, serverFailure])
        } finally {
          clearTimeout(timer)
        }
        if (exit.code !== 0)
          throw new Error(
            `${name} failed (${exit.error?.message ?? exit.code ?? exit.signal}); see ${output} and ${test.log}`,
          )
        const report = JSON.parse(await readFile(output, "utf8")) as { scripts: Record<string, Case[]> }
        for (const [script, runs] of Object.entries(report.scripts)) {
          if (runs.length === 0) throw new Error(`${name}/${script} ran no cases`)
          const actors = Object.keys(runs[0]!.actors).sort()
          const assignments = new Set(
            runs.map((run) => JSON.stringify([run.encrypt_flag, actors.map((actor) => run.actors[actor])])),
          )
          if (assignments.size !== 2 ** (actors.length + 1)) {
            throw new Error(`${name}/${script} did not cover every role assignment in both handshake modes`)
          }
        }
        const cases = Object.values(report.scripts).flat()
        const mixed = cases.filter((test) => new Set(Object.values(test.actors)).size > 1).length
        if (
          cases.length === 0 ||
          mixed === 0 ||
          cases.some((test) => test.failed_step !== undefined || test.error !== undefined)
        ) {
          throw new Error(`${name} did not pass any mixed-implementation cases; see ${output}`)
        }
        total += cases.length
        mixedTotal += mixed
        console.log(`${name}: ${cases.length} passed (${mixed} mixed OpenMLS/ts-mls assignments)`)
      }
    }
    console.log(`Interop passed: ${total} cases, including ${mixedTotal} mixed assignments. Results: ${resultsDir}`)
  } finally {
    await Promise.all(processes.map(stop))
    process.removeListener("SIGINT", interrupt)
    process.removeListener("SIGTERM", interrupt)
  }
}

main().catch((error: unknown) => {
  console.error(error)
  process.exitCode = 1
})
