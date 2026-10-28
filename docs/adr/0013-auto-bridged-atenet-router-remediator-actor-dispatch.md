# 13. Auto-Bridged `atenet-router` Sandbox Remediator Actor Dispatch & Verified Manifests

Date: 2026-10-28

## Status

Accepted

## Context

In [Build & Deploy Sandbox Remediator Image, Apply ActorTemplate/sandbox-remediator-template & Verify Live gVisor Actor Execution via atenet-router](https://github.com/gke-demos/agent-security/issues/28), we built and deployed the digest-pinned `aegis-server` (`--mode=remediator-actor`) container image, registered `ActorTemplate/sandbox-remediator-template` (with a `SNAPSHOT_FIDELITY_MEMORY` Golden Snapshot), `Actor/remediator-1`, and `EgressPolicy/default` in atespace `aegis-system`, and verified live `POST /sandbox/execute` execution through `svc/atenet-router`.

That live validation surfaced three concrete contract details that `SubstrateSandboxConnector` (`internal/aegis/live_substrate.go`) and `manifests/` must honor:

1. `svc/atenet-router` routes HTTP requests to an `Actor` based on the `ate-target-actor: <atespace>/<actor>` request header (for example, `ate-target-actor: aegis-system/remediator-1`), forwarding to port `80` inside the gVisor guest sandbox.
2. `WorkerPool/aegis-remediator-pool` pods run the distroless `ateworker-gvisor` host worker daemon (which has no `/bin/sh` or `go` binary in the host container); guest workloads run inside gVisor `Actor` sandboxes invoked over `svc/atenet-router`, not via `kubectl exec` on the worker pod.
3. `kubectl-ate get egress-policy <actor-name> -a <atespace> -o json` takes the actor name (`remediator-1`) as its positional argument, and `WorkerPool.metadata.labels` (`workload: aegis-remediator-pool`) is required so `ate-controller` propagates the label to the registered `Worker` for `ActorTemplate.workerSelector.matchLabels`.

## Decision

1. **`SubstrateTargetActor` & `ate-target-actor` Header on `dispatchGatewayHTTP`**:
   - Add `SubstrateTargetActor` (configured via `SUBSTRATE_TARGET_ACTOR`, defaulting to `"aegis-system/remediator-1"`) to `RuntimeConfig`.
   - `SubstrateSandboxConnector.dispatchGatewayHTTP` always attaches `ate-target-actor: <SubstrateTargetActor>` on outbound `POST` requests to `SubstrateGatewayURL` and records the header in `OutboundWireRecord.Headers`.

2. **Auto-Bridged `svc/atenet-router` Dispatch in `LiveSubstrate` Mode**:
   - When `LiveSubstrate` is enabled and `SubstrateGatewayURL` is unset:
     - If running in-cluster (`KUBERNETES_SERVICE_HOST` is non-empty), `SubstrateSandboxConnector.Execute` dispatches directly to `http://atenet-router.ate-system.svc.cluster.local/sandbox/execute` with `ate-target-actor: aegis-system/remediator-1`.
     - If running locally, `verifyClusterViaKubectl` inspects `WorkerPool/aegis-remediator-pool`, `Actor/remediator-1` (`kubectl-ate get actors -a aegis-system -o json`), and `EgressPolicy/default` (`kubectl-ate get egress-policy remediator-1 -a aegis-system -o json`), and automatically bridges `POST /sandbox/execute` through `svc/atenet-router` (`kubectl -n ate-system port-forward svc/atenet-router <ephemeralPort>:80` when a real `kubectl` binary is used) so live `SCENARIO-04` and `SCENARIO-05` turns wake `Actor/remediator-1` and capture its real gVisor `/proc/version` (`Linux version 4.19.0-gvisor`), `zeroEnvSecretsVerified: true`, and `atenet` Egress MITM probe results (`githubAllowedProbe: http:200`, `evilExfilProbe: blocked`).

3. **Verified GKE & Agent Substrate Manifests (`manifests/`)**:
   - Update `manifests/01-agent-substrate-v050.yaml` so `WorkerPool/aegis-remediator-pool` includes `metadata.labels.workload: aegis-remediator-pool`.
   - Update `manifests/01b-substrate-actor-template.yaml` to match the verified protojson `ActorTemplate` (`containers` list with `PORT=80`, `SSL_CERT_FILE=/run/ate/trust-bundle.pem`, `wakeupProbe` on `:80/healthz`, `resources.limits` `cpuMillicores: 1000` / `memoryBytes: 536870912`, `systemInfo` `trustBundle` volume `egress-mitm.ate.dev` + `system-roots.ate.dev`) and `EgressPolicy` (`rules: [{https: {hostnames: ["api.github.com"], ports: {numbers: [443]}}}]`).
   - Update `manifests/02-aegis-deployment.yaml` to configure `SUBSTRATE_GATEWAY_URL=http://atenet-router.ate-system.svc.cluster.local/sandbox/execute` and `SUBSTRATE_TARGET_ACTOR=aegis-system/remediator-1`.

## Consequences

- **Positive**: Both in-cluster GKE pods and local port `8088` runs dispatch `delegate_sandbox_test` through `svc/atenet-router` to the live gVisor `Actor/remediator-1` with zero manual port-forwarding setup, and tracked manifests match the exact live cluster schema.
- **Negative**: Local auto-bridging spawns a short-lived loopback `kubectl port-forward` when `SUBSTRATE_GATEWAY_URL` is not explicitly set.
