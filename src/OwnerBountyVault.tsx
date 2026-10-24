import { useEffect, useState } from "react";
import { ESCROW_NETWORKS } from "./lib/escrow-policy.mjs";
import type { VaultConnection } from "./lib/evm-vault-actions";
import { projectApiRequest } from "./lib/project-api";
import { formatAssetAmount } from "./lib/project-schema.mjs";
import type { ProjectDefinition } from "./lib/projects.mjs";
import { OwnerVaultSetup } from "./OwnerVaultSetup";
import { VaultActions } from "./VaultActions";

type PrivateFunds = {
  currency: string;
  decimals: number;
  availableMinor: string;
  freeMinor: string;
  snapshotAt: string;
};

/** Owner-only funding view. Bounty balances never use the public payment API. */
export function OwnerBountyVault({
  project,
  onRegistered,
}: {
  project: ProjectDefinition;
  onRegistered: (value: {
    project: ProjectDefinition;
    revision: number;
  }) => void;
}) {
  const [state, setState] = useState<
    | { status: "loading" }
    | { status: "error"; message: string }
    | { status: "ready"; funds: PrivateFunds | null; canSetup: boolean }
  >({ status: "loading" });
  const [reload, setReload] = useState(0);
  const [wallet, setWallet] = useState<VaultConnection | null>(null);
  // biome-ignore lint/correctness/useExhaustiveDependencies: Refresh repeats the private balance read.
  useEffect(() => {
    let active = true;
    setState({ status: "loading" });
    projectApiRequest<{ funds: PrivateFunds | null; canSetup: boolean }>(
      "GET",
      `project-vaults/${project.id}?purpose=security-bounty`,
    ).then(
      (result) => {
        if (active) setState({ status: "ready", ...result });
      },
      (error: unknown) => {
        if (active)
          setState({
            status: "error",
            message:
              error instanceof Error
                ? error.message
                : "Bounty funds could not load.",
          });
      },
    );
    return () => {
      active = false;
    };
  }, [project, reload]);
  const deployments = project.securityBounty?.settlement?.deployments ?? [];
  return (
    <section className="owner-section" aria-label="Bounty funds">
      <h2>Bounty funds</h2>
      <p>
        These funds are separate from contribution rewards. Slop shows this
        balance only to project owners.
      </p>
      {state.status === "loading" ? (
        <p role="status">Loading private bounty funds…</p>
      ) : null}
      {state.status === "error" ? <p role="alert">{state.message}</p> : null}
      {state.status === "ready" ? (
        <>
          {state.funds ? (
            <>
              <p>
                Available for new awards:{" "}
                {formatAssetAmount(
                  state.funds.availableMinor,
                  state.funds.decimals,
                )}{" "}
                {state.funds.currency}.
              </p>
              <p>
                Finalized balance checked at{" "}
                {new Date(state.funds.snapshotAt).toLocaleString()}.
              </p>
            </>
          ) : (
            <p>
              No current finalized balance is available. After a deposit, wait
              for the private scanner, then refresh.
            </p>
          )}
          {deployments.length === 0 && state.canSetup ? (
            <OwnerVaultSetup
              project={project}
              payoutPolicy="security-bounty"
              onRegistered={async (_deployment, connected) => {
                setWallet(connected);
                const result = await projectApiRequest<{
                  project: ProjectDefinition;
                  revision: number;
                }>("GET", `projects/${project.id}`);
                onRegistered(result);
                setReload((value) => value + 1);
              }}
            />
          ) : null}
          {deployments.map((deployment) =>
            ESCROW_NETWORKS[deployment.network].family === "evm" ? (
              <VaultActions
                key={`${deployment.network}:${deployment.vault}`}
                projectId={project.id}
                deployment={deployment}
                payoutPolicy="security-bounty"
                connectedWallet={wallet ?? undefined}
                onFinalized={() => setReload((value) => value + 1)}
              />
            ) : (
              <p key={deployment.vault}>
                This bounty vault uses Solana. The owner wallet can manage its
                funds.
              </p>
            ),
          )}
        </>
      ) : null}
      <button
        type="button"
        className="button secondary-button"
        disabled={state.status === "loading"}
        onClick={() => setReload((value) => value + 1)}
      >
        Refresh bounty funds
      </button>
    </section>
  );
}
