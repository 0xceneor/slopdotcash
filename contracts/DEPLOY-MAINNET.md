# Escrow mainnet deployment (humans only)

These are the exact human steps to deploy the escrow v4 `EscrowFactory` on
Base, Robinhood Chain and Ethereum, to verify its source, and to upgrade the
Solana program to the current source and make it immutable.

**Agents must not run any step in this file.** Agents never hold mainnet keys,
never sign, and never broadcast. An agent may prepare a command or review a
simulation output that a human gives it.

No project activates escrow because a factory or program exists. Activation
needs a reviewed manifest revision with the deployment evidence below
(`src/lib/escrow-policy.mjs`, `assertEscrowPolicy`).

## 0. Before any network

1. Check out the reviewed commit of `main`. Record its SHA. Run
   `git status` and confirm a clean tree.
2. Confirm that independent review, the testnet acceptance runs
   (`docs/robinhood-chain-testnet-runbook.md` and the Base Sepolia run) and a
   rehearsed key recovery runbook are recorded. These are launch gates.
3. Decide and record, for each chain, three public addresses and their
   custody:
   - `ESCROW_REGISTRAR`: creates vaults and proposes identity authority
     rotations. Use a reviewed multisig or hardware key, never the attester
     service key.
   - `ESCROW_IDENTITY_AUTHORITY`: Slop's attester key (PAY-05).
   - `ESCROW_FEE_RECIPIENT`: the network fee wallet. On Base the script
     defaults to Slop's published Base fee recipient
     `0x8f77C37D8650776bFe73c9b12B15209eE15D9b86` when this variable is not
     set. On every other chain it is required.
4. The deployer account pays gas only and holds no escrow role. Use a hardware
   wallet (`--ledger` or `--trezor`) or a Foundry keystore (`--account`).
   Never pass a private key on the command line.
5. Use Foundry 1.7.1 (commit `4072e48705af9d93e3c0f6e29e93b5e9a40caed8`).
   Build and test the exact tree:

   ```sh
   cd contracts/evm
   forge fmt --check
   forge build --sizes
   forge test
   ```

## 1. EVM factory deployment (Base, Robinhood Chain, Ethereum)

| Network | Chain id | Script | RPC variable |
| --- | --- | --- | --- |
| Base | 8453 | `script/DeployBase.s.sol:DeployBase` | `BASE_RPC_URL` |
| Robinhood Chain | 4663 | `script/DeployRobinhood.s.sol:DeployRobinhood` | `ROBINHOOD_RPC_URL` |
| Ethereum | 1 | `script/DeployEthereum.s.sol:DeployEthereum` | `ETHEREUM_RPC_URL` |

Each script rejects every other chain id and reverts when a required address
is missing. One factory serves every standard ERC-20 on its chain; the
registrar later creates one vault per project and token.

### 1.1 Robinhood Chain only: opcode check

The compiled contracts use `MCOPY` (Cancun). Read the ArbOS version first:

```sh
cast chain-id --rpc-url "$ROBINHOOD_RPC_URL"                  # 4663
cast call 0x0000000000000000000000000000000000000064 \
  'arbOSVersion()(uint256)' --rpc-url "$ROBINHOOD_RPC_URL"    # must be >= 75
```

`arbOSVersion()` returns 55 plus the ArbOS version; ArbOS 20 added `MCOPY`.
Stop if the value is below 75. Record the value and block.

### 1.2 Simulate

```sh
cd contracts/evm
export ESCROW_REGISTRAR=0x...
export ESCROW_IDENTITY_AUTHORITY=0x...
export ESCROW_FEE_RECIPIENT=0x...      # optional on Base only
forge script script/DeployEthereum.s.sol:DeployEthereum \
  --rpc-url "$ETHEREUM_RPC_URL" --ledger --sender 0xYourDeployer
```

Replace the script and RPC for Base or Robinhood Chain. Read the simulated
`FactoryDeployed` event: chain id, registrar, identity authority, fee
recipient, and `bindingDelay = 172800`. A second person checks each address
against the recorded decision.

### 1.3 Broadcast

Run the same command with `--broadcast`. Keep the `broadcast/` artifacts out of
git. Record the factory address and the deployment transaction hash.

### 1.4 Verify the deployed factory

```sh
FACTORY=0x...
RPC="$ETHEREUM_RPC_URL"
cast call "$FACTORY" 'registrar()(address)' --rpc-url "$RPC" --block finalized
cast call "$FACTORY" 'identityAuthority()(address)' --rpc-url "$RPC" --block finalized
cast call "$FACTORY" 'feeRecipient()(address)' --rpc-url "$RPC" --block finalized
cast call "$FACTORY" 'bindingDelay()(uint64)' --rpc-url "$RPC" --block finalized
cast call "$FACTORY" 'AUTHORITY_ROTATION_DELAY()(uint64)' --rpc-url "$RPC" --block finalized
cast code "$FACTORY" --rpc-url "$RPC" --block finalized | xxd -r -p | shasum -a 256
```

Deploy the same build with the same constructor arguments on a local Anvil and
compare the runtime code SHA-256. The digest is the manifest's
`factoryCodeSha256`.

### 1.5 Source verification

```sh
ARGS=$(cast abi-encode 'constructor(address,address,address,uint64)' \
  "$ESCROW_REGISTRAR" "$ESCROW_FEE_RECIPIENT" "$ESCROW_IDENTITY_AUTHORITY" 172800)
forge verify-contract "$FACTORY" src/ProjectEscrow.sol:EscrowFactory \
  --chain-id 1 --constructor-args "$ARGS" --watch \
  --verifier etherscan --etherscan-api-key "$ETHERSCAN_API_KEY"
```

- Base: `--chain-id 8453`, Etherscan v2 API key (Basescan).
- Ethereum: `--chain-id 1`.
- Robinhood Chain: `--chain-id 4663 --verifier blockscout --verifier-url
  https://robinhoodchain.blockscout.com/api/`.

`foundry.toml` pins solc 0.8.30, `evm_version = "cancun"`, optimizer 200 runs
and `bytecode_hash = "none"`; the verifier reads them from the project.

### 1.6 Each vault

Vault creation is permissionless. The project owner sends the transaction from
its own account and becomes the owner. `PURPOSE` is `0` for the ordinary vault
and `1` for a private bounty vault:

```sh
cast send "$FACTORY" 'create(bytes32,address,uint8)' \
  "$PROJECT_ID" "$TOKEN" "$PURPOSE" --rpc-url "$RPC" --ledger
KEY=$(cast call "$FACTORY" 'vaultKey(address,bytes32,address,uint8)(bytes32)' \
  "$OWNER" "$PROJECT_ID" "$TOKEN" "$PURPOSE" --rpc-url "$RPC")
VAULT=$(cast call "$FACTORY" 'vaults(bytes32)(address)' "$KEY" --rpc-url "$RPC")
```

Before you create a vault, check that the token is a standard ERC-20 with
exact transfers: no fee on transfer, no rebasing. Read `decimals()` and record
it. After creation, verify the vault source like the factory (the constructor
arguments are `projectId, token, owner, purpose, feeRecipient,
bindingDelay`), record its runtime code SHA-256 as `codeSha256`, and run
`verifyEvmDeployment` from `contracts/evm/adapter.ts` against the manifest
before activation.

### 1.7 EVM evidence

Record: source SHA, Foundry version, chain id, ArbOS version (Robinhood
Chain), deployer, registrar and custody, identity authority and custody, fee
recipient, factory address, deployment transaction, `factoryCodeSha256`, local
Anvil digest, explorer verification link, and for each vault its project ID,
token, decimals, creation transaction and `codeSha256`.

## 2. Solana program upgrade and finalization

Program: `slop-escrow`, ID `4hXeYxsTKbwVKRRn8P1emGNDmVUSx13VMykfUAsbPnnj`
(upgradeable, already on mainnet).

A human operator does every step below. An agent never runs these commands,
never holds the upgrade authority or payer key, and never signs or broadcasts.
The scripts in `contracts/solana/scripts/` only read chain state and build
unsigned transactions.

Placeholders:

- `$PROGRAM` = `4hXeYxsTKbwVKRRn8P1emGNDmVUSx13VMykfUAsbPnnj`
- `$RPC` = a private mainnet RPC URL (`-u $RPC` below; never commit it)
- `$UPGRADE_AUTHORITY` = the current upgrade authority signer (keypair path or
  `usb://ledger?key=N`)
- `$PAYER` = the fee payer keypair for the buffer
- `$IDENTITY` = the published Slop identity authority (attester) public key
- `$FEES` = the published Slop fee recipient public key

### 1. Preconditions

1. The change is merged to `main` through a reviewed PR. CI is green on the
   exact commit. Record the commit SHA as `$COMMIT`.
2. The independent review covers this program version (any-mint, permissionless
   deposit, 2% withdrawal fee, Config pinning).
3. `$IDENTITY` and `$FEES` are published and approved by the repository owner.
   They must be distinct. They cannot change after step 6.
4. The build has no `short-delay-for-tests` feature. Only `test-e2e.sh` sets it.

### 2. Verifiable build with the pinned toolchain

```bash
git clone https://github.com/SlopDotCash/slopdotcash.git && cd slopdotcash
git checkout "$COMMIT"
cd contracts/solana
# Either verifiable path; both use a pinned Docker image.
solana-verify build --library-name slop_escrow
# or: anchor build --verifiable   (Anchor 0.32.1; image solanafoundation/anchor:v0.32.1)
```

Record the output file (`target/deploy/slop_escrow.so` for `solana-verify`,
`target/verifiable/slop_escrow.so` for Anchor) as `$SO`.

```bash
sha256sum "$SO"                          # REVIEWED_SO_SHA256
solana-verify get-executable-hash "$SO"  # REVIEWED_EXECUTABLE_HASH
```

A second operator repeats this step on a different machine. Both hashes must
match. Record them in the release issue.

### 3. Record the current deployed program

```bash
solana program show "$PROGRAM" -u "$RPC"           # record Authority and Data Length
solana program dump "$PROGRAM" current.so -u "$RPC"
sha256sum current.so                               # PREVIOUS_DEPLOYED_SHA256
solana-verify get-program-hash "$PROGRAM" -u "$RPC"
```

The previous hash must equal the hash recorded at the last reviewed release.
If it differs, stop: the program changed outside the runbook.

If the size of `$SO` is larger than the `Data Length`, extend the program first:

```bash
solana program extend "$PROGRAM" <ADDITIONAL_BYTES> -u "$RPC" --keypair "$PAYER"
```

### 4. Write and check the buffer

```bash
solana program write-buffer "$SO" -u "$RPC" --keypair "$PAYER"   # prints BUFFER
solana program set-buffer-authority "$BUFFER" \
  --new-buffer-authority <UPGRADE_AUTHORITY_PUBKEY> -u "$RPC" --keypair "$PAYER"
solana program dump "$BUFFER" buffer.so -u "$RPC"
```

The prefix of `buffer.so` must equal `$SO` byte for byte, and any trailing
bytes must be zero:

```bash
python3 - "$SO" buffer.so <<'PY'
import sys, hashlib
local = open(sys.argv[1], 'rb').read(); remote = open(sys.argv[2], 'rb').read()
assert remote[:len(local)] == local, 'buffer differs'
assert not any(remote[len(local):]), 'nonzero trailing bytes'
print('ok', hashlib.sha256(local).hexdigest())
PY
```

### 5. Upgrade

```bash
solana program upgrade "$BUFFER" "$PROGRAM" \
  --upgrade-authority "$UPGRADE_AUTHORITY" -u "$RPC"
# equivalent: solana program deploy --program-id "$PROGRAM" --buffer "$BUFFER" \
#   --upgrade-authority "$UPGRADE_AUTHORITY" -u "$RPC"
solana program dump "$PROGRAM" upgraded.so -u "$RPC"
```

Run the same prefix check on `upgraded.so` against `$SO`. Then:

```bash
sha256sum upgraded.so                                # DEPLOYED_CODE_SHA256
solana-verify get-program-hash "$PROGRAM" -u "$RPC"  # must equal REVIEWED_EXECUTABLE_HASH
```

`DEPLOYED_CODE_SHA256` hashes every ProgramData byte after the 45-byte header,
including zero padding. It is the `codeSha256` value for every project manifest.

Optionally submit the verification to the public registry:
`solana-verify verify-from-repo -u "$RPC" --program-id "$PROGRAM" --library-name slop_escrow --mount-path contracts/solana --commit-hash "$COMMIT" https://github.com/SlopDotCash/slopdotcash`.

### 6. Create the Config (once, before revoking the upgrade authority)

Write `config-input.json`:

```json
{
  "programId": "4hXeYxsTKbwVKRRn8P1emGNDmVUSx13VMykfUAsbPnnj",
  "upgradeAuthority": "<UPGRADE_AUTHORITY_PUBKEY>",
  "codeSha256": "<DEPLOYED_CODE_SHA256>",
  "identityAuthority": "<IDENTITY>",
  "feeRecipient": "<FEES>"
}
```

Build the unsigned transaction. The script checks the cluster genesis, the
deployed bytes, the upgrade authority, and that no Config exists:

```bash
cd contracts/solana && npm ci --ignore-scripts --legacy-peer-deps
SLOP_SOLANA_RPC_URL="$RPC" \
SLOP_SOLANA_GENESIS=5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d \
SLOP_SOLANA_RECENT_BLOCKHASH="$(solana -u "$RPC" block --output json | jq -r .blockhash)" \
node scripts/config-plan.mjs plan config-input.json > config-plan.json
```

Check `config-plan.json`: `requiredSigner` is the upgrade authority,
`identityAuthority` is `$IDENTITY`, `feeRecipient` is `$FEES`. The upgrade
authority signs `transactionBase64` with its own wallet tooling and sends it,
within the blockhash lifetime (about 60 seconds; rebuild if it expires). The
transaction is an ordinary unsigned legacy transaction, the same format as
`owner-plan.mjs` output.

Confirm the result:

```bash
node scripts/config-plan.mjs projects config-input.json   # "config" shows $IDENTITY and $FEES
```

The Config has no update or close instruction. A mistake here requires a new
program deployment, so check both keys twice before signing.

### 7. List existing Project accounts

```bash
SLOP_SOLANA_RPC_URL="$RPC" SLOP_SOLANA_GENESIS=5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d \
node scripts/config-plan.mjs projects config-input.json > projects.json
```

This is a `getProgramAccounts` query on the Project discriminator
(`cda8bdcab5f78e13`). Every entry with `"pinned": false` was created before the
Config, or with another fee recipient. Record each one in the release issue
with its owner, fee recipient, identity authority and size. The adapter refuses
every unpinned project, so its manifest cannot activate payments. Tell its owner
to create a new project under the Config and move unused funds with
`withdraw` (2% fee).

### 8. Revoke the upgrade authority

```bash
solana program set-upgrade-authority "$PROGRAM" --final \
  --upgrade-authority "$UPGRADE_AUTHORITY" -u "$RPC"
```

After this, no one can change the program or create a Config.

### 9. Final checks

```bash
solana program show "$PROGRAM" -u "$RPC"   # Authority: none
solana program dump "$PROGRAM" final.so -u "$RPC"
sha256sum final.so                         # must equal DEPLOYED_CODE_SHA256
solana-verify get-program-hash "$PROGRAM" -u "$RPC"   # must equal REVIEWED_EXECUTABLE_HASH
node scripts/config-plan.mjs projects config-input.json   # Config unchanged
```

Every project manifest then uses `codeSha256 = DEPLOYED_CODE_SHA256`,
`upgradeAuthority = null`, `identityAuthority = $IDENTITY` and
`feeRecipient = $FEES`. The adapter (`verifySolanaDeployment`) refuses any
other value. Attach the commands, outputs and hashes from every step to the
release issue. An upgrade is not proof of payment availability: run the funded
lifecycle on each activated project separately.

## 3. Payout activation, one network at a time

Do this section for one network. Finish it, reconcile the first payout, and
record the evidence before you start the next network. Agents must not run
these steps; they may prepare commands and read reports.

The code does not enable a mainnet. Every value in
`workers/payment-executor/mainnet-execution.mjs` is `false`, and the
executor and the attester refuse a mainnet deployment before they read a
signer secret. `workers/payment-executor/configure.mjs --stack production`
generates the production stack for one mainnet. It is the identity attester
Worker only (PAY-05). Slop holds no relayer key and runs no dispatcher or
other scheduled job that starts a payment (PAY-04). The project or a
permissionless executor holds the relayer key and submits the approved
payments.

### 3.1 Preconditions

1. Sections 0 to 2 are complete for this network, and the independent review
   and the testnet acceptance runs are recorded.
2. An admin revision on `/admin` records the vault deployment in the project
   manifest (`escrow.deployments`), with the factory, factory code digest,
   registrar and identity authority from section 1.7 or section 2.9.
3. The identity authority address in each factory (EVM) or Config (Solana) is
   the address of the attester key that the attester Worker will use. Read it
   back from the chain at the finalized block and record it.

### 3.2 Configure the stack

1. Pin the signer deployments from the registry snapshot:
   `bun run projects:sync`, then
   `bun run payments:deployments mainnet <network> > pinned.json`.
2. Generate the stack:
   `node workers/payment-executor/configure.mjs --stack production --network <network> --deployments pinned.json --output workers/payment-executor/.generated`.
   It writes the attester configuration only, with
   `SIGNER_STACK=production`. Review the configuration and
   `apply-production-stack.sh`.
3. Put the attester key in the managed secret store of the attester Worker
   only, as `SIGNER_PRIVATE_KEY` (EVM) or `SOLANA_SIGNER_SEED` (Solana, 64 hex
   digits). One key per network. Never reuse the registrar, owner, fee-wallet
   or a test key. Do not create or store a relayer key: the project or a
   permissionless executor holds it (PAY-04). The hosted signer refuses the
   relayer role on a production stack.
4. Set `PAYMENT_RPC_URLS` on the attester Worker to a private endpoint for
   this network that serves the finalized tag (EVM) or finalized commitment
   (Solana).
5. To let contributors sign the destination binding on the site, add this
   network to the Pages variable `PAYMENT_NETWORKS` in `wrangler.toml`
   through a reviewed pull request. Until then `/wallets/bind-challenge`
   refuses this network.

### 3.3 Readiness report

Run the report with the stack configurations and the private RPC map in your
local shell. The report never prints an RPC URL.

```sh
PAYMENT_RPC_URLS="$PRIVATE_RPC_JSON" \
PAYMENT_SOLANA_GENESIS="$GENESIS_JSON" \
bun run payments:readiness \
  --registry-origin https://slop.cash \
  --config "$ATTESTER_CONFIG" \
  --probe
```

For each network the report states `factory`, `attester`, `rpc` and
`executor`. `--probe` reads the chain id or genesis hash and the finalized
head; `rpc=finalized` is the only passing probe result. For this network
`factory`, `attester` and `rpc` must pass. `executor` reports `missing`,
because Slop runs no relayer or dispatcher on a mainnet (PAY-04); the
executor of the project or the permissionless executor is verified
separately. Attach the report to the release issue.

### 3.4 Enable the executor for this network

1. Open a pull request that changes only this network's value in
   `mainnet-execution.mjs` to `true` and updates
   `mainnet-execution.test.ts` to match. Link the audit, the testnet evidence
   and the readiness report from step 3.3.
2. The repository owner reviews and merges it (PAY-05). Deploy the attester
   Worker from that reviewed commit only.
3. Run the readiness report again. `factory`, `attester` and `rpc` must
   pass for this network.

### 3.5 First payout and reconciliation

1. Approve one small award on one project of this network through the normal
   review flow. Wait for the contributor's wallet binding and its delay.
2. The executor of the project, or a permissionless executor, submits the
   payment with its own relayer key. Slop does not submit it, and does not
   send a manual transfer with any key.
3. Confirm the finalized `Paid` event, the obligation `state=paid`, the
   contributor net amount and the fee in the explorer, and the new
   `vault_snapshots` row (block, `total_paid`, `total_payout_fees`).
4. Confirm that the funding page shows the same totals and the observed time.
5. Record the transaction, the snapshot row and the page screenshot on the
   release issue. Then start the next network at step 3.1.

To stop new Slop attestations on a network, change its
`mainnet-execution.mjs` value back to `false` through a reviewed pull request
and redeploy the attester Worker. Slop cannot stop a payment that the project
or a permissionless executor submits for an approved and funded obligation.
