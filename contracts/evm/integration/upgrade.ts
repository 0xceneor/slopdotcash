import { createHash } from "node:crypto";
import { encodeFunctionData, parseAbi } from "viem";
import type { EvmUpgrade } from "../adapter";

/** Local-chain fixture: use the same atomic proxy initialization as deployment scripts. */
export function deployUpgradeableFactory(
  deploy: (contract: string, args?: string[]) => string,
  args: string[],
): string {
  const vault = deploy("src/ProjectEscrow.sol:ProjectEscrow");
  const factory = deploy("src/ProjectEscrow.sol:EscrowFactory");
  const data = encodeFunctionData({
    abi: parseAbi([
      "function initialize(address,address,address,uint64,address,address)",
    ]),
    functionName: "initialize",
    args: [args[0], args[1], args[2], BigInt(args[3]), args[0], vault] as [
      `0x${string}`,
      `0x${string}`,
      `0x${string}`,
      bigint,
      `0x${string}`,
      `0x${string}`,
    ],
  });
  return deploy(
    "vendor/openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol:ERC1967Proxy",
    [factory, data],
  );
}

/** Capture observed addresses for local fixture assertions; this does not approve an implementation. */
export async function captureUpgrade(
  rpc: (method: string, params: unknown[]) => Promise<unknown>,
  factory: string,
  vault: string,
): Promise<EvmUpgrade> {
  const slot =
    "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";
  const read = async (address: string) => {
    const storage = String(
      await rpc("eth_getStorageAt", [address, slot, "latest"]),
    );
    const implementation = `0x${storage.slice(-40)}`;
    const code = String(await rpc("eth_getCode", [implementation, "latest"]));
    return {
      implementation,
      digest: createHash("sha256")
        .update(Buffer.from(code.slice(2), "hex"))
        .digest("hex"),
    };
  };
  const f = await read(factory);
  const v = await read(vault);
  const authority = String(
    await rpc("eth_call", [
      {
        to: factory,
        data: encodeFunctionData({
          abi: parseAbi(["function upgradeAuthority() view returns (address)"]),
          functionName: "upgradeAuthority",
        }),
      },
      "latest",
    ]),
  );
  return {
    authority: `0x${authority.slice(-40)}`,
    vaultImplementation: v.implementation,
    vaultImplementationCodeSha256: v.digest,
    factoryImplementation: f.implementation,
    factoryImplementationCodeSha256: f.digest,
  };
}
