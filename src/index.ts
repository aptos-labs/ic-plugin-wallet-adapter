import type {
  AccountInfo,
  AdapterPlugin,
  NetworkInfo,
  SignMessagePayload,
  SignMessageResponse,
  WalletName,
} from '@aptos-labs/wallet-adapter-core';
import { NetworkName } from '@aptos-labs/wallet-adapter-core';
import { type JsonPayload, NetworkName as ICNetworkName } from '@identity-connect/api';
import { ICDappClient, ICDappClientConfig } from '@identity-connect/dapp-sdk';
import { TxnBuilderTypes, Types } from 'aptos';

type ICAccount = Awaited<ReturnType<ICDappClient['getConnectedAccounts']>>[0];

function convertAccount(account: ICAccount) {
  const publicKey = Buffer.from(account.accountEd25519PublicKeyB64, 'base64').toString('hex');
  return {
    address: account.accountAddress,
    publicKey,
  };
}

function isIcNetworkName(networkName: NetworkName | ICNetworkName): networkName is ICNetworkName {
  return Object.values(ICNetworkName).includes(networkName as any);
}

export const IcWalletName = "IdentityConnect" as WalletName<"IdentityConnect">;

export interface IdentityConnectWalletConfig extends ICDappClientConfig {
  networkName?: NetworkName;
}

export class IdentityConnectWallet implements AdapterPlugin {
  // Hack to make this always available
  readonly providerName = 'open';
  readonly provider: typeof window.open | undefined;

  readonly name = IcWalletName;
  readonly url =
    "https://identity-connect.staging.gcp.aptosdev.com/";
  readonly icon = "data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMjQiIGhlaWdodD0iMjQiIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0ibm9uZSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj4KICAgIDxtYXNrIGlkPSJwYXRoLTEtaW5zaWRlLTFfODEzM18yNTQwMyIgZmlsbD0iY3VycmVudENvbG9yIj4KICAgICAgICA8cGF0aCBmaWxsLXJ1bGU9ImV2ZW5vZGQiIGNsaXAtcnVsZT0iZXZlbm9kZCIgZD0iTTE1IDE4SDEwVjE2SDE1VjE4WiIvPgogICAgICAgIDxwYXRoIGZpbGwtcnVsZT0iZXZlbm9kZCIgY2xpcC1ydWxlPSJldmVub2RkIiBkPSJNMTUgOEgxMFY2SDE1VjhaIi8+CiAgICAgICAgPHBhdGggZmlsbC1ydWxlPSJldmVub2RkIiBjbGlwLXJ1bGU9ImV2ZW5vZGQiIGQ9Ik0xOCAxMUMyMC4yMDkxIDExIDIyIDkuMjA5MTQgMjIgN0MyMiA0Ljc5MDg2IDIwLjIwOTEgMyAxOCAzQzE1Ljc5MDkgMyAxNCA0Ljc5MDg2IDE0IDdDMTQgOS4yMDkxNCAxNS43OTA5IDExIDE4IDExWk0yMiAxM1YyMUgxNFYxM0gyMlpNMTYgMTVWMTlIMjBWMTVIMTZaTTkgNUg1VjlIOVY1Wk01IDE3QzUgMTguMTA0NiA1Ljg5NTQzIDE5IDcgMTlDOC4xMDQ1NyAxOSA5IDE4LjEwNDYgOSAxN0M5IDE1Ljg5NTQgOC4xMDQ1NyAxNSA3IDE1QzUuODk1NDMgMTUgNSAxNS44OTU0IDUgMTdaTTE2IDdDMTYgOC4xMDQ1NyAxNi44OTU0IDkgMTggOUMxOS4xMDQ2IDkgMjAgOC4xMDQ1NyAyMCA3QzIwIDUuODk1NDMgMTkuMTA0NiA1IDE4IDVDMTYuODk1NCA1IDE2IDUuODk1NDMgMTYgN1pNMyAzVjExSDExVjNIM1pNNyAxM0M0Ljc5MDg2IDEzIDMgMTQuNzkwOSAzIDE3QzMgMTkuMjA5MSA0Ljc5MDg2IDIxIDcgMjFDOS4yMDkxNCAyMSAxMSAxOS4yMDkxIDExIDE3QzExIDE0Ljc5MDkgOS4yMDkxNCAxMyA3IDEzWiIvPgogICAgPC9tYXNrPgogICAgPHBhdGggZmlsbC1ydWxlPSJldmVub2RkIiBjbGlwLXJ1bGU9ImV2ZW5vZGQiIGQ9Ik0xNSAxOEgxMFYxNkgxNVYxOFoiIGZpbGw9IiMxQzJCNDMiLz4KICAgIDxwYXRoIGZpbGwtcnVsZT0iZXZlbm9kZCIgY2xpcC1ydWxlPSJldmVub2RkIiBkPSJNMTUgOEgxMFY2SDE1VjhaIiBmaWxsPSIjMUMyQjQzIi8+CiAgICA8cGF0aCBmaWxsLXJ1bGU9ImV2ZW5vZGQiIGNsaXAtcnVsZT0iZXZlbm9kZCIgZD0iTTE4IDExQzIwLjIwOTEgMTEgMjIgOS4yMDkxNCAyMiA3QzIyIDQuNzkwODYgMjAuMjA5MSAzIDE4IDNDMTUuNzkwOSAzIDE0IDQuNzkwODYgMTQgN0MxNCA5LjIwOTE0IDE1Ljc5MDkgMTEgMTggMTFaTTIyIDEzVjIxSDE0VjEzSDIyWk0xNiAxNVYxOUgyMFYxNUgxNlpNOSA1SDVWOUg5VjVaTTUgMTdDNSAxOC4xMDQ2IDUuODk1NDMgMTkgNyAxOUM4LjEwNDU3IDE5IDkgMTguMTA0NiA5IDE3QzkgMTUuODk1NCA4LjEwNDU3IDE1IDcgMTVDNS44OTU0MyAxNSA1IDE1Ljg5NTQgNSAxN1pNMTYgN0MxNiA4LjEwNDU3IDE2Ljg5NTQgOSAxOCA5QzE5LjEwNDYgOSAyMCA4LjEwNDU3IDIwIDdDMjAgNS44OTU0MyAxOS4xMDQ2IDUgMTggNUMxNi44OTU0IDUgMTYgNS44OTU0MyAxNiA3Wk0zIDNWMTFIMTFWM0gzWk03IDEzQzQuNzkwODYgMTMgMyAxNC43OTA5IDMgMTdDMyAxOS4yMDkxIDQuNzkwODYgMjEgNyAyMUM5LjIwOTE0IDIxIDExIDE5LjIwOTEgMTEgMTdDMTEgMTQuNzkwOSA5LjIwOTE0IDEzIDcgMTNaIiBmaWxsPSIjMUMyQjQzIi8+CiAgICA8cGF0aCBkPSJNMTAgMThIOFYyMEgxMFYxOFpNMTUgMThWMjBIMTdWMThIMTVaTTEwIDE2VjE0SDhWMTZIMTBaTTE1IDE2SDE3VjE0SDE1VjE2Wk0xMCA4SDhWMTBIMTBWOFpNMTUgOFYxMEgxN1Y4SDE1Wk0xMCA2VjRIOFY2SDEwWk0xNSA2SDE3VjRIMTVWNlpNMjIgMTNIMjRWMTFIMjJWMTNaTTIyIDIxVjIzSDI0VjIxSDIyWk0xNCAyMUgxMlYyM0gxNFYyMVpNMTQgMTNWMTFIMTJWMTNIMTRaTTE2IDE5SDE0VjIxSDE2VjE5Wk0xNiAxNVYxM0gxNFYxNUgxNlpNMjAgMTlWMjFIMjJWMTlIMjBaTTIwIDE1SDIyVjEzSDIwVjE1Wk01IDVWM0gzVjVINVpNOSA1SDExVjNIOVY1Wk01IDlIM1YxMUg1VjlaTTkgOVYxMUgxMVY5SDlaTTMgM1YxSDFWM0gzWk0zIDExSDFWMTNIM1YxMVpNMTEgMTFWMTNIMTNWMTFIMTFaTTExIDNIMTNWMUgxMVYzWk0xMCAyMEgxNVYxNkgxMFYyMFpNOCAxNlYxOEgxMlYxNkg4Wk0xNSAxNEgxMFYxOEgxNVYxNFpNMTcgMThWMTZIMTNWMThIMTdaTTEwIDEwSDE1VjZIMTBWMTBaTTggNlY4SDEyVjZIOFpNMTUgNEgxMFY4SDE1VjRaTTE3IDhWNkgxM1Y4SDE3Wk0xOCAxM0MyMS4zMTM3IDEzIDI0IDEwLjMxMzcgMjQgN0gyMEMyMCA4LjEwNDU3IDE5LjEwNDYgOSAxOCA5VjEzWk0yNCA3QzI0IDMuNjg2MjkgMjEuMzEzNyAxIDE4IDFWNUMxOS4xMDQ2IDUgMjAgNS44OTU0MyAyMCA3SDI0Wk0xOCAxQzE0LjY4NjMgMSAxMiAzLjY4NjI5IDEyIDdIMTZDMTYgNS44OTU0MyAxNi44OTU0IDUgMTggNVYxWk0xMiA3QzEyIDEwLjMxMzcgMTQuNjg2MyAxMyAxOCAxM1Y5QzE2Ljg5NTQgOSAxNiA4LjEwNDU3IDE2IDdIMTJaTTE4IDE5VjE1SDE0VjE5SDE4Wk0yMCAxN0gxNlYyMUgyMFYxN1pNMTggMTVWMTlIMjJWMTVIMThaTTE2IDE3SDIwVjEzSDE2VjE3Wk01IDdIOVYzSDVWN1pNNyA5VjVIM1Y5SDdaTTkgN0g1VjExSDlWN1pNNyA1VjlIMTFWNUg3Wk03IDE3SDNDMyAxOS4yMDkxIDQuNzkwODYgMjEgNyAyMVYxN1pNNyAxN1YyMUM5LjIwOTE0IDIxIDExIDE5LjIwOTEgMTEgMTdIN1pNNyAxN0gxMUMxMSAxNC43OTA5IDkuMjA5MTQgMTMgNyAxM1YxN1pNNyAxN1YxM0M0Ljc5MDg2IDEzIDMgMTQuNzkwOSAzIDE3SDdaTTE4IDdIMTRDMTQgOS4yMDkxNCAxNS43OTA5IDExIDE4IDExVjdaTTE4IDdWMTFDMjAuMjA5MSAxMSAyMiA5LjIwOTE0IDIyIDdIMThaTTE4IDdIMjJDMjIgNC43OTA4NiAyMC4yMDkxIDMgMTggM1Y3Wk0xOCA3VjNDMTUuNzkwOSAzIDE0IDQuNzkwODYgMTQgN0gxOFpNNSAxN0M1IDE1Ljg5NTQgNS44OTU0MyAxNSA3IDE1VjExQzMuNjg2MjkgMTEgMSAxMy42ODYzIDEgMTdINVpNNyAxOUM1Ljg5NTQzIDE5IDUgMTguMTA0NiA1IDE3SDFDMSAyMC4zMTM3IDMuNjg2MjkgMjMgNyAyM1YxOVpNOSAxN0M5IDE4LjEwNDYgOC4xMDQ1NyAxOSA3IDE5VjIzQzEwLjMxMzcgMjMgMTMgMjAuMzEzNyAxMyAxN0g5Wk03IDE1QzguMTA0NTcgMTUgOSAxNS44OTU0IDkgMTdIMTNDMTMgMTMuNjg2MyAxMC4zMTM3IDExIDcgMTFWMTVaTTE0IDE1SDIyVjExSDE0VjE1Wk0yMCAxM1YyMUgyNFYxM0gyMFpNMjIgMTlIMTRWMjNIMjJWMTlaTTE2IDIxVjEzSDEyVjIxSDE2Wk0zIDVIMTFWMUgzVjVaTTUgMTFWM0gxVjExSDVaTTExIDlIM1YxM0gxMVY5Wk05IDNWMTFIMTNWM0g5WiIgZmlsbD0iIzRENUM2RCIgbWFzaz0idXJsKCNwYXRoLTEtaW5zaWRlLTFfODEzM18yNTQwMykiLz4KPC9zdmc+Cg=="

  readonly client: ICDappClient;
  networkName: NetworkName;

  private get icNetworkName(): ICNetworkName {
    if (!isIcNetworkName(this.networkName)) {
      throw new Error(`Unsupported network ${this.networkName}`);
    }
    return this.networkName;
  }

  constructor(dappId: string, options: IdentityConnectWalletConfig = {}) {
    const { networkName = NetworkName.Mainnet, ...icDappClientOptions } = options;
    this.client = new ICDappClient(dappId, icDappClientOptions);
    this.networkName = networkName;
  }

  private async getConnectedAccount() {
    const accounts = await this.client.getConnectedAccounts();
    return accounts[0] ? convertAccount(accounts[0]) : undefined;
  }

  async connect(): Promise<AccountInfo> {
    const account = await this.getConnectedAccount();
    if (account !== undefined) {
      return account;
    }

    await this.client.connect();
    const newAccount = await this.getConnectedAccount();
    if (!newAccount) {
      throw new Error(`${IcWalletName} Address Info Error`);
    }

    return newAccount;
  }

  async account(): Promise<AccountInfo> {
    const account = await this.getConnectedAccount();
    if (!account) {
      throw new Error(`${IcWalletName} Account Error`);
    }
    return account;
  }

  async disconnect(): Promise<void> {
    const account = await this.getConnectedAccount();
    if (account) {
      await this.client.disconnect(account.address);
    }
  }

  async signAndSubmitTransaction(
    transaction: Types.TransactionPayload,
  ): Promise<{ hash: Types.HexEncodedBytes }> {
    const account = await this.getConnectedAccount();
    if (!account) {
      throw `${IcWalletName} Account not paired`;
    }

    if (!['entry_function_payload', 'multisig_payload', undefined].includes(transaction.type)) {
      throw `${IcWalletName} Transaction type not supported`;
    }
    const jsonPayload = transaction as JsonPayload;

    try {
      const response = await this.client.signAndSubmitTransaction(
        account.address,
        jsonPayload,
        { networkName: this.icNetworkName },
      );
      return response as { hash: Types.HexEncodedBytes };
    } catch (error: any) {
      throw error?.message ?? error;
    }
  }

  async signAndSubmitBCSTransaction(
    transaction: TxnBuilderTypes.TransactionPayload,
  ): Promise<{ hash: Types.HexEncodedBytes }> {
    const account = await this.getConnectedAccount();
    if (!account) {
      throw `${IcWalletName} Account not paired`;
    }

    try {
      const response = await this.client.signAndSubmitTransaction(
        account.address,
        transaction,
        { networkName: this.icNetworkName },
      );
      return response as { hash: Types.HexEncodedBytes };
    } catch (error: any) {
      throw error?.message ?? error;
    }
  }

  async signMessage(message: SignMessagePayload): Promise<SignMessageResponse> {
    const account = await this.getConnectedAccount();
    if (!account) {
      throw `${IcWalletName} Account not paired`;
    }

    if (typeof message !== "object" || !message.nonce) {
      throw `${IcWalletName} Invalid signMessage Payload`;
    }

    const {
      prefix,
      ...rest
    } = await this.client.signMessage(account.address, message, { networkName: this.icNetworkName });
    if (prefix !== 'APTOS') {
      throw `${IcWalletName} Sign Message failed`;
    }
    return { prefix, ...rest };
  }

  async signTransaction(
    transaction: Types.TransactionPayload | TxnBuilderTypes.TransactionPayload,
  ): Promise<{ hash: Types.HexEncodedBytes }> {
    throw new Error('Method not supported');
  }

  async onNetworkChange(callback: any): Promise<void> {
    // Not applicable for IC
  }

  async onAccountChange(callback: any): Promise<void> {
    // Not applicable for IC
  }

  async network(): Promise<NetworkInfo> {
    return {
      name: this.networkName,
    };
  }
}
