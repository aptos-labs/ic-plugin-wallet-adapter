import type {
  AccountInfo,
  AdapterPlugin,
  NetworkInfo,
  SignMessagePayload,
  SignMessageResponse,
  WalletName,
} from '@aptos-labs/wallet-adapter-core';
import { NetworkName } from '@aptos-labs/wallet-adapter-core';
import { NetworkName as ICNetworkName } from '@identity-connect/api';
import { ICDappClient, ICDappClientConfig } from '@identity-connect/dapp-sdk';
import {
  JsonTransactionPayload,
  SignTransactionRequestArgs,
  SignTransactionResponseArgs, TransactionOptions,
} from '@identity-connect/wallet-api';
import { BCS, HexString, TxnBuilderTypes, Types } from 'aptos';
import { txnAuthenticatorFromAccountAuthenticator } from './normalization';

type ICAccount = Awaited<ReturnType<ICDappClient['getConnectedAccounts']>>[0];
const ChainIds: Record<NetworkName, string | undefined> = {
  mainnet: "1",
  testnet: "2",
  devnet: undefined,
};

function decodeBase64(base64Str: string): Uint8Array {
  return Uint8Array.from(atob(base64Str), (m) => m.codePointAt(0)!);
}

function convertAccount(account: ICAccount) {
  const publicKeyBytes = decodeBase64(account.accountEd25519PublicKeyB64);
  const publicKey = HexString.fromUint8Array(publicKeyBytes).toString();
  return {
    address: account.accountAddress,
    publicKey,
    dappWalletId: account.dappWalletId,
  };
}

function isIcNetworkName(networkName: NetworkName | ICNetworkName): networkName is ICNetworkName {
  return Object.values(ICNetworkName).includes(networkName as any);
}

export const IcWalletName = "IdentityConnect" as WalletName<"IdentityConnect">;

export interface IdentityConnectWalletConfig extends ICDappClientConfig {
  networkName?: NetworkName;
  chainId?: string;
}

export class IdentityConnectWallet implements AdapterPlugin {
  // Hack to make this always available
  readonly providerName = 'open';
  readonly provider: typeof window.open | undefined;

  readonly name = IcWalletName;
  readonly url = "https://identityconnect.com";
  readonly icon = "data:image/png;base64,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"
  readonly client: ICDappClient;
  networkName: NetworkName;
  chainId: string;

  private onDisconnectListenerCleanup?: () => void;

  private get icNetworkName(): ICNetworkName {
    if (!isIcNetworkName(this.networkName)) {
      throw new Error(`Unsupported network ${this.networkName}`);
    }
    return this.networkName;
  }

  constructor(dappId: string, options: IdentityConnectWalletConfig = {}) {
    const {
      networkName = NetworkName.Mainnet,
      chainId,
      ...icDappClientOptions
    } = options;
    this.client = new ICDappClient(dappId, icDappClientOptions);
    this.networkName = networkName;
    this.chainId = chainId ?? ChainIds[networkName] ?? "";
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

    try {
      const response = await this.client.signAndSubmitTransaction(
        account.address,
        {
          payload: transaction as JsonTransactionPayload,
        },
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
        {
          payload: transaction,
        },
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
    payloadOrArgs: TxnBuilderTypes.TransactionPayload | SignTransactionRequestArgs,
    options?: TransactionOptions,
  ) {
    const account = await this.getConnectedAccount();
    if (!account) {
      throw `${IcWalletName} Account not paired`;
    }
    const isNewApi = 'payload' in payloadOrArgs || 'rawTxn' in payloadOrArgs;

    if (isNewApi) {
      return this.client.signTransaction(account.address, payloadOrArgs, { networkName: this.icNetworkName });
    }

    const { accountAuthenticator, rawTxn } = await this.client.signTransaction(account.address, {
      payload: payloadOrArgs,
      options,
    }, { networkName: this.icNetworkName });
    const txnAuthenticator =
      txnAuthenticatorFromAccountAuthenticator(accountAuthenticator);
    const signedTxn = new TxnBuilderTypes.SignedTransaction(
      rawTxn,
      txnAuthenticator,
    );
    return BCS.bcsToBytes(signedTxn);
  }

  async isDappWallet() {
    const account = await this.getConnectedAccount();
    return account?.dappWalletId;
  }

  async offboardDappWallet(): Promise<boolean> {
    const account = await this.getConnectedAccount();
    if (account === undefined) {
      return false;
    }

    if (account.dappWalletId === undefined) {
      throw "Can not export non-dapp wallet."
    }

    return this.client.offboard(account.address);
  }

  async onNetworkChange(callback: any): Promise<void> {
    // Not applicable for IC
  }

  async onAccountChange(callback: any): Promise<void> {
    // Not applicable for IC
    if (this.onDisconnectListenerCleanup) {
      this.onDisconnectListenerCleanup();
    }
    this.onDisconnectListenerCleanup = this.client.onDisconnect(() => {
      callback(null);
    });
  }

  async network(): Promise<NetworkInfo> {
    return {
      name: this.networkName,
      chainId: this.chainId,
    };
  }
}
