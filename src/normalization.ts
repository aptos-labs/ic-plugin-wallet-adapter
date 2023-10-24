import { TxnBuilderTypes } from 'aptos';

export function txnAuthenticatorFromAccountAuthenticator(
  authenticator: TxnBuilderTypes.AccountAuthenticator,
): TxnBuilderTypes.TransactionAuthenticator {
  if (authenticator instanceof TxnBuilderTypes.AccountAuthenticatorEd25519) {
    return new TxnBuilderTypes.TransactionAuthenticatorEd25519(
      authenticator.public_key,
      authenticator.signature,
    );
  }
  throw new Error('Unexpected value');
}
