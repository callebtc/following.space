import { AccountManager } from 'applesauce-accounts';
import { ExtensionAccount, NostrConnectAccount, PrivateKeyAccount } from 'applesauce-accounts/accounts';

// Creating a manager has no browser side effects. Restoration happens explicitly in login.ts.
export const accounts = new AccountManager();
accounts.registerType(ExtensionAccount);
accounts.registerType(NostrConnectAccount);
accounts.registerType(PrivateKeyAccount);
