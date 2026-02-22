export type VaultCustomField = {
  key: string;
  value: string;
};

export type VaultItemPayload = {
  username?: string;
  password?: string;
  notes?: string;
  otpSecret?: string | null;
  customFields?: VaultCustomField[];
  [key: string]: unknown;
};

export type VaultItemMetadata = {
  id: string;
  title: string;
  itemType: string;
  websiteUrl: string | null;
  favorite: boolean;
  createdAt: Date;
  updatedAt: Date;
  lastViewedAt: Date | null;
};

export type VaultItemDetail = VaultItemMetadata & {
  payload: VaultItemPayload;
};

export type EncryptedVaultPayload = {
  encryptedPayload: string;
  iv: string;
  authTag: string;
  encryptionAlgorithm: string;
  keyVersion: number;
  encryptedDataKey: string | null;
};
