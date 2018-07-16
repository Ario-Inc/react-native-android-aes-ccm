export as namespace AndroidAESCCMModule;

export function setKey(key: number[]): void;
export function encrypt(aad: number[], clear: number[], nonce: number[]): Promise<number[]>;
export function decrypt(aad: number[], encrypted: number[], nonce: number[], tag: number[]): Promise<number[]>;