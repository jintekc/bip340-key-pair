export type Hex = Uint8Array | string;
export type PrivateKeyHex = Hex;
export type PublicKeyHex = Hex;
export type SignatureHex = Hex;
export type HashHex = Hex;

export type Bytes = Uint8Array;
export type PrivateKeyBytes = Bytes;
export type PublicKeyBytes = Bytes;
export type KeyBytes = Bytes;
export type PrefixBytes = Bytes;
export type PublicKeyMultibaseBytes = Bytes;
export type SignatureBytes = Bytes;
export type ProofBytes = Bytes;
export type HashBytes = Bytes;
export type MessageBytes = Bytes;

export type PrivateKeySecret = bigint;
export type PrivateKeySeed = PrivateKeyBytes | PrivateKeySecret;
export type PrivateKeyPoint = bigint;

export type PublicKeyJSON = {
    parity: number;
    x: PublicKeyBytes;
    y: PublicKeyBytes;
    hex: Hex;
    multibase: string;
    prefix: PrefixBytes;
}
export type PrivateKeyJSON = {
    bytes: PrivateKeyBytes;
    secret: PrivateKeySecret;
    point: PrivateKeyPoint
    hex: Hex;
}
export type KeyPairJSON = {
    privateKey: PrivateKeyJSON;
    publicKey: PublicKeyJSON;
}
