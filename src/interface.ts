import { Hex, PrefixBytes, PrivateKeyBytes, PublicKeyBytes, PublicKeyMultibaseBytes } from './types.js';
import { PrivateKey } from './private-key.js';
import { PublicKey } from './public-key.js';
import { KeyPair } from './key-pair.js';

/**
 * Interface for the PrivateKey class.
 * @export
 * @interface IPrivateKey
 * @type {IPrivateKey}
 */
export interface IPrivateKey {
  /**
   * Get the private key bytes
   * @readonly @type {PrivateKeyBytes} The private key bytes.
   */
  bytes: PrivateKeyBytes;

  /**
   * Getter returns the private key bytes in secret form.
   * Setter allows alternative method of using a bigint secret to genereate the private key bytes.
   * @type {BigInt} The private key secret.
   */
  secret: BigInt;

  /**
   * Get the private key point
   * @readonly @type {BigInt} The private key point.
   */
  point: BigInt;

  /**
   * Checks if this private key is equal to another private key
   * @public
   * @returns {boolean} True if the private keys are equal
   */
  equals(other: PrivateKey): boolean;

  /**
   * Uses the private key to compute the corresponding public key.
   * @see PrivateKeyUtils.computePublicKey
   * @public
   * @returns {PublicKey} A new PublicKey object
   */
  computePublicKey(): PublicKey;

  /**
   * Returns the private key as a hex string
   * @public
   * @returns {Hex} The private key as a hex string
   */
  hex(): Hex;
}


/**
 * Interface for the PublicKey class.
 * @export
 * @interface IPublicKey
 * @type {IPublicKey}
 */
export interface IPublicKey {
  /**
   * Compressed public key getter
   * @type {PublicKeyBytes} The 33 byte compressed public key [parity, x-coord]
   */
  bytes: PublicKeyBytes;

  /**
   * Uncompressed public key getter
   * @type {PublicKeyBytes} The 65 byte uncompressed public key [0x04, x-coord, y-coord]
   */
  uncompressed: PublicKeyBytes;

  /**
   * Public key parity getter
   * @type {number} The 1 byte parity (0x02 if even, 0x03 if odd)
   */
  parity: number;

  /**
   * Public key multibase prefix getter
   * @type {PrefixBytes} The 2 byte multibase prefix
   */
  prefix: PrefixBytes;

  /**
   * Public key x-coordinate getter
   * @type {PublicKeyBytes} The 32 byte x-coordinate of the public key
   */
  x: PublicKeyBytes;

  /**
   * Public key y-coordinate getter
   * @type {PublicKeyBytes} The 32 byte y-coordinate of the public key
   */
  y: PublicKeyBytes;

  /**
   * Public key multibase getter
   * @returns {string} The public key as a base58btc multibase string
   */
  multibase: string;

  /**
   * Decode the base58btc multibase string to the compressed public key prefixed with 0x02
   * @returns {PublicKeyMultibaseBytes} The public key as a 33-byte compressed public key with header.
   */
  decode(): PublicKeyMultibaseBytes;

  /**
   * Encode the PublicKey as an x-only base58btc multibase public key
   * @returns {string} The public key formatted a base58btc multibase string
   */
  encode(): string;

  /**
   * Public key hex getter.
   * @returns {Hex} The public key as a hex string.
   */
  hex(): Hex;

  /**
   * Public key equality check. Checks if `this` public key is equal to `other` public key.
   * @param {PublicKey} other The public key to compare.
   * @returns {boolean} True if the public keys are equal.
   */
  equals(other: PublicKey): boolean;
}

/**
 * Interface for class KeyPair
 * @export
 * @interface IKeyPair
 * @type {IKeyPair}
 */
export interface IKeyPair {
  /** @readonly @type {PublicKey} Get/set the public key associated with the key pair (required) */
  readonly publicKey: PublicKey;

  /**
   * @readonly
   * @type {PrivateKey} The private key associated with this key pair (optional)
   * @throws {KeyPairError} If the private key is not available
   */
  readonly privateKey?: PrivateKey;
}