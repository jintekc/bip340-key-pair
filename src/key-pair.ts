import { PrivateKeyBytes, PublicKeyBytes } from './types.js';
import { KeyPairError } from './error.js';
import { IKeyPair } from './interface.js';
import { PrivateKey } from './private-key.js';
import { PublicKey } from './public-key.js';

/** Params for the {@link KeyPair} constructor */
interface KeyPairParams {
  privateKey?: PrivateKey | PrivateKeyBytes;
  publicKey?: PublicKey | PublicKeyBytes;
}

/**
 * Encapsulates a PublicKey and a PrivateKey object as a single KeyPair object.
 * @export
 * @class KeyPair
 * @type {KeyPair}
 * @implements {IKeyPair}
 */
export class KeyPair implements IKeyPair {
  /** @type {PrivateKey} The private key object */
  private _privateKey?: PrivateKey;

  /** @type {PublicKey} The public key object */;
  private _publicKey: PublicKey;

  /**
   * Creates an instance of KeyPair. Must provide a at least a private key.
   * Can optionally provide btoh a private and public key, but must be a valid pair.
   * @constructor
   * @param {PrivateKey} privateKey The private key object
   */
  constructor({ privateKey, publicKey }: KeyPairParams = {} as KeyPairParams) {
    // If no private key or public key, throw an error
    if (!privateKey && !publicKey) {
      throw new KeyPairError('Argument missing: must at least provide a publicKey', 'KEYPAIR_CONSTRUCTOR_ERROR');
    }
    // Set the private and public keys
    this._privateKey = privateKey instanceof Uint8Array ? new PrivateKey(privateKey) : privateKey;
    this._publicKey = publicKey as PublicKey ?? this._privateKey?.computePublicKey();
  }

  /** @see IKeyPair.publicKey */
  set publicKey(publicKey: PublicKey) {
    this._publicKey = publicKey;
  }

  /** @see IKeyPair.publicKey */
  get publicKey(): PublicKey {
    const publicKey = this._publicKey;
    return publicKey;
  }

  /** @see IKeyPair.privateKey */
  get privateKey(): PrivateKey {
    if(!this._privateKey) {
      throw new KeyPairError('Private key not available', 'PRIVATE_KEY_ERROR');
    }
    const privateKey = this._privateKey;
    return privateKey;
  }
}

/**
 * Utility class for creating and working with KeyPair objects.
 * @export
 * @class KeyPairUtils
 * @type {KeyPairUtils}
 */
export class KeyPairUtils {
  /**
   * Static method creates a new KeyPair from a PrivateKey object or private key bytes.
   * @static
   * @param {PrivateKey | PrivateKeyBytes} pk The private key bytes
   * @returns {KeyPair} A new KeyPair object
   */
  public static fromPrivateKey(pk: PrivateKey | PrivateKeyBytes): KeyPair {

    // If the private key is a PrivateKey object, get the raw bytes else use the bytes
    const bytes = pk instanceof PrivateKey ? pk.bytes : pk;

    // Throw error if the private key is not 32 bytes
    if(bytes.length !== 32) {
      throw new KeyPairError('Invalid arg: must be 32 byte private key', 'FROM_PRIVATE_KEY_ERROR');
    }

    // If pk Uint8Array, construct PrivateKey object else use the object
    const privateKey = pk instanceof Uint8Array ? new PrivateKey(pk) : pk;

    // Compute the public key from the private key
    const publicKey = privateKey.computePublicKey();

    // Return a new KeyPair object
    return new KeyPair({ privateKey, publicKey });
  }

  /**
   * Static method generates a new KeyPair (PrivateKey, PublicKey).
   * @static
   * @returns {KeyPair} A new KeyPair object
   */
  public static generate(): KeyPair {
    const privateKey = PrivateKey.generate();
    // Derive the public key from the private key
    const publicKey = privateKey.computePublicKey();
    // Return a randomly generated KeyPair
    return new KeyPair({ privateKey, publicKey });
  }
}