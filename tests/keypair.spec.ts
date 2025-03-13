import { expect } from 'chai';
import { KeyPairError } from '../src/error.js';
import { KeyPair } from '../src/key-pair.js';
import { PrivateKey } from '../src/private-key.js';
import { PublicKey } from '../src/public-key.js';

describe('KeyPair instantiated', () => {
  const bytes = {
    privateKey : new Uint8Array([
      115, 253, 220, 18, 252, 147, 66, 187,
      41, 174, 155, 94, 212, 118, 50,  59,
      220, 105,  58, 17, 110,  54, 81,  36,
      85, 174, 232, 48, 254, 138, 37, 162
    ]),
    publicKey : new Uint8Array([
      2, 154, 213, 246, 168,  93,  39, 238,
      105, 177,  51, 174, 210, 115, 180, 242,
      245, 215,  14, 212, 167,  22, 117,   1,
      156,  26, 118, 240,  76, 102,  53,  38,
      239
    ])
  };


  describe('without params', () => {
    it('should throw KeyPairError', () => {
      expect(() => new KeyPair())
        .to.throw(KeyPairError, 'Argument missing: must at least provide a publicKey');
    });
  });

  describe('with private key bytes', () => {
    const keyPair = new KeyPair({ privateKey: bytes.privateKey });

    it('should construct a new instanceOf KeyPair', () => {
      expect(keyPair).to.be.instanceOf(KeyPair);
    });

    it('should have property privateKey as an instanceOf PrivateKey with matching bytes', () => {
      expect(keyPair.privateKey).to.be.instanceOf(PrivateKey);
      expect(keyPair.privateKey.bytes).to.deep.equal(bytes.privateKey);
    });

    it('should have property publicKey as an instanceOf PublicKey with matching bytes', () => {
      expect(keyPair.publicKey).to.be.instanceOf(PublicKey);
      expect(keyPair.publicKey.bytes).to.deep.equal(bytes.publicKey);
    });
  });

  describe('with public key bytes', () => {
    const keyPair = new KeyPair({ publicKey: bytes.publicKey });

    it('should construct a new instanceOf KeyPair', () => {
      expect(keyPair).to.be.instanceOf(KeyPair);
    });

    it('should not have property privateKey', () => {
      expect(() => keyPair.privateKey).to.throw(KeyPairError, 'Private key not available');
    });

    it('should have property publicKey as an instanceOf PublicKey with matching bytes', () => {
      expect(keyPair.publicKey).to.be.instanceOf(PublicKey);
      expect(keyPair.publicKey.bytes).to.deep.equal(bytes.publicKey);
    });
  });

  describe('with private and public key bytes', () => {
    const keyPair = new KeyPair(bytes);

    it('should construct a new instanceOf KeyPair', () => {
      expect(keyPair).to.be.instanceOf(KeyPair);
    });

    it('should have property privateKey as an instanceOf PrivateKey with matching bytes', () => {
      expect(keyPair.privateKey).to.be.instanceOf(PrivateKey);
      expect(keyPair.privateKey.bytes).to.deep.equal(bytes.privateKey);
    });

    it('should have property publicKey as an instanceOf PublicKey with matching bytes', () => {
      expect(keyPair.publicKey).to.be.instanceOf(PublicKey);
      expect(keyPair.publicKey.bytes).to.deep.equal(bytes.publicKey);
    });
  });

  describe('with PrivateKey', () => {
    const privateKey = new PrivateKey(bytes.privateKey);
    const keyPair = new KeyPair({ privateKey });

    it('should construct a new KeyPair', () => {
      expect(keyPair).to.be.instanceOf(KeyPair);
    });

    it('should construct', () => {
      expect(keyPair.privateKey).to.be.instanceOf(PrivateKey);
      expect(keyPair.publicKey).to.be.instanceOf(PublicKey);
    });
  });

  describe('with PublicKey', () => {
    const publicKey = new PublicKey(bytes.publicKey);
    const keyPair = new KeyPair({ publicKey });

    it('should construct a new KeyPair', () => {
      expect(keyPair).to.be.instanceOf(KeyPair);
    });

    it('should construct', () => {
      expect(() => keyPair.privateKey).to.throw(KeyPairError, 'Private key not available');
      expect(keyPair.publicKey).to.be.instanceOf(PublicKey);
    });
  });


  describe('with PrivateKey and PublicKey', () => {
    const privateKey = new PrivateKey(bytes.privateKey);
    const publicKey = new PublicKey(bytes.publicKey);
    const keyPair = new KeyPair({ privateKey, publicKey });

    it('should construct a new KeyPair', () => {
      expect(keyPair).to.be.instanceOf(KeyPair);
    });

    it('should construct', () => {
      expect(keyPair.privateKey).to.be.instanceOf(PrivateKey);
      expect(keyPair.publicKey).to.be.instanceOf(PublicKey);
    });
  });
});