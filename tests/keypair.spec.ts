import { expect } from 'chai';
import { KeyPairError } from '../src/error.js';
import { KeyPair } from '../src/key-pair.js';
import { PrivateKey } from '../src/private-key.js';
import { PublicKey } from '../src/public-key.js';

describe('KeyPair instantiated', () => {
  const bytes =  new Uint8Array([
    115, 253, 220, 18, 252, 147, 66, 187,
    41, 174, 155, 94, 212, 118, 50,  59,
    220, 105,  58, 17, 110,  54, 81,  36,
    85, 174, 232, 48, 254, 138, 37, 162
  ]);
  const privateKey = new PrivateKey(bytes);
  const publicKey = privateKey.computePublicKey();

  describe('without params', () => {
    it('should throw KeyPairError', () => {
      expect(() => new KeyPair())
        .to.throw(KeyPairError, 'Argument missing: must at least provide a publicKey');
    });
  });

  describe('with private key bytes', () => {
    const keyPair = new KeyPair({ privateKey: bytes });

    it('should construct a new KeyPair', () => {
      expect(keyPair).to.be.instanceOf(KeyPair);
    });

    it('should have property privateKey as PrivateKey with matching bytes', () => {
      expect(keyPair.privateKey).to.be.instanceOf(PrivateKey);
      expect(keyPair.privateKey.bytes).to.deep.equal(bytes);
    });

    it('should have property publicKey as PublicKey with matching bytes', () => {
      expect(keyPair.publicKey).to.be.instanceOf(PublicKey);
      expect(keyPair.publicKey.bytes).to.deep.equal(bytes);
    });
  });

  describe('with PrivateKey', () => {
    const keyPair = new KeyPair({ privateKey });

    it('should construct a new KeyPair', () => {
      expect(keyPair).to.be.instanceOf(KeyPair);
    });

    it('should construct', () => {
      expect(keyPair.privateKey).to.be.instanceOf(PrivateKey);
      expect(keyPair.publicKey).to.be.instanceOf(PublicKey);
    });
  });


  describe('with PrivateKey and PublicKey', () => {
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