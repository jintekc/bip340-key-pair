import { expect } from 'chai';
import { PublicKeyError } from '../src/error.js';
import { PublicKey } from '../src/public-key.js';

describe('PublicKey instantiated', () => {
  const bytes = new Uint8Array([
    2, 154, 213, 246, 168,  93,  39, 238,
    105, 177,  51, 174, 210, 115, 180, 242,
    245, 215,  14, 212, 167,  22, 117,   1,
    156,  26, 118, 240,  76, 102,  53,  38,
    239
  ]);
  const hex = '029ad5f6a85d27ee69b133aed273b4f2f5d70ed4a71675019c1a76f04c663526ef';
  const multibase = 'z66PwJnYvwJLhGrVc8vcuUkKs99sKCzYRM2HQ2gDCGTAStHk';
  const parity = 2;
  const x = new Uint8Array([
    154, 213, 246, 168,  93,  39, 238, 105,
    177,  51, 174, 210, 115, 180, 242, 245,
    215,  14, 212, 167,  22, 117,   1, 156,
    26, 118, 240,  76, 102,  53,  38, 239
  ]);
  const y = new Uint8Array([
    57, 120, 174, 166,  82, 187, 183, 241,
    7, 118, 238,   5, 196, 240, 218,   1,
    104,   9, 174,  89,  77, 178, 114,  59,
    36,  84, 218, 244, 179, 107, 163, 205
  ]);
  const uncompressed = new Uint8Array([
    4, 154, 213, 246, 168,  93,  39, 238, 105, 177,  51,
    174, 210, 115, 180, 242, 245, 215,  14, 212, 167,  22,
    117,   1, 156,  26, 118, 240,  76, 102,  53,  38, 239,
    57, 120, 174, 166,  82, 187, 183, 241,   7, 118, 238,
    5, 196, 240, 218,   1, 104,   9, 174,  89,  77, 178,
    114,  59,  36,  84, 218, 244, 179, 107, 163, 205
  ]);
  const prefix = new Uint8Array([225, 74]);
  const json = { parity, x, y, hex, multibase, prefix };
  const decoded = new Uint8Array([...prefix, ...x]);

  describe('with invalid bytes', () => {
    it('should throw PublicKeyError if bytes invalid', () => {
      expect(() => new PublicKey(new Uint8Array([0])))
        .to.throw(PublicKeyError, 'Invalid argument: byte length must be 32 (x-only) or 33 (compressed)');
    });
  });

  describe('with valid bytes', () => {
    const publicKey = new PublicKey(bytes);

    it('should be an instance of PublicKey', () => {
      expect(publicKey).to.be.instanceOf(PublicKey);
    });

    it('should have property bytes matching the seed bytes', () => {
      expect(publicKey.bytes).to.deep.equal(bytes);
    });

    it('should have property hex matching the expected hex', () => {
      expect(publicKey.hex).to.equal(hex);
    });

    it('should have property multibase matching the expected multibase', () => {
      expect(publicKey.multibase).to.equal(multibase);
    });

    it('should have property parity matching the expected parity', () => {
      expect(publicKey.parity).to.deep.equal(parity);
    });

    it('should x-coordinate matching the expected x-coordinate', () => {
      expect(publicKey.x).to.deep.equal(x);
    });

    it('should have y-coordinate matching the expected y-coordinate', () => {
      expect(publicKey.y).to.deep.equal(y);
    });

    it('should have property uncompressed matching the expected uncompressed', () => {
      expect(publicKey.uncompressed).to.deep.equal(uncompressed);
    });

    it('should have property prefix matching the expected prefix', () => {
      expect(publicKey.prefix).to.deep.equal(prefix);
    });

    it('should have property x matching the expected x', () => {
      expect(publicKey.x).to.deep.equal(x);
    });

    it('should equal the expected PublicKey', () => {
      expect(publicKey.equals(new PublicKey(bytes))).to.be.true;
    });

    it('should have property hex matching the expected hex', () => {
      expect(publicKey.hex).to.equal(hex);
    });

    it('should have a json representation matching the expected json', () => {
      expect(publicKey.json()).to.deep.equal(json);
    });

    it('should decode the multibase and match the expected multibase byte arrayt', () => {
      expect(publicKey.decode()).to.deep.equal(decoded);
    });

    it('should encode the x-coordinate and match the expected multibase', () => {
      expect(publicKey.encode()).to.equal(multibase);
    });
  });
});