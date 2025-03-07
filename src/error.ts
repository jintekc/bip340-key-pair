export class KeyPairError extends Error {
  name: string = 'KeyPairError';
  type: string = 'KeyPairError';
  message: string;

  constructor(message: string, type?: string, name?: string) {
    super();
    this.type = type ?? this.type;
    this.name = name ?? this.name;
    this.message = message;
  }
}

export class PrivateKeyError extends KeyPairError {
  constructor(message: string, type?: string) {
    super(message, type ?? 'PrivateKeyError', 'PrivateKeyError');
  }
}

export class PublicKeyError extends KeyPairError {
  constructor(message: string, type?: string) {
    super(message, type ?? 'PublicKeyError', 'PublicKeyError');
  }
}