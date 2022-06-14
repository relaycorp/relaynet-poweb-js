// tslint:disable:max-classes-per-file

import { VError } from 'verror';

export abstract class PoWebError extends VError {
  override get name(): string {
    return this.constructor.name;
  }
}

export class ClientError extends PoWebError {}
export class ServerError extends PoWebError {}
export class ConnectionTimeoutError extends PoWebError {}

export class ParcelDeliveryError extends PoWebError {}

export class RefusedParcelError extends PoWebError {}

export class InvalidHandshakeChallengeError extends ServerError {}

export class NonceSignerError extends ClientError {}
