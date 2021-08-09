// tslint:disable:max-classes-per-file

import {
  derSerializePublicKey,
  DETACHED_SIGNATURE_TYPES,
  generateRSAKeyPair,
  HandshakeChallenge,
  HandshakeResponse,
  issueEndpointCertificate,
  MAX_RAMF_MESSAGE_LENGTH,
  ParcelCollection,
  ParcelDelivery,
  PrivateNodeRegistration,
  Signer,
  StreamingMode,
} from '@relaycorp/relaynet-core';
import {
  generateNodeKeyPairSet,
  generatePDACertificationPath,
  NodeKeyPairSet,
  PDACertPath,
} from '@relaycorp/relaynet-testing';
import {
  AcceptConnectionAction,
  CloseConnectionAction,
  CloseFrame,
  createMockWebSocketStream,
  EmitClientErrorAction,
  MockServer,
  ReceiveMessageAction,
  SendMessageAction,
} from '@relaycorp/ws-mock';
import MockAdapter from 'axios-mock-adapter';
import bufferToArray from 'buffer-to-arraybuffer';
import { createHash } from 'crypto';
import pipe from 'it-pipe';

import {
  asyncIterableToArray,
  expectArrayBuffersToEqual,
  getMockInstance,
  getPromiseRejection,
  iterableTake,
} from './_test_utils';
import { WebSocketCode } from './_websocketUtils';
import {
  InvalidHandshakeChallengeError,
  NonceSignerError,
  ParcelDeliveryError,
  RefusedParcelError,
  ServerError,
} from './errors';

const mockCreateWebSocketStream = createMockWebSocketStream;
jest.mock('ws', () => ({
  __esModule: true,
  createWebSocketStream: mockCreateWebSocketStream,
  default: jest.fn(),
}));
import WebSocket, { ClientOptions } from 'ws';
import {
  PARCEL_CONTENT_TYPE,
  PNR_CONTENT_TYPE,
  PNRA_CONTENT_TYPE,
  PNRR_CONTENT_TYPE,
  PoWebClient,
} from './PoWebClient';

let nodeKeyPairs: NodeKeyPairSet;
let certificationPath: PDACertPath;
beforeAll(async () => {
  nodeKeyPairs = await generateNodeKeyPairSet();
  certificationPath = await generatePDACertificationPath(nodeKeyPairs);
});

describe('Common Axios instance defaults', () => {
  test('responseType should be ArrayBuffer', () => {
    const client = PoWebClient.initLocal();

    expect(client.internalAxios.defaults.responseType).toEqual('arraybuffer');
  });

  test('maxContentLength should be 1 MiB', () => {
    const client = PoWebClient.initLocal();

    expect(client.internalAxios.defaults.maxContentLength).toEqual(1048576);
  });

  test('Redirects should be disabled', () => {
    const client = PoWebClient.initLocal();

    expect(client.internalAxios.defaults.maxRedirects).toEqual(0);
  });

  test('Status validation should be disabled', () => {
    const client = PoWebClient.initLocal();

    expect(client.internalAxios.defaults.validateStatus?.(400)).toEqual(true);
  });
});

describe('initLocal', () => {
  test('Host name should be the localhost IP address', () => {
    const client = PoWebClient.initLocal();

    expect(client.hostName).toEqual('127.0.0.1');
  });

  test('TLS should not be used', () => {
    const client = PoWebClient.initLocal();

    expect(client.useTLS).toBeFalsy();
  });

  test('Port should default to 276', () => {
    const client = PoWebClient.initLocal();

    expect(client.port).toEqual(276);
  });

  test('Port should be overridable', () => {
    const port = 13276;
    const client = PoWebClient.initLocal(port);

    expect(client.port).toEqual(port);
  });

  test('Base URL should factor in the host name, port and use of TLS', () => {
    const client = PoWebClient.initLocal();

    expect(client.internalAxios.defaults.baseURL).toEqual('http://127.0.0.1:276/v1');
  });

  test('HTTP agent should be configured with Keep-Alive', () => {
    const client = PoWebClient.initLocal();

    expect(client.internalAxios.defaults.httpAgent.keepAlive).toEqual(true);
  });

  test('Default timeout should be 3 seconds', () => {
    const client = PoWebClient.initLocal();

    expect(client.internalAxios.defaults.timeout).toEqual(3_000);
  });
});

describe('initRemote', () => {
  const hostName = 'gw.relaycorp.tech';

  test('Specified host name should be honored', () => {
    const client = PoWebClient.initRemote(hostName);

    expect(client.hostName).toEqual(hostName);
  });

  test('TLS should be used', () => {
    const client = PoWebClient.initRemote(hostName);

    expect(client.useTLS).toBeTruthy();
  });

  test('Port should default to 443', () => {
    const client = PoWebClient.initRemote(hostName);

    expect(client.port).toEqual(443);
  });

  test('Port should be overridable', () => {
    const port = 13276;
    const client = PoWebClient.initRemote(hostName, port);

    expect(client.port).toEqual(port);
  });

  test('Base URL should factor in the host name, port and use of TLS', () => {
    const client = PoWebClient.initRemote(hostName);

    expect(client.internalAxios.defaults.baseURL).toEqual(`https://${hostName}:443/v1`);
  });

  test('HTTPS agent should be configured with Keep-Alive', () => {
    const client = PoWebClient.initRemote(hostName);

    expect(client.internalAxios.defaults.httpsAgent.keepAlive).toEqual(true);
  });

  test('Default timeout should be 5 seconds', () => {
    const client = PoWebClient.initRemote(hostName);

    expect(client.internalAxios.defaults.timeout).toEqual(5_000);
  });
});

describe('preRegisterNode', () => {
  let client: PoWebClient;
  let mockAxios: MockAdapter;
  beforeEach(() => {
    client = PoWebClient.initLocal();
    mockAxios = new MockAdapter(client.internalAxios);
  });

  const PNRA_SERIALIZED = Buffer.from('the PNRA');

  test('Request should be POSTed to /v1/pre-registrations', async () => {
    mockAxios
      .onPost('/pre-registrations')
      .reply(200, PNRA_SERIALIZED, { 'content-type': PNRA_CONTENT_TYPE });

    await client.preRegisterNode(nodeKeyPairs.privateGateway.publicKey);

    expect(mockAxios.history.post).toHaveLength(1);
    expect(mockAxios.history.post[0].url).toEqual('/pre-registrations');
    expect(mockAxios.history.post[0].headers).toHaveProperty('Content-Type', 'text/plain');
  });

  test('Request body should be SHA-256 digest of the node public key', async () => {
    mockAxios
      .onPost('/pre-registrations')
      .reply(200, PNRA_SERIALIZED, { 'content-type': PNRA_CONTENT_TYPE });

    await client.preRegisterNode(nodeKeyPairs.privateGateway.publicKey);

    const publicKeySerialized = await derSerializePublicKey(nodeKeyPairs.privateGateway.publicKey);
    const expectedDigest = createHash('sha256').update(publicKeySerialized).digest('hex');
    expect(Buffer.from(mockAxios.history.post[0].data).toString()).toEqual(expectedDigest);
  });

  test('An invalid response content type should be refused', async () => {
    const invalidContentType = 'application/json';
    mockAxios.onPost('/pre-registrations').reply(200, null, { 'content-type': invalidContentType });

    await expect(client.preRegisterNode(nodeKeyPairs.privateGateway.publicKey)).rejects.toEqual(
      new ServerError(`Server responded with invalid content type (${invalidContentType})`),
    );
  });

  test('20X response status other than 200 should throw an error', async () => {
    const statusCode = 201;
    mockAxios
      .onPost('/pre-registrations')
      .reply(statusCode, null, { 'content-type': PNRA_CONTENT_TYPE });

    await expect(client.preRegisterNode(nodeKeyPairs.privateGateway.publicKey)).rejects.toEqual(
      new ServerError(`Unexpected response status (${statusCode})`),
    );
  });

  test('Authorization should be output serialized if status is 200', async () => {
    mockAxios.onPost('/pre-registrations').reply(200, PNRA_SERIALIZED, {
      'content-type': PNRA_CONTENT_TYPE,
    });

    const authorizationSerialized = await client.preRegisterNode(
      nodeKeyPairs.privateGateway.publicKey,
    );

    expect(authorizationSerialized).toBeInstanceOf(ArrayBuffer);
    expect(PNRA_SERIALIZED.equals(Buffer.from(authorizationSerialized))).toBeTruthy();
  });
});

describe('registerNode', () => {
  let client: PoWebClient;
  let mockAxios: MockAdapter;
  beforeEach(() => {
    client = PoWebClient.initLocal();
    mockAxios = new MockAdapter(client.internalAxios);
  });

  const pnraSerialized = bufferToArray(Buffer.from('the authorization'));

  let expectedRegistration: PrivateNodeRegistration;
  let expectedRegistrationSerialized: Buffer;
  beforeAll(async () => {
    const tomorrow = new Date();
    tomorrow.setDate(tomorrow.getDate() + 1);

    expectedRegistration = new PrivateNodeRegistration(
      certificationPath.privateGateway,
      certificationPath.publicGateway,
    );
    expectedRegistrationSerialized = Buffer.from(expectedRegistration.serialize());
  });

  test('PNRA should be POSTed to /v1/nodes', async () => {
    mockAxios
      .onPost('/nodes')
      .reply(200, expectedRegistrationSerialized, { 'content-type': PNR_CONTENT_TYPE });

    await client.registerNode(pnraSerialized);

    expect(mockAxios.history.post).toHaveLength(1);
    expect(mockAxios.history.post[0].url).toEqual('/nodes');
    expect(mockAxios.history.post[0].headers).toHaveProperty('Content-Type', PNRR_CONTENT_TYPE);
    expect(
      Buffer.from(mockAxios.history.post[0].data).equals(Buffer.from(pnraSerialized)),
    ).toBeTruthy();
  });

  test('An invalid response content type should be refused', async () => {
    const invalidContentType = 'text/plain';
    mockAxios
      .onPost('/nodes')
      .reply(200, expectedRegistrationSerialized, { 'content-type': invalidContentType });

    await expect(client.registerNode(pnraSerialized)).rejects.toEqual(
      new ServerError(`Server responded with invalid content type (${invalidContentType})`),
    );
  });

  test('20X response status other than 200 should throw an error', async () => {
    const statusCode = 201;
    mockAxios
      .onPost('/nodes')
      .reply(statusCode, expectedRegistrationSerialized, { 'content-type': PNR_CONTENT_TYPE });

    await expect(client.registerNode(pnraSerialized)).rejects.toEqual(
      new ServerError(`Unexpected response status (${statusCode})`),
    );
  });

  test('Malformed registrations should be refused', async () => {
    const invalidRegistration = Buffer.from('invalid');
    mockAxios
      .onPost('/nodes')
      .reply(200, invalidRegistration, { 'content-type': PNR_CONTENT_TYPE });

    await expect(client.registerNode(pnraSerialized)).rejects.toMatchObject({
      message: /^Malformed registration received/,
    });
  });

  test('Registration should be output if response status is 200', async () => {
    mockAxios
      .onPost('/nodes')
      .reply(200, expectedRegistrationSerialized, { 'content-type': PNR_CONTENT_TYPE });

    const registration = await client.registerNode(pnraSerialized);

    expect(
      expectedRegistration.privateNodeCertificate.isEqual(registration.privateNodeCertificate),
    ).toBeTruthy();
    expect(
      expectedRegistration.gatewayCertificate.isEqual(registration.gatewayCertificate),
    ).toBeTruthy();
  });
});

describe('deliverParcel', () => {
  const parcelSerialized = bufferToArray(Buffer.from('I am a "parcel"'));
  let signer: Signer;
  beforeAll(async () => {
    signer = new Signer(certificationPath.privateGateway, nodeKeyPairs.privateGateway.privateKey);
  });

  let client: PoWebClient;
  let mockAxios: MockAdapter;
  beforeEach(() => {
    client = PoWebClient.initLocal();
    mockAxios = new MockAdapter(client.internalAxios);
  });

  test('Parcel should be POSTed to /v1/parcels', async () => {
    mockAxios.onPost('/parcels').reply(200, null);

    await client.deliverParcel(parcelSerialized, signer);

    expect(mockAxios.history.post).toHaveLength(1);
    expect(mockAxios.history.post[0].url).toEqual('/parcels');
    expect(mockAxios.history.post[0].headers).toHaveProperty('Content-Type', PARCEL_CONTENT_TYPE);
    expect(
      Buffer.from(mockAxios.history.post[0].data).equals(Buffer.from(parcelSerialized)),
    ).toBeTruthy();
  });

  test('Delivery signature should be in the request headers', async () => {
    mockAxios.onPost('/parcels').reply(200, null);

    await client.deliverParcel(parcelSerialized, signer);

    const authorizationHeaderValue = mockAxios.history.post[0].headers.authorization;
    expect(authorizationHeaderValue).toBeDefined();
    expect(authorizationHeaderValue).toStartWith('Relaynet-Countersignature ');
    const [, countersignatureBase64] = authorizationHeaderValue.split(' ', 2);
    const countersignature = Buffer.from(countersignatureBase64, 'base64');
    await DETACHED_SIGNATURE_TYPES.PARCEL_DELIVERY.verify(
      bufferToArray(countersignature),
      parcelSerialized,
      [certificationPath.publicGateway],
    );
  });

  test('HTTP 20X should be regarded a successful delivery', async () => {
    mockAxios.onPost('/parcels').reply(200, null);
    await client.deliverParcel(parcelSerialized, signer);

    mockAxios.onPost('/parcels').reply(299, null);
    await client.deliverParcel(parcelSerialized, signer);
  });

  test('HTTP 422 should throw a RefusedParcelError', async () => {
    mockAxios.onPost('/parcels').reply(422, null);

    const error = await getRejection(client.deliverParcel(parcelSerialized, signer));

    expect(error).toBeInstanceOf(RefusedParcelError);
    expect(error.message).toEqual('Parcel was rejected');
  });

  test('RefusedParcelError should include rejection reason if available', async () => {
    const message = 'Not enough postage';
    mockAxios.onPost('/parcels').reply(422, { message });

    const error = await getRejection(client.deliverParcel(parcelSerialized, signer));

    expect(error).toBeInstanceOf(RefusedParcelError);
    expect(error.message).toEqual(`Parcel was rejected: ${message}`);
  });

  test('HTTP 50X should throw a ServerError', async () => {
    mockAxios.onPost('/parcels').reply(500, null);

    const error = await getRejection(client.deliverParcel(parcelSerialized, signer));

    expect(error).toBeInstanceOf(ServerError);
    expect(error.message).toEqual('Server was unable to get parcel (HTTP 500)');
  });

  test('HTTP responses other than 20X/422/50X should throw errors', async () => {
    mockAxios.onPost('/parcels').reply(400, null);

    const error = await getRejection(client.deliverParcel(parcelSerialized, signer));

    expect(error).toBeInstanceOf(ParcelDeliveryError);
    expect(error.message).toEqual('Could not deliver parcel (HTTP 400)');
  });

  test('Other client exceptions should be propagated', async () => {
    mockAxios.onPost('/parcels').networkError();

    const error = await getRejection(client.deliverParcel(parcelSerialized, signer));

    expect(error).toHaveProperty('isAxiosError', true);
  });
});

describe('collectParcels', () => {
  const ENDPOINT_URL = new URL('ws://127.0.0.1:276/v1/parcel-collection');

  const NONCE = bufferToArray(Buffer.from('the-nonce'));

  let nonceSigner: Signer;
  beforeAll(async () => {
    nonceSigner = new Signer(
      certificationPath.privateEndpoint,
      nodeKeyPairs.privateEndpoint.privateKey,
    );
  });

  let mockServer: MockServer;
  beforeEach(() => {
    mockServer = new MockServer();
    getMockInstance(WebSocket).mockImplementation(() => mockServer.mockClientWebSocket);
  });
  afterEach(() => {
    getMockInstance(WebSocket).mockReset();
  });

  test('Maximum incoming payload size should be enough for large parcels', async () => {
    const client = PoWebClient.initLocal();

    await Promise.all([
      asyncIterableToArray(client.collectParcels([nonceSigner])).catch(() => undefined),
      mockServer.runActions(new AcceptConnectionAction(), new CloseConnectionAction()),
    ]);

    expect(WebSocket).toBeCalledWith(
      expect.anything(),
      expect.objectContaining({ maxPayload: MAX_RAMF_MESSAGE_LENGTH }),
    );
  });

  test('Request should be made to the parcel collection endpoint', async () => {
    const client = PoWebClient.initLocal();

    await Promise.all([
      asyncIterableToArray(client.collectParcels([nonceSigner])).catch(() => undefined),
      mockServer.runActions(new AcceptConnectionAction(), new CloseConnectionAction()),
    ]);

    expect(WebSocket).toBeCalledWith(ENDPOINT_URL.toString(), expect.anything());
  });

  test('At least one nonce signer should be required', async () => {
    const client = PoWebClient.initLocal();

    const error = await getPromiseRejection(asyncIterableToArray(client.collectParcels([])));

    expect(error).toBeInstanceOf(NonceSignerError);
    expect(error.message).toEqual('At least one nonce signer must be specified');
    expect(WebSocket).not.toBeCalled();
  });

  describe('Handshake', () => {
    test('Server closing connection before handshake should throw error', async () => {
      const client = PoWebClient.initLocal();

      const sessionPromise = Promise.all([
        asyncIterableToArray(client.collectParcels([nonceSigner])),
        mockServer.runActions(new AcceptConnectionAction(), new CloseConnectionAction()),
      ]);

      const error = await getPromiseRejection(sessionPromise);
      expect(error).toBeInstanceOf(InvalidHandshakeChallengeError);
      expect(error.message).toEqual('Server closed the connection before/during the handshake');

      await expect(mockServer.waitForPeerClosure()).resolves.toEqual({
        code: WebSocketCode.NORMAL,
      });
    });

    test('Server closing connection during handshake should throw error', async () => {
      const client = PoWebClient.initLocal();

      const sessionPromise = Promise.all([
        asyncIterableToArray(client.collectParcels([nonceSigner])),
        mockServer.runActions(new AcceptConnectionAction(), new CloseConnectionAction()),
      ]);

      const error = await getPromiseRejection(sessionPromise);
      expect(error).toBeInstanceOf(InvalidHandshakeChallengeError);
      expect(error.message).toEqual('Server closed the connection before/during the handshake');

      await expect(mockServer.waitForPeerClosure()).resolves.toEqual({
        code: WebSocketCode.NORMAL,
      });
    });

    test('Connection error during handshake should be rethrown', async () => {
      const client = PoWebClient.initLocal();
      const originalError = new Error('Something went wrong');

      const sessionPromise = Promise.all([
        asyncIterableToArray(client.collectParcels([nonceSigner])),
        mockServer.runActions(
          new AcceptConnectionAction(),
          new EmitClientErrorAction(originalError),
        ),
      ]);

      const error = await getPromiseRejection(sessionPromise);
      expect(error).toBeInstanceOf(ServerError);
      expect(error.message).toStartWith('Got connection error before/during the handshake:');
      expect((error as ServerError).cause()).toEqual(originalError);

      expect(mockServer.peerCloseFrame).toBeNull();
    });

    test('Getting a malformed challenge should throw an error', async () => {
      const client = PoWebClient.initLocal();

      const sessionPromise = Promise.all([
        asyncIterableToArray(client.collectParcels([nonceSigner])),
        mockServer.runActions(new AcceptConnectionAction(), new SendMessageAction('malformed')),
      ]);

      const error = await getPromiseRejection(sessionPromise);
      expect(error).toBeInstanceOf(InvalidHandshakeChallengeError);
      expect(error.message).toStartWith('Server sent a malformed handshake challenge:');
      expect((error as InvalidHandshakeChallengeError).cause()).toBeTruthy();

      expect(mockServer.wasConnectionClosed).toBeTrue();
      expect(mockServer.peerCloseFrame?.code).toEqual(WebSocketCode.CANNOT_ACCEPT);
      expect(mockServer.peerCloseFrame?.reason).toEqual('Malformed handshake challenge');
    });

    test('Challenge nonce should be signed with each signer', async () => {
      const client = PoWebClient.initLocal();
      const receiveResponseAction = new ReceiveMessageAction();

      await Promise.all([
        asyncIterableToArray(
          client.collectParcels([nonceSigner], StreamingMode.CLOSE_UPON_COMPLETION),
        ),
        mockServer.runActions(
          new AcceptConnectionAction(),
          new SendHandshakeChallengeAction(NONCE),
          receiveResponseAction,
          new CloseConnectionAction(),
        ),
      ]);

      expect(receiveResponseAction.message).toBeInstanceOf(Buffer);
      const response = HandshakeResponse.deserialize(
        bufferToArray(receiveResponseAction.message as Buffer),
      );
      expect(response.nonceSignatures).toHaveLength(1);

      await DETACHED_SIGNATURE_TYPES.NONCE.verify(response.nonceSignatures[0], NONCE, [
        certificationPath.privateGateway,
      ]);
    });

    describe('Handshake completion callback', () => {
      test('Callback should not be called if handshake fails', async () => {
        const client = PoWebClient.initLocal();
        const handshakeCallback = jest.fn();

        await expect(
          Promise.all([
            asyncIterableToArray(
              client.collectParcels([nonceSigner], StreamingMode.KEEP_ALIVE, handshakeCallback),
            ),
            mockServer.runActions(new AcceptConnectionAction(), new CloseConnectionAction()),
          ]),
        ).toReject();

        expect(handshakeCallback).not.toBeCalled();
      });

      test('Callback should be called after handshake but before the first parcel', async () => {
        const client = PoWebClient.initLocal();
        const handshakeCallback = jest.fn();

        await Promise.all([
          asyncIterableToArray(
            client.collectParcels(
              [nonceSigner],
              StreamingMode.CLOSE_UPON_COMPLETION,
              handshakeCallback,
            ),
          ),
          mockServer.runActions(
            new AcceptConnectionAction(),
            new SendHandshakeChallengeAction(NONCE),
            new ReceiveMessageAction(), // Handshake response
            new CloseConnectionAction(),
          ),
        ]);

        await expect(handshakeCallback).toBeCalledWith();
      });
    });
  });

  test('Call should return if server closed connection normally after the handshake', async () => {
    const client = PoWebClient.initLocal();

    const [parcelCollections] = await Promise.all([
      asyncIterableToArray(
        client.collectParcels([nonceSigner], StreamingMode.CLOSE_UPON_COMPLETION),
      ),
      mockServer.runActions(
        new AcceptConnectionAction(),
        new SendHandshakeChallengeAction(NONCE),
        new ReceiveMessageAction(),
        new CloseConnectionAction(),
      ),
    ]);

    expect(parcelCollections).toHaveLength(0);

    await expect(mockServer.waitForPeerClosure()).resolves.toEqual({
      code: WebSocketCode.NORMAL,
    });
  });

  test('Call should return if server closed connection without status', async () => {
    const client = PoWebClient.initLocal();

    await Promise.all([
      asyncIterableToArray(
        client.collectParcels([nonceSigner], StreamingMode.CLOSE_UPON_COMPLETION),
      ),
      mockServer.runActions(
        new AcceptConnectionAction(),
        new SendHandshakeChallengeAction(NONCE),
        new ReceiveMessageAction(),
        new CloseConnectionAction(WebSocketCode.NO_STATUS),
      ),
    ]);

    await expect(mockServer.waitForPeerClosure()).resolves.toEqual({
      code: WebSocketCode.NORMAL,
    });
  });

  test('Error should be thrown if server closes connection with error code', async () => {
    const client = PoWebClient.initLocal();
    const closeReason = 'Just because';

    const sessionPromise = Promise.all([
      asyncIterableToArray(client.collectParcels([nonceSigner])),
      mockServer.runActions(
        new AcceptConnectionAction(),
        new SendHandshakeChallengeAction(NONCE),
        new ReceiveMessageAction(),
        new CloseConnectionAction(WebSocketCode.VIOLATED_POLICY, closeReason),
      ),
    ]);

    const error = await getPromiseRejection(sessionPromise);
    expect(error).toBeInstanceOf(ServerError);
    expect(error.message).toEqual(
      'Server closed connection unexpectedly ' +
        `(code: ${WebSocketCode.VIOLATED_POLICY}, reason: ${closeReason})`,
    );

    await expect(mockServer.waitForPeerClosure()).resolves.toEqual({
      code: WebSocketCode.NORMAL,
    });
  });

  test('Connection error should be rethrown', async () => {
    const client = PoWebClient.initLocal();
    const originalError = new Error('Oops');

    const sessionPromise = Promise.all([
      asyncIterableToArray(client.collectParcels([nonceSigner])),
      mockServer.runActions(
        new AcceptConnectionAction(),
        new SendHandshakeChallengeAction(NONCE),
        new ReceiveMessageAction(),
        new EmitClientErrorAction(originalError),
      ),
    ]);

    const error = await getPromiseRejection(sessionPromise);
    expect(error).toBeInstanceOf(ServerError);
    expect(error.message).toStartWith('Connection error');
    expect((error as ServerError).cause()).toEqual(originalError);

    expect(mockServer.peerCloseFrame).toBeNull();
  });

  test('Malformed deliveries should be refused', async () => {
    const client = PoWebClient.initLocal();

    const sessionPromise = Promise.all([
      asyncIterableToArray(client.collectParcels([nonceSigner])),
      mockServer.runActions(
        new AcceptConnectionAction(),
        new SendHandshakeChallengeAction(NONCE),
        new ReceiveMessageAction(),
        new SendMessageAction(Buffer.from('this is not a valid parcel delivery')),
      ),
    ]);

    const error = await getPromiseRejection(sessionPromise);
    expect(error).toBeInstanceOf(ParcelDeliveryError);
    expect(error.message).toStartWith('Received malformed parcel delivery from the server');
    expect((error as ParcelDeliveryError).cause()).toBeTruthy();

    expect(mockServer.peerCloseFrame).toEqual<CloseFrame>({
      code: WebSocketCode.CANNOT_ACCEPT,
      reason: 'Malformed parcel delivery',
    });
  });

  test('Getting a 1005 close code should close the connection normally', async () => {
    const client = PoWebClient.initLocal();

    await Promise.all([
      asyncIterableToArray(
        client.collectParcels([nonceSigner], StreamingMode.CLOSE_UPON_COMPLETION),
      ),
      mockServer.runActions(
        new AcceptConnectionAction(),
        new SendHandshakeChallengeAction(NONCE),
        new ReceiveMessageAction(), // Handshake response
        new CloseConnectionAction(WebSocketCode.NO_STATUS),
      ),
    ]);

    await expect(mockServer.waitForPeerClosure()).resolves.toEqual<CloseFrame>({
      code: WebSocketCode.NORMAL,
    });
  });

  test('Breaking out of the iterable should close the connection normally', async () => {
    const client = PoWebClient.initLocal();

    const [parcelCollections] = await Promise.all([
      asyncIterableToArray(iterableTake(client.collectParcels([nonceSigner]), 1)),
      mockServer.runActions(
        new AcceptConnectionAction(),
        new SendHandshakeChallengeAction(NONCE),
        new ReceiveMessageAction(), // Handshake response
        new DeliverParcelAction(new ArrayBuffer(0), 'id1'),
        new DeliverParcelAction(new ArrayBuffer(0), 'id2'),
      ),
    ]);

    expect(parcelCollections).toHaveLength(1);

    await expect(mockServer.waitForPeerClosure()).resolves.toEqual<CloseFrame>({
      code: WebSocketCode.NORMAL,
    });
  });

  describe('Streaming mode', () => {
    test('Streaming mode should be Keep-Alive by default', async () => {
      const client = PoWebClient.initLocal();

      await Promise.all([
        asyncIterableToArray(client.collectParcels([nonceSigner])).catch(() => undefined),
        mockServer.runActions(new AcceptConnectionAction(), new CloseConnectionAction()),
      ]);

      expect(WebSocket).toBeCalledWith(
        expect.anything(),
        expect.objectContaining<ClientOptions>({
          headers: { 'X-Relaynet-Streaming-Mode': 'keep-alive' },
        }),
      );
    });

    test('Streaming mode can be changed on request', async () => {
      const client = PoWebClient.initLocal();

      await Promise.all([
        asyncIterableToArray(
          client.collectParcels([nonceSigner], StreamingMode.CLOSE_UPON_COMPLETION),
        ).catch(() => undefined),
        mockServer.runActions(new AcceptConnectionAction(), new CloseConnectionAction()),
      ]);

      expect(WebSocket).toBeCalledWith(
        expect.anything(),
        expect.objectContaining<ClientOptions>({
          headers: { 'X-Relaynet-Streaming-Mode': 'close-upon-completion' },
        }),
      );
    });
  });

  describe('Reconnections', () => {
    test('Connection should be recreated if it ended normally and Keep Alive is on', async () => {
      const mockServer1 = new MockServer();
      const parcel1Serialized = Buffer.from('parcel1');
      getMockInstance(WebSocket).mockImplementationOnce(() => {
        setImmediate(() => {
          mockServer1.runActions(
            new AcceptConnectionAction(),
            new SendHandshakeChallengeAction(NONCE),
            new ReceiveMessageAction(), // Handshake response
            new DeliverParcelAction(bufferToArray(parcel1Serialized), 'id1'),
            new CloseConnectionAction(WebSocketCode.NO_STATUS),
          );
        });
        return mockServer1.mockClientWebSocket;
      });
      const mockServer2 = new MockServer();
      const parcel2Serialized = Buffer.from('parcel2');
      getMockInstance(WebSocket).mockImplementationOnce(() => {
        setImmediate(() => {
          mockServer2.runActions(
            new AcceptConnectionAction(),
            new SendHandshakeChallengeAction(NONCE),
            new ReceiveMessageAction(), // Handshake response
            new DeliverParcelAction(bufferToArray(parcel2Serialized), 'id2'),
            new CloseConnectionAction(WebSocketCode.NO_STATUS),
          );
        });
        return mockServer2.mockClientWebSocket;
      });
      const client = PoWebClient.initLocal();

      const parcelCollections = await asyncIterableToArray(
        iterableTake(client.collectParcels([nonceSigner], StreamingMode.KEEP_ALIVE), 2),
      );

      expect(
        parcel1Serialized.equals(Buffer.from(parcelCollections[0].parcelSerialized)),
      ).toBeTrue();
      expect(
        parcel2Serialized.equals(Buffer.from(parcelCollections[1].parcelSerialized)),
      ).toBeTrue();
      await expect(mockServer1.wasConnectionClosed).toBeTrue();
      await expect(mockServer2.wasConnectionClosed).toBeTrue();
    });

    test.each([StreamingMode.CLOSE_UPON_COMPLETION, StreamingMode.KEEP_ALIVE])(
      'Connection should not be recreated if it ended normally and streaming mode is %s',
      async (mode) => {
        const client = PoWebClient.initLocal();

        await expect(
          Promise.all([
            asyncIterableToArray(iterableTake(client.collectParcels([nonceSigner], mode), 1)),
            mockServer.runActions(
              new AcceptConnectionAction(),
              new SendHandshakeChallengeAction(NONCE),
              new ReceiveMessageAction(), // Handshake response
              new CloseConnectionAction(WebSocketCode.VIOLATED_POLICY),
            ),
          ]),
        ).rejects.toBeInstanceOf(ServerError);

        expect(WebSocket).toBeCalledTimes(1);
        await expect(mockServer.wasConnectionClosed).toBeTrue();
      },
    );
  });

  describe('Collection', () => {
    test("No collection should be output if the server doesn't deliver anything", async () => {
      const client = PoWebClient.initLocal();

      const [parcelCollections] = await Promise.all([
        asyncIterableToArray(
          client.collectParcels([nonceSigner], StreamingMode.CLOSE_UPON_COMPLETION),
        ),
        mockServer.runActions(
          new AcceptConnectionAction(),
          new SendHandshakeChallengeAction(NONCE),
          new ReceiveMessageAction(), // Handshake response
          new CloseConnectionAction(),
        ),
      ]);

      await expect(parcelCollections).toHaveLength(0);
    });

    test('One collection should be output if there is one delivery', async () => {
      const client = PoWebClient.initLocal();

      const [parcelCollections] = await Promise.all([
        asyncIterableToArray(
          client.collectParcels([nonceSigner], StreamingMode.CLOSE_UPON_COMPLETION),
        ),
        mockServer.runActions(
          new AcceptConnectionAction(),
          new SendHandshakeChallengeAction(NONCE),
          new ReceiveMessageAction(), // Handshake response
          new DeliverParcelAction(new ArrayBuffer(0), 'id1'),
          new CloseConnectionAction(),
        ),
      ]);

      expect(parcelCollections).toHaveLength(1);
      expect(parcelCollections[0]).toBeInstanceOf(ParcelCollection);
    });

    test('Multiple collections should be output if there are multiple deliveries', async () => {
      const client = PoWebClient.initLocal();

      const [parcelCollections] = await Promise.all([
        asyncIterableToArray(
          client.collectParcels([nonceSigner], StreamingMode.CLOSE_UPON_COMPLETION),
        ),
        mockServer.runActions(
          new AcceptConnectionAction(),
          new SendHandshakeChallengeAction(NONCE),
          new ReceiveMessageAction(), // Handshake response
          new DeliverParcelAction(new ArrayBuffer(0), 'id1'),
          new DeliverParcelAction(new ArrayBuffer(0), 'id2'),
          new CloseConnectionAction(),
        ),
      ]);

      expect(parcelCollections).toHaveLength(2);
    });

    test('Parcel serialization should be encapsulated', async () => {
      const client = PoWebClient.initLocal();
      const parcelSerialized = bufferToArray(Buffer.from('I am a parcel :wink: :wink:'));

      const [parcelCollections] = await Promise.all([
        asyncIterableToArray(
          client.collectParcels([nonceSigner], StreamingMode.CLOSE_UPON_COMPLETION),
        ),
        mockServer.runActions(
          new AcceptConnectionAction(),
          new SendHandshakeChallengeAction(NONCE),
          new ReceiveMessageAction(), // Handshake response
          new DeliverParcelAction(parcelSerialized, 'id1'),
          new CloseConnectionAction(),
        ),
      ]);

      expectArrayBuffersToEqual(parcelSerialized, parcelCollections[0].parcelSerialized);
    });

    test('Nonce signer should be set as the trusted certificates', async () => {
      const client = PoWebClient.initLocal();
      const nonceSigner2KeyPair = await generateRSAKeyPair();
      const nonceSigner2Certificate = await issueEndpointCertificate({
        issuerCertificate: certificationPath.privateGateway,
        issuerPrivateKey: nodeKeyPairs.privateGateway.privateKey,
        subjectPublicKey: nonceSigner2KeyPair.publicKey,
        validityEndDate: certificationPath.privateGateway.expiryDate,
      });
      const nonceSigner2 = new Signer(nonceSigner2Certificate, nonceSigner2KeyPair.privateKey);

      const [parcelCollections] = await Promise.all([
        asyncIterableToArray(
          client.collectParcels([nonceSigner, nonceSigner2], StreamingMode.CLOSE_UPON_COMPLETION),
        ),
        mockServer.runActions(
          new AcceptConnectionAction(),
          new SendHandshakeChallengeAction(NONCE),
          new ReceiveMessageAction(), // Handshake response
          new DeliverParcelAction(new ArrayBuffer(0), 'id1'),
          new CloseConnectionAction(),
        ),
      ]);

      const trustedCertificates = parcelCollections[0].trustedCertificates;
      expect(trustedCertificates).toHaveLength(2);
      expect(trustedCertificates[0].isEqual(nonceSigner.certificate)).toBeTrue();
      expect(trustedCertificates[1].isEqual(nonceSigner2.certificate)).toBeTrue();
    });

    test('Acknowledging the collection should send an ACK to the server', async () => {
      const client = PoWebClient.initLocal();
      const ackReceiver = new ReceiveMessageAction();
      const deliveryId = 'id1';

      await Promise.all([
        pipe(
          client.collectParcels([nonceSigner], StreamingMode.CLOSE_UPON_COMPLETION),
          async (collections): Promise<void> => {
            for await (const collection of collections) {
              await collection.ack();
            }
          },
        ),
        mockServer.runActions(
          new AcceptConnectionAction(),
          new SendHandshakeChallengeAction(NONCE),
          new ReceiveMessageAction(), // Handshake response
          new DeliverParcelAction(new ArrayBuffer(0), deliveryId),
          ackReceiver,
          new CloseConnectionAction(),
        ),
      ]);

      expect(ackReceiver.wasRun).toBeTrue();
      expect(ackReceiver.message).toEqual(deliveryId);
    });
  });

  describe('Pings', () => {
    test.todo('Connection should be terminated if first ping is not received within 7s', async () => {

    });

    test.todo('Connection should be terminated if a subsequent ping is not received within 7s');

    test.todo('Connection should be kept open if pings are received every < 7 seconds');
  });
});

async function getRejection(promise: Promise<any>): Promise<Error> {
  try {
    await promise;
  } catch (error) {
    return error;
  }
  throw new Error('Expected promise to reject');
}

class SendHandshakeChallengeAction extends SendMessageAction {
  constructor(nonce: ArrayBuffer) {
    const challenge = new HandshakeChallenge(nonce);
    super(challenge.serialize());
  }
}

class DeliverParcelAction extends SendMessageAction {
  constructor(parcelSerialized: ArrayBuffer, deliveryId: string) {
    super(new ParcelDelivery(deliveryId, parcelSerialized).serialize());
  }
}
