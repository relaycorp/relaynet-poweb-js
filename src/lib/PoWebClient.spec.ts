// tslint:disable:max-classes-per-file

import {
  derSerializePublicKey,
  generateRSAKeyPair,
  HandshakeChallenge,
  HandshakeResponse,
  issueEndpointCertificate,
  MAX_RAMF_MESSAGE_LENGTH,
  ParcelCollection,
  ParcelCollectionHandshakeSigner,
  ParcelCollectionHandshakeVerifier,
  ParcelDelivery,
  ParcelDeliverySigner,
  ParcelDeliveryVerifier,
  PrivateNodeRegistration,
  StreamingMode,
} from '@relaycorp/relaynet-core';
import {
  generateIdentityKeyPairSet,
  generatePDACertificationPath,
  NodeKeyPairSet,
  PDACertPath,
} from '@relaycorp/relaynet-testing';
import { CloseFrame, createMockWebSocketStream, MockServer } from '@relaycorp/ws-mock';
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
  ConnectionTimeoutError,
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
  WEBSOCKET_PING_TIMEOUT_MS,
} from './PoWebClient';

let nodeKeyPairs: NodeKeyPairSet;
let certificationPath: PDACertPath;
beforeAll(async () => {
  nodeKeyPairs = await generateIdentityKeyPairSet();
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
      certificationPath.internetGateway,
      'braavos.relaycorp.cloud',
    );
    expectedRegistrationSerialized = Buffer.from(await expectedRegistration.serialize());
  });

  test('PNRA should be POSTed to /v1/nodes', async () => {
    mockAxios
      .onPost('/nodes')
      .reply(200, expectedRegistrationSerialized, { 'content-type': PNR_CONTENT_TYPE });

    await client.registerNode(pnraSerialized);

    expect(mockAxios.history.post).toHaveLength(1);
    expect(mockAxios.history.post[0].url).toEqual('/nodes');
    expect(mockAxios.history.post[0].headers).toHaveProperty('Content-Type', PNRR_CONTENT_TYPE);
    expect(Buffer.from(mockAxios.history.post[0].data)).toEqual(Buffer.from(pnraSerialized));
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
  let signer: ParcelDeliverySigner;
  let verifier: ParcelDeliveryVerifier;
  beforeAll(async () => {
    signer = new ParcelDeliverySigner(
      certificationPath.privateGateway,
      nodeKeyPairs.privateGateway.privateKey,
    );
    verifier = new ParcelDeliveryVerifier([certificationPath.internetGateway]);
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

    const authorizationHeaderValue = mockAxios.history.post[0].headers!.authorization as string;
    expect(authorizationHeaderValue).toBeDefined();
    expect(authorizationHeaderValue).toStartWith('Relaynet-Countersignature ');
    const [, countersignatureBase64] = authorizationHeaderValue.split(' ', 2);
    const countersignature = Buffer.from(countersignatureBase64, 'base64');
    await verifier.verify(bufferToArray(countersignature), parcelSerialized);
  });

  test('HTTP 20X should be regarded a successful delivery', async () => {
    mockAxios.onPost('/parcels').reply(200, null);
    await client.deliverParcel(parcelSerialized, signer);

    mockAxios.onPost('/parcels').reply(299, null);
    await client.deliverParcel(parcelSerialized, signer);
  });

  test('HTTP 422 should throw a RefusedParcelError', async () => {
    mockAxios.onPost('/parcels').reply(422, null);

    await expect(client.deliverParcel(parcelSerialized, signer)).rejects.toThrowWithMessage(
      RefusedParcelError,
      'Parcel was rejected',
    );
  });

  test('RefusedParcelError should include rejection reason if available', async () => {
    const message = 'Not enough postage';
    mockAxios.onPost('/parcels').reply(422, { message });

    await expect(client.deliverParcel(parcelSerialized, signer)).rejects.toThrowWithMessage(
      RefusedParcelError,
      `Parcel was rejected: ${message}`,
    );
  });

  test('HTTP 50X should throw a ServerError', async () => {
    mockAxios.onPost('/parcels').reply(500, null);

    await expect(client.deliverParcel(parcelSerialized, signer)).rejects.toThrowWithMessage(
      ServerError,
      'Server was unable to get parcel (HTTP 500)',
    );
  });

  test('HTTP responses other than 20X/422/50X should throw errors', async () => {
    mockAxios.onPost('/parcels').reply(400, null);

    await expect(client.deliverParcel(parcelSerialized, signer)).rejects.toThrowWithMessage(
      ParcelDeliveryError,
      'Could not deliver parcel (HTTP 400)',
    );
  });

  test('Other client exceptions should be propagated', async () => {
    mockAxios.onPost('/parcels').networkError();

    const error = await getPromiseRejection(client.deliverParcel(parcelSerialized, signer));

    expect(error).toHaveProperty('isAxiosError', true);
  });
});

describe('collectParcels', () => {
  const ENDPOINT_URL = new URL('ws://127.0.0.1:276/v1/parcel-collection');

  const NONCE = bufferToArray(Buffer.from('the-nonce'));

  let signer: ParcelCollectionHandshakeSigner;
  beforeAll(async () => {
    signer = new ParcelCollectionHandshakeSigner(
      certificationPath.privateEndpoint,
      nodeKeyPairs.privateEndpoint.privateKey,
    );
  });

  let mockServer: ParcelCollectionMockServer;
  beforeEach(() => {
    getMockInstance(WebSocket).mockReset();
    mockServer = makeMockServer();
  });

  test('Maximum incoming payload size should be enough for large parcels', async () => {
    const client = PoWebClient.initLocal();

    await mockServer.use(
      asyncIterableToArray(client.collectParcels([signer])).catch(() => undefined),
    );

    expect(WebSocket).toBeCalledWith(
      expect.anything(),
      expect.objectContaining({ maxPayload: MAX_RAMF_MESSAGE_LENGTH }),
    );
  });

  test('Request should be made to the parcel collection endpoint', async () => {
    const client = PoWebClient.initLocal();

    await mockServer.use(
      asyncIterableToArray(client.collectParcels([signer])).catch(() => undefined),
    );

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

      const error = await getPromiseRejection(
        mockServer.use(asyncIterableToArray(client.collectParcels([signer]))),
      );

      expect(error).toBeInstanceOf(InvalidHandshakeChallengeError);
      expect(error.message).toEqual('Server closed the connection before/during the handshake');
    });

    test('Server closing connection during handshake should throw error', async () => {
      const client = PoWebClient.initLocal();

      const error = await getPromiseRejection(
        mockServer.use(asyncIterableToArray(client.collectParcels([signer]))),
      );

      expect(error).toBeInstanceOf(InvalidHandshakeChallengeError);
      expect(error.message).toEqual('Server closed the connection before/during the handshake');
    });

    test('Connection error during handshake should be rethrown', async () => {
      const client = PoWebClient.initLocal();
      const originalError = new Error('Something went wrong');

      const error = await getPromiseRejection(
        mockServer.use(asyncIterableToArray(client.collectParcels([signer])), async () => {
          mockServer.abort(originalError);
        }),
      );

      expect(error).toBeInstanceOf(ServerError);
      expect(error.message).toStartWith('Got connection error before/during the handshake:');
      expect((error as ServerError).cause()).toEqual(originalError);

      expect(mockServer.peerCloseFrame).toBeNull();
    });

    test('Getting a malformed challenge should throw an error', async () => {
      const client = PoWebClient.initLocal();

      const error = await getPromiseRejection(
        mockServer.use(asyncIterableToArray(client.collectParcels([signer])), async () => {
          await mockServer.send('malformed');
          await mockServer.waitForPeerClosure();
        }),
      );

      expect(error).toBeInstanceOf(InvalidHandshakeChallengeError);
      expect(error.message).toStartWith('Server sent a malformed handshake challenge:');
      expect((error as InvalidHandshakeChallengeError).cause()).toBeTruthy();

      expect(mockServer.didPeerCloseConnection).toBeTrue();
      expect(mockServer.peerCloseFrame?.code).toEqual(WebSocketCode.CANNOT_ACCEPT);
      expect(mockServer.peerCloseFrame?.reason).toEqual('Malformed handshake challenge');
    });

    test('Challenge nonce should be signed with each signer', async () => {
      const client = PoWebClient.initLocal();

      await mockServer.use(
        asyncIterableToArray(client.collectParcels([signer], StreamingMode.CLOSE_UPON_COMPLETION)),
        async () => {
          const challenge = new HandshakeChallenge(NONCE);
          await mockServer.send(challenge.serialize());

          const responseRaw = await mockServer.receive();
          const response = HandshakeResponse.deserialize(bufferToArray(responseRaw as Buffer));
          expect(response.nonceSignatures).toHaveLength(1);

          const verifier = new ParcelCollectionHandshakeVerifier([
            certificationPath.privateGateway,
          ]);
          await verifier.verify(response.nonceSignatures[0], NONCE);
        },
      );
    });

    describe('Handshake completion callback', () => {
      test('Callback should not be called if handshake fails', async () => {
        const client = PoWebClient.initLocal();
        const handshakeCallback = jest.fn();

        await expect(
          mockServer.use(
            asyncIterableToArray(
              client.collectParcels([signer], StreamingMode.KEEP_ALIVE, handshakeCallback),
            ),
          ),
        ).toReject();

        expect(handshakeCallback).not.toBeCalled();
      });

      test('Callback should be called after handshake but before the first parcel', async () => {
        const client = PoWebClient.initLocal();
        const handshakeCallback = jest.fn();

        await mockServer.useWithHandshake(
          asyncIterableToArray(
            client.collectParcels([signer], StreamingMode.CLOSE_UPON_COMPLETION, handshakeCallback),
          ),
        );

        await expect(handshakeCallback).toBeCalledWith();
      });
    });
  });

  test('Call should return if server closed connection normally after the handshake', async () => {
    const client = PoWebClient.initLocal();

    const parcelCollections = await mockServer.useWithHandshake(
      asyncIterableToArray(client.collectParcels([signer], StreamingMode.CLOSE_UPON_COMPLETION)),
    );

    expect(parcelCollections).toHaveLength(0);
  });

  test('Call should return if server closed connection without status', async () => {
    const client = PoWebClient.initLocal();

    await mockServer.useWithHandshake(
      asyncIterableToArray(client.collectParcels([signer], StreamingMode.CLOSE_UPON_COMPLETION)),
      async () => {
        mockServer.close();
      },
    );
  });

  test('Error should be thrown if server closes connection with error code', async () => {
    const client = PoWebClient.initLocal();
    const closeReason = 'Just because';

    const error = await getPromiseRejection(
      mockServer.useWithHandshake(
        asyncIterableToArray(client.collectParcels([signer])),
        async () => {
          mockServer.close(WebSocketCode.VIOLATED_POLICY, Buffer.from(closeReason));
        },
      ),
    );

    expect(error).toBeInstanceOf(ServerError);
    expect(error.message).toEqual(
      'Server closed connection unexpectedly ' +
        `(code: ${WebSocketCode.VIOLATED_POLICY}, reason: ${closeReason})`,
    );
  });

  test('Connection error should be rethrown', async () => {
    const client = PoWebClient.initLocal();
    const originalError = new Error('Oops');

    const error = await getPromiseRejection(
      mockServer.useWithHandshake(
        asyncIterableToArray(client.collectParcels([signer])),
        async () => {
          mockServer.abort(originalError);
        },
      ),
    );

    expect(error).toBeInstanceOf(ServerError);
    expect(error.message).toStartWith('Connection error');
    expect((error as ServerError).cause()).toEqual(originalError);

    expect(mockServer.peerCloseFrame).toBeNull();
  });

  test('Malformed deliveries should be refused', async () => {
    const client = PoWebClient.initLocal();

    const error = await getPromiseRejection(
      mockServer.useWithHandshake(
        asyncIterableToArray(client.collectParcels([signer])),
        async () => {
          await mockServer.send(Buffer.from('this is not a valid parcel delivery'));
          await mockServer.waitForPeerClosure();
        },
      ),
    );

    expect(error).toBeInstanceOf(ParcelDeliveryError);
    expect(error.message).toStartWith('Received malformed parcel delivery from the server');
    expect((error as ParcelDeliveryError).cause()).toBeTruthy();

    expect(mockServer.peerCloseFrame).toEqual<CloseFrame>({
      code: WebSocketCode.CANNOT_ACCEPT,
      reason: 'Malformed parcel delivery',
    });
  });

  test('Breaking out of the iterable should close the connection normally', async () => {
    const client = PoWebClient.initLocal();

    const parcelCollections = await mockServer.useWithHandshake(
      asyncIterableToArray(iterableTake(client.collectParcels([signer]), 1)),
      async () => {
        await mockServer.sendParcelDelivery(new ArrayBuffer(0), 'id1');
        await mockServer.sendParcelDelivery(new ArrayBuffer(0), 'id2');
        await mockServer.waitForPeerClosure();
      },
    );

    expect(parcelCollections).toHaveLength(1);

    expect(mockServer.peerCloseFrame).toEqual<CloseFrame>({
      code: WebSocketCode.NORMAL,
    });
  });

  describe('Streaming mode', () => {
    test('Streaming mode should be Keep-Alive by default', async () => {
      const client = PoWebClient.initLocal();

      await mockServer.useWithHandshake(
        asyncIterableToArray(client.collectParcels([signer])).catch(() => undefined),
      );

      expect(WebSocket).toBeCalledWith(
        expect.anything(),
        expect.objectContaining<ClientOptions>({
          headers: { 'X-Relaynet-Streaming-Mode': 'keep-alive' },
        }),
      );
    });

    test('Streaming mode can be changed on request', async () => {
      const client = PoWebClient.initLocal();

      await mockServer.useWithHandshake(
        asyncIterableToArray(
          client.collectParcels([signer], StreamingMode.CLOSE_UPON_COMPLETION),
        ).catch(() => undefined),
      );

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
      const mockServer2 = makeMockServer();
      const parcel1Serialized = Buffer.from('parcel1');
      const parcel2Serialized = Buffer.from('parcel2');
      const client = PoWebClient.initLocal();

      const [parcelCollections] = await Promise.all([
        asyncIterableToArray(
          iterableTake(client.collectParcels([signer], StreamingMode.KEEP_ALIVE), 2),
        ),
        (async () => {
          await mockServer.useWithHandshake(new Promise(setImmediate), async () => {
            await mockServer.sendParcelDelivery(bufferToArray(parcel1Serialized), 'id1');
          });

          await mockServer2.useWithHandshake(Promise.resolve(), async () => {
            await mockServer2.sendParcelDelivery(bufferToArray(parcel2Serialized), 'id2');
            await mockServer2.waitForPeerClosure();
          });
        })(),
      ]);

      expect(
        parcel1Serialized.equals(Buffer.from(parcelCollections[0].parcelSerialized)),
      ).toBeTrue();
      expect(
        parcel2Serialized.equals(Buffer.from(parcelCollections[1].parcelSerialized)),
      ).toBeTrue();
      await expect(mockServer.didPeerCloseConnection).toBeTrue();
      await expect(mockServer2.didPeerCloseConnection).toBeTrue();
    });

    test.each([StreamingMode.CLOSE_UPON_COMPLETION, StreamingMode.KEEP_ALIVE])(
      'Connection should not be recreated if it ended normally and streaming mode is %s',
      async (mode) => {
        const client = PoWebClient.initLocal();

        await expect(
          mockServer.useWithHandshake(
            asyncIterableToArray(iterableTake(client.collectParcels([signer], mode), 1)),
            async () => {
              mockServer.close(WebSocketCode.VIOLATED_POLICY);
            },
          ),
        ).rejects.toBeInstanceOf(ServerError);

        expect(WebSocket).toBeCalledTimes(1);
        await expect(mockServer.didPeerCloseConnection).toBeTrue();
      },
    );
  });

  describe('Collection', () => {
    test("No collection should be output if the server doesn't deliver anything", async () => {
      const client = PoWebClient.initLocal();

      const parcelCollections = await mockServer.useWithHandshake(
        asyncIterableToArray(client.collectParcels([signer], StreamingMode.CLOSE_UPON_COMPLETION)),
      );

      await expect(parcelCollections).toHaveLength(0);
    });

    test('One collection should be output if there is one delivery', async () => {
      const client = PoWebClient.initLocal();

      const parcelCollections = await mockServer.useWithHandshake(
        asyncIterableToArray(client.collectParcels([signer], StreamingMode.CLOSE_UPON_COMPLETION)),
        async () => {
          await mockServer.sendParcelDelivery(new ArrayBuffer(0), 'id1');
        },
      );

      expect(parcelCollections).toHaveLength(1);
      expect(parcelCollections[0]).toBeInstanceOf(ParcelCollection);
    });

    test('Multiple collections should be output if there are multiple deliveries', async () => {
      const client = PoWebClient.initLocal();

      const parcelCollections = await mockServer.useWithHandshake(
        asyncIterableToArray(client.collectParcels([signer], StreamingMode.CLOSE_UPON_COMPLETION)),
        async () => {
          await mockServer.sendParcelDelivery(new ArrayBuffer(0), 'id1');
          await mockServer.sendParcelDelivery(new ArrayBuffer(0), 'id2');
        },
      );

      expect(parcelCollections).toHaveLength(2);
    });

    test('Parcel serialization should be encapsulated', async () => {
      const client = PoWebClient.initLocal();
      const parcelSerialized = bufferToArray(Buffer.from('I am a parcel :wink: :wink:'));

      const parcelCollections = await mockServer.useWithHandshake(
        asyncIterableToArray(client.collectParcels([signer], StreamingMode.CLOSE_UPON_COMPLETION)),
        async () => {
          await mockServer.sendParcelDelivery(parcelSerialized, 'id1');
        },
      );

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
      const nonceSigner2 = new ParcelCollectionHandshakeSigner(
        nonceSigner2Certificate,
        nonceSigner2KeyPair.privateKey,
      );

      const parcelCollections = await mockServer.useWithHandshake(
        asyncIterableToArray(
          client.collectParcels([signer, nonceSigner2], StreamingMode.CLOSE_UPON_COMPLETION),
        ),
        async () => {
          await mockServer.sendParcelDelivery(new ArrayBuffer(0), 'id1');
        },
      );

      const trustedCertificates = parcelCollections[0].trustedCertificates;
      expect(trustedCertificates).toHaveLength(2);
      expect(trustedCertificates[0].isEqual(signer.certificate)).toBeTrue();
      expect(trustedCertificates[1].isEqual(nonceSigner2.certificate)).toBeTrue();
    });

    test('Acknowledging the collection should send an ACK to the server', async () => {
      const client = PoWebClient.initLocal();
      const deliveryId = 'id1';

      await mockServer.useWithHandshake(
        pipe(
          client.collectParcels([signer], StreamingMode.CLOSE_UPON_COMPLETION),
          async (collections): Promise<void> => {
            for await (const collection of collections) {
              await collection.ack();
            }
          },
        ),
        async () => {
          await mockServer.sendParcelDelivery(new ArrayBuffer(0), deliveryId);

          const message = await mockServer.receive();
          expect(message).toEqual(deliveryId);
        },
      );
    });
  });

  describe('Pings', () => {
    beforeEach(() => {
      jest.useFakeTimers('legacy');
    });
    afterEach(() => {
      jest.useRealTimers();
    });

    test('Connection should be terminated if a subsequent ping is not received within 7s', async () => {
      const client = PoWebClient.initLocal();

      const error = await getPromiseRejection(
        mockServer.useWithHandshake(
          asyncIterableToArray(
            client.collectParcels([signer], StreamingMode.CLOSE_UPON_COMPLETION),
          ),
          async () => {
            jest.advanceTimersByTime(WEBSOCKET_PING_TIMEOUT_MS - 100);

            mockServer.ping();
            jest.advanceTimersByTime(WEBSOCKET_PING_TIMEOUT_MS + 1);
          },
        ),
      );

      expect(mockServer.client.wasTerminated).toBeTrue();

      expect(error).toBeInstanceOf(ServerError);
      expect(error.message).toMatch(/^Connection error:/);
      expect((error as ServerError).cause()?.message).toEqual('Ping timeout');
    });

    test('Connection should be kept open if pings are received every < 7 seconds', async () => {
      const client = PoWebClient.initLocal();

      await mockServer.useWithHandshake(
        asyncIterableToArray(client.collectParcels([signer], StreamingMode.CLOSE_UPON_COMPLETION)),
        async () => {
          jest.advanceTimersByTime(WEBSOCKET_PING_TIMEOUT_MS - 100);
          mockServer.ping();

          jest.advanceTimersByTime(WEBSOCKET_PING_TIMEOUT_MS - 100);
          mockServer.ping();

          jest.advanceTimersByTime(WEBSOCKET_PING_TIMEOUT_MS - 100);
          mockServer.ping();
        },
      );

      expect(mockServer.client.wasTerminated).toBeFalse();
    });

    describe('Before handshake completes', () => {
      test('Error should be thrown if ping not received on time and connection is not Keep Alive', async () => {
        const client = PoWebClient.initLocal();

        const error = await getPromiseRejection(
          mockServer.use(
            asyncIterableToArray(
              client.collectParcels([signer], StreamingMode.CLOSE_UPON_COMPLETION),
            ),
            async () => {
              jest.advanceTimersByTime(WEBSOCKET_PING_TIMEOUT_MS + 100);

              expect(mockServer.client.wasTerminated).toBeTrue();
            },
          ),
        );

        expect(error).toBeInstanceOf(ConnectionTimeoutError);
        expect(error.message).toEqual('Lost connection before completing handshake');
      });

      test('Reconnection should be attempted if ping not received on time and connection is Keep Alive', async () => {
        const mockServer2 = makeMockServer();
        const parcelSerialized = Buffer.from('parcel1');
        const client = PoWebClient.initLocal();

        await Promise.all([
          asyncIterableToArray(
            iterableTake(client.collectParcels([signer], StreamingMode.KEEP_ALIVE), 1),
          ),
          (async () => {
            // First session won't get past the handshake:
            await mockServer.use(new Promise(setImmediate), async () => {
              jest.advanceTimersByTime(WEBSOCKET_PING_TIMEOUT_MS + 100);

              expect(mockServer.client.wasTerminated);
            });

            await mockServer2.useWithHandshake(Promise.resolve(), async () => {
              await mockServer2.sendParcelDelivery(bufferToArray(parcelSerialized), 'id');
              await mockServer2.waitForPeerClosure();
            });
          })(),
        ]);
      });
    });

    describe('After handshake', () => {
      test('Error should be thrown if ping not received on time and connection is not Keep Alive', async () => {
        const client = PoWebClient.initLocal();

        const error = await getPromiseRejection(
          mockServer.useWithHandshake(
            asyncIterableToArray(
              client.collectParcels([signer], StreamingMode.CLOSE_UPON_COMPLETION),
            ),
            async () => {
              jest.advanceTimersByTime(WEBSOCKET_PING_TIMEOUT_MS + 100);

              expect(mockServer.client.wasTerminated).toBeTrue();
            },
          ),
        );

        expect(error).toBeInstanceOf(ServerError);
        expect(error.message).toMatch(/^Connection error:/);
        expect((error as ServerError).cause()).toBeInstanceOf(ConnectionTimeoutError);
        expect((error as ServerError).cause()?.message).toEqual('Ping timeout');
      });

      test('Reconnection should be attempted if ping not received on time and connection is Keep Alive', async () => {
        const mockServer2 = makeMockServer();
        const parcelSerialized = Buffer.from('parcel1');
        const client = PoWebClient.initLocal();

        await Promise.all([
          asyncIterableToArray(
            iterableTake(client.collectParcels([signer], StreamingMode.KEEP_ALIVE), 1),
          ),
          (async () => {
            await mockServer.useWithHandshake(new Promise(setImmediate), async () => {
              jest.advanceTimersByTime(WEBSOCKET_PING_TIMEOUT_MS + 100);

              expect(mockServer.client.wasTerminated);
            });

            await mockServer2.useWithHandshake(Promise.resolve(), async () => {
              await mockServer2.sendParcelDelivery(bufferToArray(parcelSerialized), 'id');
              await mockServer2.waitForPeerClosure();
            });
          })(),
        ]);
      });
    });
  });

  function makeMockServer(): ParcelCollectionMockServer {
    const server = new ParcelCollectionMockServer();
    getMockInstance(WebSocket).mockImplementationOnce(() => server.client);
    return server;
  }

  class ParcelCollectionMockServer extends MockServer {
    public async useWithHandshake<T>(
      clientPromise: Promise<T>,
      serverImplementation?: () => Promise<void>,
    ): Promise<T> {
      return super.use(clientPromise, async () => {
        const challenge = new HandshakeChallenge(NONCE);
        await this.send(challenge.serialize());

        // Discard handshake response
        const responseRaw = await this.receive();
        HandshakeResponse.deserialize(bufferToArray(responseRaw as Buffer));

        await serverImplementation?.();
      });
    }

    public async sendParcelDelivery(
      parcelSerialized: ArrayBuffer,
      deliveryId: string,
    ): Promise<void> {
      const delivery = new ParcelDelivery(deliveryId, parcelSerialized);
      await this.send(delivery.serialize());
    }
  }
});
