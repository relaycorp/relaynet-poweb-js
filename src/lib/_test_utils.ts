export async function getPromiseRejection(promise: Promise<any>): Promise<Error> {
  try {
    await promise;
  } catch (error) {
    return error as Error;
  }
  throw new Error('Expected promise to throw');
}

export async function asyncIterableToArray<T>(iterable: AsyncIterable<T>): Promise<readonly T[]> {
  // tslint:disable-next-line:readonly-array
  const values = [];
  for await (const item of iterable) {
    values.push(item);
  }
  return values;
}

export async function* iterableTake<T>(iterable: AsyncIterable<T>, max: number): AsyncIterable<T> {
  if (max <= 0) {
    return;
  }

  let count = 0;
  for await (const item of iterable) {
    yield item;
    count++;
    if (max === count) {
      break;
    }
  }
}

export function expectArrayBuffersToEqual(
  expectedArrayBuffer: ArrayBuffer,
  actualArrayBuffer: ArrayBuffer,
): void {
  expect(expectedArrayBuffer).toBeInstanceOf(ArrayBuffer);
  expect(actualArrayBuffer).toBeInstanceOf(ArrayBuffer);

  const expectedBuffer = Buffer.from(expectedArrayBuffer);
  const actualBuffer = Buffer.from(actualArrayBuffer);
  expect(expectedBuffer.equals(actualBuffer)).toBeTrue();
}

export function getMockInstance(mockedObject: any): jest.MockInstance<any, any> {
  return mockedObject as unknown as jest.MockInstance<any, any>;
}
