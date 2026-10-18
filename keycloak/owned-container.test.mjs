import assert from 'node:assert/strict';
import test from 'node:test';
import {
  createOwnedContainer, removeOwnedContainer, UnconfirmedContainerOwnershipError,
} from './owned-container.mjs';

const ID = 'a'.repeat(64);
const NONCE = 'synthetic-current-run-nonce';

test('name collision never permits cleanup by name or an unknown ID', () => {
  const calls = [];
  const docker = (args) => {
    calls.push(args);
    throw new Error('Docker name is already in use by another container');
  };
  let id;
  assert.throws(() => {
    id = createOwnedContainer(docker, {
      name: 'occupied-fixture-name', nonce: NONCE, args: ['fixture-image'],
    });
  }, /already in use/);
  assert.equal(removeOwnedContainer(docker, id, NONCE), false);
  assert.deepEqual(calls.map((args) => args[0]), ['create']);
});

test('successful creation and cleanup verify ownership and remove only the exact ID', () => {
  const calls = [];
  const docker = (args) => {
    calls.push(args);
    if (args[0] === 'create') return ID;
    if (args[0] === 'inspect') return `${ID} ${NONCE}`;
    if (args[0] === 'rm') return ID;
    throw new Error('Unexpected Docker command');
  };
  const id = createOwnedContainer(docker, {
    name: 'owned-fixture-name', nonce: NONCE, args: ['fixture-image'],
  });
  assert.equal(removeOwnedContainer(docker, id, NONCE), true);
  assert.deepEqual(calls.map((args) => args[0]), ['create', 'inspect', 'inspect', 'rm']);
  assert.deepEqual(calls.at(-1), ['rm', '--force', ID]);
});

test('a mismatched ownership nonce prevents removal even with a valid ID', () => {
  const calls = [];
  const docker = (args) => {
    calls.push(args);
    return `${ID} synthetic-different-owner`;
  };
  assert.throws(() => removeOwnedContainer(docker, ID, NONCE), /ownership could not be confirmed/);
  assert.deepEqual(calls.map((args) => args[0]), ['inspect']);
});

test('container names and truncated IDs are never valid removal targets', () => {
  const docker = () => assert.fail('Docker must not be called for an invalid ID');
  assert.throws(() => removeOwnedContainer(docker, 'occupied-fixture-name', NONCE), /full container ID/);
  assert.throws(() => removeOwnedContainer(docker, ID.slice(0, 12), NONCE), /full container ID/);
});

test('unverifiable creation does not return an adoptable container ID', () => {
  const calls = [];
  const docker = (args) => {
    calls.push(args);
    return args[0] === 'create' ? ID : `${ID} synthetic-different-owner`;
  };
  let id;
  assert.throws(() => {
    id = createOwnedContainer(docker, {
      name: 'unverified-fixture-name', nonce: NONCE, args: ['fixture-image'],
    });
  }, /ownership could not be confirmed/);
  assert.equal(removeOwnedContainer(docker, id, NONCE), false);
  assert.deepEqual(calls.map((args) => args[0]), ['create', 'inspect']);
});

test('inspect failure preserves and surfaces the created full ID and nonce without removal', () => {
  const calls = [];
  const inspectFailure = new Error('Synthetic Docker inspection failure');
  const docker = (args) => {
    calls.push(args);
    if (args[0] === 'create') return ID;
    if (args[0] === 'inspect') throw inspectFailure;
    assert.fail('Unconfirmed containers must not be removed');
  };
  let id;
  assert.throws(() => {
    id = createOwnedContainer(docker, {
      name: 'created-but-unconfirmed-fixture', nonce: NONCE, args: ['fixture-image'],
    });
  }, (error) => {
    assert(error instanceof UnconfirmedContainerOwnershipError);
    assert.equal(error.containerId, ID);
    assert.equal(error.ownershipNonce, NONCE);
    assert.equal(error.ownershipLabel, 'shoten.identity-lab.owner');
    assert.equal(error.cause, inspectFailure);
    const surfacedFirstLine = error.message.split('\n')[0];
    assert(surfacedFirstLine.includes(`ID=${ID}`));
    assert(surfacedFirstLine.includes(`shoten.identity-lab.owner=${NONCE}`));
    assert(surfacedFirstLine.includes('No automatic removal was performed'));
    return true;
  });
  assert.equal(removeOwnedContainer(docker, id, NONCE), false);
  assert.deepEqual(calls.map((args) => args[0]), ['create', 'inspect']);
});
