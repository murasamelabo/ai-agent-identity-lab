import assert from 'node:assert/strict';

const OWNER_LABEL = 'shoten.identity-lab.owner';

export class UnconfirmedContainerOwnershipError extends Error {
  constructor(containerId, ownershipNonce, cause) {
    super(
      `Created container ownership could not be confirmed: ID=${containerId}; expected ${OWNER_LABEL}=${ownershipNonce}; verify both before manual recovery. No automatic removal was performed.`,
      { cause },
    );
    this.name = 'UnconfirmedContainerOwnershipError';
    this.containerId = containerId;
    this.ownershipNonce = ownershipNonce;
    this.ownershipLabel = OWNER_LABEL;
  }
}

function verifyOwnership(docker, id, nonce) {
  assert.match(id, /^[a-f0-9]{64}$/, 'Cleanup requires a full container ID, never a name');
  assert.equal(
    docker(['inspect', '--format', `{{.Id}} {{index .Config.Labels "${OWNER_LABEL}"}}`, id]),
    `${id} ${nonce}`,
    'Container ownership could not be confirmed; no removal is permitted',
  );
}

export function createOwnedContainer(docker, { name, nonce, args, options }) {
  const id = docker([
    'create', '--name', name, '--label', `${OWNER_LABEL}=${nonce}`, ...args,
  ], options);
  assert.match(id, /^[a-f0-9]{64}$/, 'Docker create must return a full container ID');
  try {
    verifyOwnership(docker, id, nonce);
  } catch (cause) {
    throw new UnconfirmedContainerOwnershipError(id, nonce, cause);
  }
  return id;
}

export function removeOwnedContainer(docker, id, nonce) {
  if (id === undefined) return false;
  verifyOwnership(docker, id, nonce);
  docker(['rm', '--force', id]);
  return true;
}
