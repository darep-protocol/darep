import { generateKeyPairSync, createPrivateKey, createPublicKey, randomUUID } from 'node:crypto';
import { readFileSync, mkdirSync, writeFileSync, linkSync, unlinkSync, openSync, fsyncSync, closeSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { validateContact, requireThat } from './protocol.js';
import { makeIdentityDocument, publicKeyOf } from './records.js';

export const readJson = file => JSON.parse(readFileSync(file, 'utf8'));
// Publish a complete file atomically, with exclusive creation even for concurrent operators.
export function writeNewJson(file, object) {
  const temp = join(dirname(file), '.' + randomUUID() + '.tmp');
  const fd = openSync(temp, 'wx', 0o600);
  try {
    writeFileSync(fd, JSON.stringify(object, null, 2) + '\n');
    fsyncSync(fd);
    linkSync(temp, file);
  } finally { closeSync(fd); unlinkSync(temp); }
}
// provider.json holds the owner's contact (identity document plus delivery origin), the signing key and its kid.
export function initialize(dir, id, origin) {
  const keys = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const document = makeIdentityDocument(id, keys.publicKey);
  const card = validateContact({ id, origin, document });
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  writeNewJson(join(dir, 'provider.json'), {
    darep: '2', card, kid: document.keys[0].id, privateKey: keys.privateKey.export({ type: 'pkcs8', format: 'pem' }),
  });
  return card;
}
export function loadConfig(dir) {
  const file = readJson(join(dir, 'provider.json'));
  // Wire v2 (A1) is a breaking change with a data wipe. A v1 identity cannot sign v2 records.
  requireThat(file.darep === '2', 409, 'This provider directory holds a Wire v1 identity. Wire v2 needs a new directory: run init again.');
  const card = validateContact(file.card);
  const key = createPrivateKey(file.privateKey);
  const entry = card.document.keys.find(k => k.id === file.kid);
  const spki = k => k.export({ type: 'spki', format: 'pem' });
  requireThat(entry && spki(createPublicKey(key)) === spki(publicKeyOf(entry.publicKeyJwk)), 500, 'Identity key mismatch');
  return { card, key, kid: file.kid, signer: { key, kid: file.kid } };
}
