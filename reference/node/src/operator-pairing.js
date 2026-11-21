import { randomUUID } from 'node:crypto';
import { z } from 'zod';
import { identity, publicCard, hash, parse, Problem, requireThat, validateContact } from './protocol.js';
import { instant, RecordRejection, signCompact, unverifiedPayload, verifyCompact } from './records.js';

// The pairing code is this implementation's out-of-band exchange, not a Wire v2 record. It carries the
// sender's contact (identity-document snapshot plus delivery origin) signed by a key in that same document.
// The owner's fingerprint comparison is what makes the self-signed snapshot trustworthy (records.md TA-2).
const media = 'darep-pairing-v2+jws';
const lifetime = 15 * 60_000;
const digest = z.string().regex(/^[a-f0-9]{64}$/);
const envelope = z.strictObject({
  version: z.literal(2), kind: z.enum(['invite', 'answer', 'finish']),
  nonce: z.uuidv4(), expires: z.number().int().safe(), card: z.looseObject({}), address: identity,
  parent: digest.nullable(), to: digest.nullable(),
});
// Covers everything the owner accepts by pinning: address, delivery origin, document id, and every key with
// its purposes and validity. Member order in the transmitted JSON does not change the digest.
// Pairing fingerprints sort JSON members for the Python owner exchange only.
// Record signatures and receipt digests always cover the original bytes (NC1).
function sorted(value) {
  if (Array.isArray(value)) return value.map(sorted);
  if (value && typeof value === 'object') return Object.fromEntries(Object.keys(value).sort().map(k => [k, sorted(value[k])]));
  return value;
}
function cardDigest(card) {
  const external = publicCard(validateContact(card));
  return hash(JSON.stringify(sorted([external.identity, external.inbox])));
}
export function fingerprint(card) {
  return cardDigest(card).slice(0, 32).toUpperCase().match(/.{4}/g).join('-');
}

export class Pairing {
  constructor(store, config, now = Date.now) {
    this.store = store;
    this.config = config;
    this.now = now;
    store.db.exec(
      'CREATE TABLE IF NOT EXISTS operator_pairing (' +
      'side TEXT NOT NULL, nonce TEXT NOT NULL, offer_hash TEXT NOT NULL, answer_hash TEXT, ' +
      'reply TEXT, done INTEGER NOT NULL DEFAULT 0, expires INTEGER NOT NULL, ' +
      'PRIMARY KEY (side,nonce))'
    );
  }
  encode(kind, nonce, expires, parent, to) {
    const { card, signer } = this.config;
    return signCompact(JSON.stringify({ version: 2, kind, nonce, expires, card: publicCard(card), address: card.id, parent, to }), signer, media);
  }
  async invite() {
    const nonce = randomUUID();
    const expires = this.now() + lifetime;
    const code = await this.encode('invite', nonce, expires, null, null);
    this.store.db.prepare('DELETE FROM operator_pairing WHERE expires < ?').run(this.now());
    this.store.db.prepare("INSERT INTO operator_pairing(side,nonce,offer_hash,expires) VALUES('issuer',?,?,?)")
      .run(nonce, hash(code), expires);
    return { code, expires, nonce };
  }
  openInvites() {
    return this.store.db.prepare("SELECT nonce, expires FROM operator_pairing WHERE side='issuer' AND done=0 AND expires>? ORDER BY expires DESC")
      .all(this.now());
  }
  cancel(nonce) {
    const row = this.store.db.prepare("DELETE FROM operator_pairing WHERE side='issuer' AND nonce=? AND done=0 AND expires>?")
      .run(nonce, this.now());
    return { cancelled: row.changes === 1 };
  }
  async decode(code) {
    requireThat(typeof code === 'string' && code.length > 0 && code.length <= 16384, 400, 'Invalid invitation code');
    let unverified;
    try { unverified = unverifiedPayload(code); } catch { throw new Problem(400, 'Invalid invitation code'); }
    requireThat(unverified?.version === 2, 400, 'This invitation uses an older format. Ask your contact to update and start pairing again.');
    const card = validateContact(unverified.card);
    let signed;
    try {
      signed = verifyCompact(code, media, id => id === card.document.id ? card.document : null);
      const now = this.now();
      requireThat(signed.key.purpose.includes('record') && !Object.hasOwn(signed.key, 'revoked') &&
        instant(signed.key.validFrom) <= now && !(instant(signed.key.validUntil) <= now), 401, 'Signing key is not valid');
    } catch (error) {
      if (error instanceof RecordRejection) throw new Problem(401, 'Invalid signature or signed payload');
      throw error;
    }
    const verified = parse(envelope, signed.value);
    requireThat(verified.address === card.id, 403, 'Pairing address does not match its identity');
    requireThat(verified.expires > this.now() && verified.expires <= this.now() + lifetime + 60_000, 410, 'Invitation expired. Start pairing again.');
    requireThat(card.id !== this.config.card.id, 400, 'Enter the reply from the other person');
    const opening = verified.kind === 'invite';
    requireThat(opening ? verified.to === null && verified.parent === null :
      verified.to === cardDigest(this.config.card) && verified.parent !== null, 403, 'This invitation belongs to another identity');
    this.store.checkPin(card);
    return { ...verified, card };
  }
  row(side, nonce) {
    return this.store.db.prepare('SELECT * FROM operator_pairing WHERE side=? AND nonce=?').get(side, nonce);
  }
  match(row, parent, column, expires) {
    requireThat(row && row[column] === parent && row.expires === expires, 409, 'No matching active pairing record');
  }
  matchFinish(card, nonce, parent, expires) {
    const row = this.row('guest', nonce);
    this.match(row, parent, 'answer_hash', expires);
    requireThat(unverifiedPayload(row.reply).to === cardDigest(card), 403, 'Pairing confirmation came from another identity');
    return row;
  }
  async inspect(code) {
    const msg = await this.decode(code);
    if (msg.kind === 'answer') this.match(this.row('issuer', msg.nonce), msg.parent, 'offer_hash', msg.expires);
    if (msg.kind === 'finish') this.matchFinish(msg.card, msg.nonce, msg.parent, msg.expires);
    return { kind: msg.kind, peer: msg.card.id, origin: msg.card.origin, fingerprint: fingerprint(msg.card), expires: msg.expires };
  }
  async approve(code, acknowledged) {
    const { kind, card, expires, nonce, parent } = await this.decode(code);
    requireThat(fingerprint(card) === acknowledged, 400, 'Verify your contact’s fingerprint first');
    const db = this.store.db;
    if (kind === 'invite') {
      const answer = await this.encode('answer', nonce, expires, hash(code), cardDigest(card));
      db.prepare("INSERT OR IGNORE INTO operator_pairing(side,nonce,offer_hash,answer_hash,reply,expires) VALUES('guest',?,?,?,?,?)")
        .run(nonce, hash(code), hash(answer), answer, expires);
      const row = this.row('guest', nonce);
      this.match(row, hash(code), 'offer_hash', expires);
      requireThat(!row.done, 409, 'This invitation has already been paired');
      return { phase: 'answer', code: row.reply };
    }
    if (kind === 'answer') {
      const answerHash = hash(code);
      const finish = await this.encode('finish', nonce, expires, answerHash, cardDigest(card));
      return this.store.transaction(() => {
        this.match(this.row('issuer', nonce), parent, 'offer_hash', expires);
        db.prepare("UPDATE operator_pairing SET answer_hash=?,reply=? WHERE side='issuer' AND nonce=? AND answer_hash IS NULL")
          .run(answerHash, finish, nonce);
        const row = this.row('issuer', nonce);
        this.match(row, answerHash, 'answer_hash', expires);
        if (!row.done) this.pin('issuer', nonce, card);
        return { phase: 'finish', code: row.reply };
      });
    }
    return this.store.transaction(() => {
      const row = this.matchFinish(card, nonce, parent, expires);
      if (!row.done) this.pin('guest', nonce, card);
      return { phase: 'paired' };
    });
  }
  pin(side, nonce, card) {
    this.store.trust(card);
    this.store.db.prepare('UPDATE operator_pairing SET done=1 WHERE side=? AND nonce=?').run(side, nonce);
  }
}
