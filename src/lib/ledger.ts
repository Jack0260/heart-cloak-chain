// Blockchain-inspired health ledger with hash chaining, Pedersen-style commitments,
// and Schnorr zero-knowledge proofs (Fiat–Shamir). Demo-grade math over a safe-prime group.

export type SignalType = "heart_rate" | "sleep_cycle";

// Demo uses a ~97-bit safe-prime group P = 2q+1 (fast in BigInt; not production strength).


function modPow(b: bigint, e: bigint, m: bigint): bigint {
  let r = 1n;
  b %= m;
  if (b < 0n) b += m;
  while (e > 0n) {
    if (e & 1n) r = (r * b) % m;
    b = (b * b) % m;
    e >>= 1n;
  }
  return r;
}

function isProbablePrime(n: bigint): boolean {
  if (n < 2n) return false;
  for (const sp of [2n, 3n, 5n, 7n, 11n, 13n, 17n, 19n, 23n, 29n, 31n, 37n]) {
    if (n === sp) return true;
    if (n % sp === 0n) return false;
  }
  let d = n - 1n, s = 0;
  while ((d & 1n) === 0n) { d >>= 1n; s++; }
  for (const a of [2n, 3n, 5n, 7n, 11n, 13n, 17n, 19n, 23n, 29n, 31n, 37n]) {
    let x = modPow(a, d, n);
    if (x === 1n || x === n - 1n) continue;
    let ok = false;
    for (let i = 1; i < s; i++) {
      x = (x * x) % n;
      if (x === n - 1n) { ok = true; break; }
    }
    if (!ok) return false;
  }
  return true;
}

// Deterministic safe-prime group (computed once).
function buildGroup() {
  let q = (1n << 96n) + 1n;
  while (true) {
    q += 2n;
    if (isProbablePrime(q) && isProbablePrime(2n * q + 1n)) break;
  }
  const P = 2n * q + 1n;
  const g = modPow(2n, 2n, P);
  const h = modPow(3n, 2n, P);
  return { P, q, g, h };
}
export const GROUP = buildGroup();

const enc = new TextEncoder();
const toHex = (b: ArrayBuffer) => [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, "0")).join("");

export async function sha256(s: string) {
  return toHex(await crypto.subtle.digest("SHA-256", enc.encode(s)));
}
async function hashToScalar(...parts: (string | bigint)[]) {
  return BigInt("0x" + (await sha256(parts.map(String).join("|")))) % GROUP.q;
}
export function randScalar(): bigint {
  const b = crypto.getRandomValues(new Uint8Array(16));
  return BigInt("0x" + [...b].map((x) => x.toString(16).padStart(2, "0")).join("")) % GROUP.q;
}

/** Pedersen commitment C = g^v · h^r mod P. Hides v, binds the owner to it. */
export function commit(v: bigint, r: bigint) {
  const { P, g, h } = GROUP;
  return (modPow(g, v, P) * modPow(h, r, P)) % P;
}

/** Non-interactive ZK proof of knowledge of (v, r) opening C. Reveals nothing about v. */
export interface OpeningProof { t: string; sv: string; sr: string }
export async function proveOpening(C: bigint, v: bigint, r: bigint): Promise<OpeningProof> {
  const { P, q, g, h } = GROUP;
  const a = randScalar(), b = randScalar();
  const t = (modPow(g, a, P) * modPow(h, b, P)) % P;
  const c = await hashToScalar(C, t);
  return { t: t.toString(16), sv: ((a + c * v) % q).toString(16), sr: ((b + c * r) % q).toString(16) };
}
export async function verifyOpening(C: bigint, pr: OpeningProof) {
  const { P, g, h } = GROUP;
  const t = BigInt("0x" + pr.t), sv = BigInt("0x" + pr.sv), sr = BigInt("0x" + pr.sr);
  const c = await hashToScalar(C, t);
  const lhs = (modPow(g, sv, P) * modPow(h, sr, P)) % P;
  return lhs === (t * modPow(C, c, P)) % P;
}

/**
 * ZK range proof that v ∈ [0, 2^bits): commit to each bit and prove each bit commitment
 * opens to 0 OR 1 (Cramer–Damgård–Schoenmakers OR-proof), then show Σ 2^i·C_i = C.
 * Used for "value is below threshold" claims: prove (threshold - 1 - v) ∈ [0, 2^bits).
 */
interface BitProof { C: string; c0: string; c1: string; s0: string; s1: string }
export interface RangeProof { bits: BitProof[]; nbits: number }

export async function proveRange(v: bigint, r: bigint, nbits: number): Promise<RangeProof> {
  const { P, q, h } = GROUP;
  const bits: BitProof[] = [];
  let rSum = 0n;
  const rs: bigint[] = [];
  for (let i = 0; i < nbits; i++) {
    let ri = randScalar();
    if (i === nbits - 1) {
      // force Σ 2^i r_i = r
      const inv = modPow(1n << BigInt(i), q - 2n, q);
      ri = (((r - rSum) % q + q) % q * inv) % q;
    }
    rs.push(ri);
    rSum = (rSum + (1n << BigInt(i)) * ri) % q;
  }
  for (let i = 0; i < nbits; i++) {
    const bit = (v >> BigInt(i)) & 1n;
    const ri = rs[i]!;
    const Ci = commit(bit, ri);
    // statements: Y0 = Ci (=h^ri if bit 0), Y1 = Ci/g (=h^ri if bit 1)
    const Y = [Ci, (Ci * modPow(GROUP.g, P - 2n, P)) % P];
    const real = Number(bit), fake = 1 - real;
    const cf = randScalar(), sf = randScalar();
    const tf = (modPow(h, sf, P) * modPow(modPow(Y[fake]!, cf, P), P - 2n, P)) % P;
    const w = randScalar();
    const tr = modPow(h, w, P);
    const t = real === 0 ? [tr, tf] : [tf, tr];
    const c = await hashToScalar(Ci, t[0]!, t[1]!);
    const cr = ((c - cf) % q + q) % q;
    const sr = (w + cr * ri) % q;
    const cs: [bigint, bigint] = real === 0 ? [cr, cf] : [cf, cr];
    const ss: [bigint, bigint] = real === 0 ? [sr, sf] : [sf, sr];
    bits.push({ C: Ci.toString(16), c0: cs[0].toString(16), c1: cs[1].toString(16), s0: ss[0].toString(16), s1: ss[1].toString(16) });
  }
  return { bits, nbits };
}

export async function verifyRange(C: bigint, pr: RangeProof) {
  const { P, q, g, h } = GROUP;
  let agg = 1n;
  for (let i = 0; i < pr.bits.length; i++) {
    const b = pr.bits[i]!;
    const Ci = BigInt("0x" + b.C);
    const c0 = BigInt("0x" + b.c0), c1 = BigInt("0x" + b.c1);
    const s0 = BigInt("0x" + b.s0), s1 = BigInt("0x" + b.s1);
    const Y0 = Ci, Y1 = (Ci * modPow(g, P - 2n, P)) % P;
    const t0 = (modPow(h, s0, P) * modPow(modPow(Y0, c0, P), P - 2n, P)) % P;
    const t1 = (modPow(h, s1, P) * modPow(modPow(Y1, c1, P), P - 2n, P)) % P;
    const c = await hashToScalar(Ci, t0, t1);
    if ((c0 + c1) % q !== c) return false;
    agg = (agg * modPow(Ci, 1n << BigInt(i), P)) % P;
  }
  return agg === C;
}

// ---------- Ledger ----------
export interface Block {
  index: number;
  timestamp: number;
  prevHash: string;
  pseudonym: string; // salted hash of patient id — unlinkable without salt
  signal: SignalType;
  commitment: string; // hides the raw value
  openingProof: OpeningProof;
  claims: { label: string; threshold: number; proof: RangeProof }[];
  nonce: number;
  hash: string;
}

/** Private vault kept by the data owner; never written to the chain. */
export interface Secret { blockHash: string; value: number; blinding: string; patientId: string }

export const DIFFICULTY = "000";
export const THRESHOLDS: Record<SignalType, { label: string; t: number; unit: string }> = {
  heart_rate: { label: "resting HR < 100 bpm", t: 100, unit: "bpm" },
  sleep_cycle: { label: "sleep < 600 min", t: 600, unit: "min" },
};

export async function pseudonymize(patientId: string, salt: string) {
  return (await sha256(`${salt}:${patientId}`)).slice(0, 16);
}

export async function blockHash(b: Omit<Block, "hash">) {
  return sha256(JSON.stringify({ ...b, claims: b.claims }));
}

export async function mine(b: Omit<Block, "hash" | "nonce">): Promise<Block> {
  let nonce = 0;
  while (true) {
    const h = await blockHash({ ...b, nonce });
    if (h.startsWith(DIFFICULTY)) return { ...b, nonce, hash: h };
    nonce++;
  }
}

export async function genesis(): Promise<Block> {
  const C = commit(0n, 0n);
  return mine({
    index: 0, timestamp: 0, prevHash: "0".repeat(64), pseudonym: "genesis",
    signal: "heart_rate", commitment: C.toString(16),
    openingProof: await proveOpening(C, 0n, 0n), claims: [],
  });
}

const NBITS = 10; // supports values/differences up to 1023

export async function appendReading(
  chain: Block[], patientId: string, salt: string, signal: SignalType, value: number,
): Promise<{ block: Block; secret: Secret }> {
  const v = BigInt(Math.round(value));
  const r = randScalar();
  const C = commit(v, r);
  const th = THRESHOLDS[signal];
  const claims: Block["claims"] = [];
  if (value < th.t && value >= 0 && th.t - 1 - value < 1 << NBITS) {
    // Prove (t-1-v) in range using commitment C' = g^(t-1) / C  (blinding = -r)
    const d = BigInt(th.t - 1) - v;
    const negR = (GROUP.q - r) % GROUP.q;
    claims.push({ label: th.label, threshold: th.t, proof: await proveRange(d, negR, NBITS) });
  }
  const prev = chain[chain.length - 1]!;
  const block = await mine({
    index: chain.length, timestamp: Date.now(), prevHash: prev.hash,
    pseudonym: await pseudonymize(patientId, salt), signal,
    commitment: C.toString(16), openingProof: await proveOpening(C, v, r), claims,
  });
  return { block, secret: { blockHash: block.hash, value, blinding: r.toString(16), patientId } };
}

export function thresholdCommitment(C: bigint, t: number) {
  const { P, g } = GROUP;
  return (modPow(g, BigInt(t - 1), P) * modPow(C, P - 2n, P)) % P;
}

export async function verifyBlock(b: Block, prev?: Block) {
  const { hash, ...rest } = b;
  const issues: string[] = [];
  if ((await blockHash(rest)) !== hash) issues.push("hash mismatch (tampered)");
  if (!hash.startsWith(DIFFICULTY)) issues.push("invalid proof-of-work");
  if (prev && b.prevHash !== prev.hash) issues.push("broken link to previous block");
  const C = BigInt("0x" + b.commitment);
  if (!(await verifyOpening(C, b.openingProof))) issues.push("ZK opening proof invalid");
  for (const c of b.claims) {
    if (!(await verifyRange(thresholdCommitment(C, c.threshold), c.proof))) issues.push(`range proof invalid: ${c.label}`);
  }
  return issues;
}

/** Owner opens a commitment to an authorized party (selective disclosure). */
export function checkDisclosure(b: Block, value: number, blindingHex: string) {
  return commit(BigInt(value), BigInt("0x" + blindingHex)).toString(16) === b.commitment;
}

/** k-anonymous aggregate: coarse buckets, suppressed if fewer than k distinct pseudonyms. */
export function anonymizedAggregate(secrets: Secret[], chain: Block[], signal: SignalType, k: number, epsilon: number) {
  const byHash = new Map(chain.map((b) => [b.hash, b]));
  const rows = secrets.filter((s) => byHash.get(s.blockHash)?.signal === signal);
  const width = signal === "heart_rate" ? 20 : 120;
  const buckets = new Map<number, { count: number; people: Set<string> }>();
  for (const s of rows) {
    const key = Math.floor(s.value / width) * width;
    const e = buckets.get(key) ?? { count: 0, people: new Set() };
    e.count++; e.people.add(byHash.get(s.blockHash)!.pseudonym);
    buckets.set(key, e);
  }
  const laplace = () => { const u = Math.random() - 0.5; return -(1 / epsilon) * Math.sign(u) * Math.log(1 - 2 * Math.abs(u)); };
  return [...buckets.entries()].sort((a, b) => a[0] - b[0]).map(([lo, e]) => ({
    range: `${lo}–${lo + width - 1}`,
    count: e.people.size >= k ? Math.max(0, Math.round(e.count + laplace())) : null,
    suppressed: e.people.size < k,
  }));
}
