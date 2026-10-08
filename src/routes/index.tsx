import { createFileRoute } from "@tanstack/react-router";
import { useEffect, useState } from "react";
import {
  genesis, appendReading, verifyBlock, checkDisclosure, anonymizedAggregate, THRESHOLDS,
  type Block, type Secret, type SignalType,
} from "@/lib/ledger";

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: "VitalChain — Private Health Signal Ledger" },
      { name: "description", content: "Hash-chained ledger for heart rate and sleep data with zero-knowledge proofs and anonymized analytics." },
      { property: "og:title", content: "VitalChain — Private Health Signal Ledger" },
      { property: "og:description", content: "Store, query and anonymize biosignals with zero-knowledge proofs." },
    ],
  }),
  component: Index,
});

const SALT = "vitalchain-demo-salt";
const short = (h: string) => h.slice(0, 10) + "…";

function Panel({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="rounded-lg border border-border bg-card p-5">
      <h2 className="mb-4 font-mono text-xs uppercase tracking-widest text-primary">{title}</h2>
      {children}
    </section>
  );
}
const input = "w-full rounded border border-input bg-background px-3 py-2 font-mono text-sm";
const btn = "rounded bg-primary px-4 py-2 font-mono text-sm font-semibold text-primary-foreground hover:shadow-glow disabled:opacity-50";

function Index() {
  const [chain, setChain] = useState<Block[]>([]);
  const [vault, setVault] = useState<Secret[]>([]);
  const [busy, setBusy] = useState(false);
  const [patient, setPatient] = useState("patient-001");
  const [signal, setSignal] = useState<SignalType>("heart_rate");
  const [value, setValue] = useState(72);
  const [audit, setAudit] = useState<Record<number, string[]>>({});
  const [qSignal, setQSignal] = useState<SignalType | "all">("all");
  const [qPatient, setQPatient] = useState("");
  const [qHash, setQHash] = useState<string | null>(null);
  const [k, setK] = useState(2);
  const [eps, setEps] = useState(1);
  const [disclose, setDisclose] = useState<{ idx: number; ok: boolean } | null>(null);

  useEffect(() => {
    (async () => {
      setBusy(true);
      const c = [await genesis()];
      const v: Secret[] = [];
      const seed: [string, SignalType, number][] = [
        ["patient-001", "heart_rate", 68], ["patient-002", "heart_rate", 74], ["patient-003", "heart_rate", 112],
        ["patient-001", "sleep_cycle", 430], ["patient-002", "sleep_cycle", 390], ["patient-003", "sleep_cycle", 455],
        ["patient-004", "heart_rate", 79], ["patient-004", "sleep_cycle", 410],
      ];
      for (const [p, s, val] of seed) {
        const { block, secret } = await appendReading(c, p, SALT, s, val);
        c.push(block); v.push(secret);
      }
      setChain(c); setVault(v); setBusy(false);
    })();
  }, []);

  async function add() {
    setBusy(true);
    const { block, secret } = await appendReading(chain, patient, SALT, signal, value);
    setChain([...chain, block]); setVault([...vault, secret]); setBusy(false);
  }
  async function verifyAll() {
    setBusy(true);
    const r: Record<number, string[]> = {};
    for (let i = 0; i < chain.length; i++) r[i] = await verifyBlock(chain[i]!, chain[i - 1]);
    setAudit(r); setBusy(false);
  }
  function tamper(i: number) {
    const c = [...chain];
    const b = c[i]!;
    c[i] = { ...b, commitment: (BigInt("0x" + b.commitment) + 1n).toString(16) };
    setChain(c); setAudit({});
  }
  useEffect(() => {
    if (!qPatient) return setQHash(null);
    import("@/lib/ledger").then(({ pseudonymize }) => pseudonymize(qPatient, SALT).then(setQHash));
  }, [qPatient]);

  const results = chain.slice(1).filter((b) =>
    (qSignal === "all" || b.signal === qSignal) && (!qHash || b.pseudonym === qHash));

  return (
    <main className="mx-auto max-w-6xl px-4 py-10">
      <header className="mb-8">
        <p className="font-mono text-xs text-accent">// zero-knowledge biosignal ledger</p>
        <h1 className="mt-2 text-4xl font-bold">VitalChain</h1>
        <p className="mt-2 max-w-2xl text-muted-foreground">
          Readings are stored as hidden commitments in a tamper-evident hash chain. Anyone can verify claims
          like “heart rate under 100” with a zero-knowledge proof — without ever seeing the number.
        </p>
      </header>

      <div className="grid gap-5 lg:grid-cols-3">
        <Panel title="1 · Store reading">
          <div className="space-y-3">
            <input className={input} value={patient} onChange={(e) => setPatient(e.target.value)} placeholder="patient id" />
            <select className={input} value={signal} onChange={(e) => setSignal(e.target.value as SignalType)}>
              <option value="heart_rate">Heart rate (bpm)</option>
              <option value="sleep_cycle">Sleep duration (min)</option>
            </select>
            <input className={input} type="number" value={value} onChange={(e) => setValue(+e.target.value)} />
            <button className={btn + " w-full"} disabled={busy} onClick={add}>{busy ? "mining…" : "Commit + prove + mine"}</button>
            <p className="text-xs text-muted-foreground">Patient ID is salted-hashed into a pseudonym. Raw value stays in your private vault.</p>
          </div>
        </Panel>

        <Panel title="2 · Query (sees only public data)">
          <div className="space-y-3">
            <select className={input} value={qSignal} onChange={(e) => setQSignal(e.target.value as SignalType | "all")}>
              <option value="all">All signals</option>
              <option value="heart_rate">Heart rate</option>
              <option value="sleep_cycle">Sleep</option>
            </select>
            <input className={input} value={qPatient} onChange={(e) => setQPatient(e.target.value)} placeholder="patient id (needs salt)" />
            <p className="font-mono text-xs text-muted-foreground">{results.length} blocks matched</p>
            <ul className="max-h-48 space-y-1 overflow-auto font-mono text-xs">
              {results.map((b) => (
                <li key={b.index} className="rounded bg-muted px-2 py-1">
                  #{b.index} {b.signal} · {b.claims.length ? <span className="text-success">✓ {b.claims[0]!.label}</span> : <span className="text-accent">no claim</span>}
                </li>
              ))}
            </ul>
          </div>
        </Panel>

        <Panel title="3 · Anonymized analytics">
          <div className="mb-3 grid grid-cols-2 gap-2 font-mono text-xs">
            <label>k-anonymity <input className={input} type="number" min={1} value={k} onChange={(e) => setK(+e.target.value)} /></label>
            <label>privacy ε <input className={input} type="number" step={0.1} min={0.1} value={eps} onChange={(e) => setEps(+e.target.value)} /></label>
          </div>
          {(["heart_rate", "sleep_cycle"] as SignalType[]).map((s) => (
            <div key={s} className="mb-3">
              <p className="mb-1 text-xs text-muted-foreground">{s === "heart_rate" ? "Heart rate (bpm)" : "Sleep (min)"}</p>
              {anonymizedAggregate(vault, chain, s, k, eps).map((r) => (
                <div key={r.range} className="flex justify-between font-mono text-xs">
                  <span>{r.range}</span>
                  <span className={r.suppressed ? "text-accent" : "text-success"}>{r.suppressed ? "suppressed" : `≈${r.count}`}</span>
                </div>
              ))}
            </div>
          ))}
          <p className="text-xs text-muted-foreground">Buckets with fewer than k people are hidden; counts get noise (differential privacy).</p>
        </Panel>
      </div>

      <div className="mt-5">
        <Panel title="Ledger">
          <div className="mb-4 flex flex-wrap items-center gap-3">
            <button className={btn} disabled={busy} onClick={verifyAll}>Verify chain + ZK proofs</button>
            <span className="font-mono text-xs text-muted-foreground">{chain.length} blocks · proof-of-work "000"</span>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full font-mono text-xs">
              <thead className="text-left text-muted-foreground">
                <tr><th className="p-2">#</th><th>hash</th><th>prev</th><th>pseudonym</th><th>signal</th><th>commitment</th><th>status</th><th></th></tr>
              </thead>
              <tbody>
                {chain.map((b) => {
                  const a = audit[b.index];
                  const secret = vault.find((s) => s.blockHash === b.hash);
                  return (
                    <tr key={b.index} className="border-t border-border">
                      <td className="p-2">{b.index}</td>
                      <td>{short(b.hash)}</td>
                      <td className="text-muted-foreground">{short(b.prevHash)}</td>
                      <td>{b.pseudonym}</td>
                      <td>{b.signal}</td>
                      <td className="text-muted-foreground">{short(b.commitment)}</td>
                      <td>{a ? (a.length ? <span className="text-destructive">✗ {a[0]}</span> : <span className="text-success">✓ valid</span>) : "—"}</td>
                      <td className="space-x-2 whitespace-nowrap">
                        {b.index > 0 && <button className="text-accent underline" onClick={() => tamper(b.index)}>tamper</button>}
                        {secret && (
                          <button className="text-primary underline" onClick={() => setDisclose({ idx: b.index, ok: checkDisclosure(b, secret.value, secret.blinding) })}>
                            disclose
                          </button>
                        )}
                        {disclose?.idx === b.index && secret && (
                          <span className={disclose.ok ? "text-success" : "text-destructive"}>
                            {disclose.ok ? `= ${secret.value} ${THRESHOLDS[b.signal].unit}` : "opening fails"}
                          </span>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </Panel>
      </div>
    </main>
  );
}
