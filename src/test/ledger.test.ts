import { describe, it, expect } from "vitest";
import { genesis, appendReading, verifyBlock, checkDisclosure, anonymizedAggregate } from "@/lib/ledger";

describe("health ledger", () => {
  it("verifies valid blocks with ZK proofs and detects tampering", async () => {
    const chain = [await genesis()];
    const { block, secret } = await appendReading(chain, "alice", "salt", "heart_rate", 72);
    expect(block.claims.length).toBe(1);
    expect(await verifyBlock(block, chain[0])).toEqual([]);
    expect(checkDisclosure(block, 72, secret.blinding)).toBe(true);
    expect(checkDisclosure(block, 73, secret.blinding)).toBe(false);
    const tampered = { ...block, commitment: (BigInt("0x" + block.commitment) + 1n).toString(16) };
    expect((await verifyBlock(tampered, chain[0])).length).toBeGreaterThan(0);
  }, 30000);

  it("no below-threshold claim for HR >= 100", async () => {
    const chain = [await genesis()];
    const { block } = await appendReading(chain, "bob", "s", "heart_rate", 120);
    expect(block.claims.length).toBe(0);
  }, 30000);

  it("suppresses buckets with fewer than k people", async () => {
    const chain = [await genesis()];
    const { block, secret } = await appendReading(chain, "a", "s", "heart_rate", 70);
    chain.push(block);
    const agg = anonymizedAggregate([secret], chain, "heart_rate", 2, 1);
    expect(agg[0].suppressed).toBe(true);
  }, 30000);
});
