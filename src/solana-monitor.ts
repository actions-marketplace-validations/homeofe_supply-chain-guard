/**
 * Solana C2 wallet monitor
 *
 * Monitors Solana wallet addresses for transactions containing memo instructions.
 * GlassWorm and similar campaigns encode C2 URLs as Solana transaction memos,
 * making the blockchain an uncensorable command-and-control channel.
 */

import * as https from "node:https";
import type { SolanaMonitorOptions, SolanaTransaction } from "./types.js";

const SOLANA_RPC = "https://api.mainnet-beta.solana.com";
const MEMO_PROGRAM_ID = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr";

interface TransactionDetail {
  signature: string;
  blockTime: number | null;
  memos: string[];
}

/**
 * Monitor a Solana wallet for C2 memo transactions.
 * Runs continuously until stopped.
 */
export async function monitorWallet(
  options: SolanaMonitorOptions,
  onAlert: (alert: C2Alert) => void,
): Promise<void> {
  const { address, interval, limit } = options;
  let lastSignature: string | null = null;

  console.log(`\n  Monitoring Solana wallet: ${address}`);
  console.log(`  Polling interval: ${interval}s | Checking last ${limit} transactions`);
  console.log(`  Press Ctrl+C to stop\n`);

  // Initial fetch to set baseline
  const initial = await getRecentSignatures(address, limit);
  if (initial.length > 0) {
    lastSignature = initial[0]?.signature ?? null;
    console.log(`  Baseline set: ${initial.length} existing transactions`);
    console.log(`  Latest: ${lastSignature}\n`);
  }

  // Poll loop
  const poll = async (): Promise<void> => {
    try {
      const signatures = await getRecentSignatures(address, limit);

      // Find new transactions since last check
      const newSigs: Array<{ signature: string }> = [];
      for (const sig of signatures) {
        if (sig.signature === lastSignature) break;
        newSigs.push(sig);
      }

      if (newSigs.length > 0 && lastSignature !== null) {
        console.log(`  [${new Date().toISOString()}] ${newSigs.length} new transaction(s)`);

        for (const sig of newSigs) {
          const detail = await getTransactionDetail(sig.signature);
          if (detail && detail.memos.length > 0) {
            for (const memo of detail.memos) {
              const alert: C2Alert = {
                timestamp: new Date().toISOString(),
                wallet: address,
                signature: sig.signature,
                memo,
                decodedUrls: extractUrls(memo),
                blockTime: detail.blockTime,
              };

              onAlert(alert);
            }
          }
        }

        lastSignature = newSigs[0]?.signature ?? lastSignature;
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      console.error(`  [${new Date().toISOString()}] Poll error: ${message}`);
    }

    // Schedule next poll
    setTimeout(() => void poll(), interval * 1000);
  };

  await poll();
}

/**
 * One-shot check: get recent transactions and check for memos.
 */
export async function checkWallet(
  address: string,
  limit = 20,
): Promise<TransactionDetail[]> {
  const signatures = await getRecentSignatures(address, limit);
  const results: TransactionDetail[] = [];

  for (const sig of signatures) {
    const detail = await getTransactionDetail(sig.signature);
    if (detail && detail.memos.length > 0) {
      results.push(detail);
    }
  }

  return results;
}

/**
 * Get recent transaction signatures for a wallet.
 */
async function getRecentSignatures(
  address: string,
  limit: number,
): Promise<Array<{ signature: string }>> {
  const response = await solanaRpc("getSignaturesForAddress", [
    address,
    { limit },
  ]);

  if (!Array.isArray(response)) return [];

  return response.map(
    (tx: { signature: string }) => ({ signature: tx.signature }),
  );
}

/**
 * Get full transaction detail and extract memo instructions.
 */
async function getTransactionDetail(
  signature: string,
): Promise<TransactionDetail | null> {
  const response = await solanaRpc("getTransaction", [
    signature,
    { encoding: "jsonParsed", maxSupportedTransactionVersion: 0 },
  ]);

  if (!response) return null;

  const memos: string[] = [];
  const tx = response as {
    blockTime?: number | null;
    transaction?: {
      message?: {
        instructions?: Array<{
          programId?: string;
          parsed?: string;
          data?: string;
        }>;
      };
    };
    meta?: {
      innerInstructions?: Array<{
        instructions?: Array<{
          programId?: string;
          parsed?: string;
          data?: string;
        }>;
      }>;
    };
  };

  // Check main instructions
  const instructions = tx.transaction?.message?.instructions ?? [];
  for (const ix of instructions) {
    if (ix.programId === MEMO_PROGRAM_ID) {
      const memoText = ix.parsed ?? ix.data ?? "";
      if (memoText) memos.push(memoText);
    }
  }

  // Check inner instructions
  const innerInstructions = tx.meta?.innerInstructions ?? [];
  for (const inner of innerInstructions) {
    for (const ix of inner.instructions ?? []) {
      if (ix.programId === MEMO_PROGRAM_ID) {
        const memoText = ix.parsed ?? ix.data ?? "";
        if (memoText) memos.push(memoText);
      }
    }
  }

  return {
    signature,
    blockTime: tx.blockTime ?? null,
    memos,
  };
}

/**
 * Make a JSON-RPC call to the Solana RPC endpoint.
 */
function solanaRpc(method: string, params: unknown[]): Promise<unknown> {
  const body = JSON.stringify({
    jsonrpc: "2.0",
    id: 1,
    method,
    params,
  });

  return new Promise((resolve, reject) => {
    const url = new URL(SOLANA_RPC);
    const req = https.request(
      {
        hostname: url.hostname,
        port: url.port || 443,
        path: url.pathname,
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Content-Length": Buffer.byteLength(body),
        },
      },
      (res) => {
        let data = "";
        res.on("data", (chunk: Buffer) => {
          data += chunk.toString();
        });
        res.on("end", () => {
          try {
            const parsed = JSON.parse(data) as { result?: unknown; error?: { message: string } };
            if (parsed.error) {
              reject(new Error(`Solana RPC error: ${parsed.error.message}`));
              return;
            }
            resolve(parsed.result);
          } catch {
            reject(new Error("Failed to parse Solana RPC response"));
          }
        });
      },
    );

    req.on("error", reject);
    req.write(body);
    req.end();
  });
}

/**
 * Extract URLs from a memo string.
 */
function extractUrls(text: string): string[] {
  const urlRegex = /https?:\/\/[^\s"'<>]+/gi;
  return text.match(urlRegex) ?? [];
}

/**
 * Alert structure for detected C2 communications.
 */
export interface C2Alert {
  timestamp: string;
  wallet: string;
  signature: string;
  memo: string;
  decodedUrls: string[];
  blockTime: number | null;
}

/**
 * Format a C2 alert for display.
 */
export function formatAlert(alert: C2Alert): string {
  const lines = [
    "",
    "  ====================================",
    "  !! C2 MEMO DETECTED !!",
    "  ====================================",
    `  Time:      ${alert.timestamp}`,
    `  Wallet:    ${alert.wallet}`,
    `  Signature: ${alert.signature}`,
    `  Memo:      ${alert.memo}`,
  ];

  if (alert.decodedUrls.length > 0) {
    lines.push(`  URLs:      ${alert.decodedUrls.join(", ")}`);
  }

  if (alert.blockTime) {
    lines.push(
      `  Block:     ${new Date(alert.blockTime * 1000).toISOString()}`,
    );
  }

  lines.push("  ====================================", "");
  return lines.join("\n");
}
