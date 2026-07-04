"use strict";
/**
 * Tests for the Vercel AI SDK adapter. No live eval-server — global fetch is
 * stubbed so these run standalone. Covers the fail-open regression from
 * PrismorSec/prismor#136: a network error from fetch() itself (eval-server
 * unreachable) must fail open, not throw.
 */
const test = require("node:test");
const assert = require("node:assert/strict");
const { prismorTools, prismorTool, PrismorBlocked } = require("../dist/index.js");

function withMockFetch(impl, fn) {
  const original = globalThis.fetch;
  globalThis.fetch = impl;
  return Promise.resolve(fn()).finally(() => {
    globalThis.fetch = original;
  });
}

test("allows the call when the eval-server returns allow: true", async () => {
  await withMockFetch(
    async () => ({ ok: true, json: async () => ({ allow: true, reason: null, findings: [], blocking: null, subject: null }) }),
    async () => {
      const run_shell = { execute: async ({ command }) => `ran: ${command}` };
      const tools = prismorTools({ run_shell });
      const result = await tools.run_shell.execute({ command: "echo hi" });
      assert.equal(result, "ran: echo hi");
    },
  );
});

test("throws PrismorBlocked when the eval-server denies the call", async () => {
  await withMockFetch(
    async () => ({ ok: true, json: async () => ({ allow: false, reason: "blocked for testing", findings: [], blocking: null, subject: null }) }),
    async () => {
      const run_shell = { execute: async () => "should not run" };
      const tools = prismorTools({ run_shell });
      await assert.rejects(
        () => tools.run_shell.execute({ command: "rm -rf /" }),
        PrismorBlocked,
      );
    },
  );
});

test("fails open (does not throw) on a non-2xx response", async () => {
  await withMockFetch(
    async () => ({ ok: false, status: 503 }),
    async () => {
      const run_shell = { execute: async ({ command }) => `ran: ${command}` };
      const tools = prismorTools({ run_shell });
      const result = await tools.run_shell.execute({ command: "rm -rf /" });
      assert.equal(result, "ran: rm -rf /");
    },
  );
});

test("fails open (does not throw) when fetch itself rejects — #136 regression", async () => {
  await withMockFetch(
    async () => {
      throw new TypeError("fetch failed");
    },
    async () => {
      const run_shell = { execute: async ({ command }) => `ran: ${command}` };
      const tools = prismorTools({ run_shell });
      // Before the fix, this threw the raw fetch error instead of failing open.
      const result = await tools.run_shell.execute({ command: "rm -rf /" });
      assert.equal(result, "ran: rm -rf /");
    },
  );
});

test("a tool with no execute() is returned unchanged", () => {
  const noop = {};
  const wrapped = prismorTool("noop", noop);
  assert.equal(wrapped, noop);
});
