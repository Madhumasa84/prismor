# prismor

Prismor adapter for the [Vercel AI SDK](https://sdk.vercel.ai).

Wraps tool `execute` functions to call the Prismor HTTP eval-server before
the tool body runs. Works with any framework that uses the Vercel AI SDK —
Next.js, Remix, Node.js, edge runtimes.

## Prerequisites

Start the eval-server (Python, from the `immunity-agent` repo):

```bash
immunity eval-server --port 7071 --workspace /path/to/project
```

## Install

```bash
npm install prismor
```

## Usage

```typescript
import { generateText, tool } from "ai";
import { openai } from "@ai-sdk/openai";
import { z } from "zod";
import { prismorTools } from "prismor";

const run_shell = tool({
  description: "Run a shell command",
  parameters: z.object({ command: z.string() }),
  execute: async ({ command }) => {
    // ... your implementation
  },
});

// Wrap all tools — every execute() is now policy-checked
const tools = prismorTools({ run_shell }, { subject: `user:${userId}` });

const result = await generateText({
  model: openai("gpt-4o-mini"),
  tools,
  prompt: "List the files in the current directory",
});
```

A blocked call throws `PrismorBlocked`. In a Next.js API route:

```typescript
import { PrismorBlocked } from "prismor";

try {
  const result = await generateText({ model, tools, prompt });
} catch (e) {
  if (e instanceof PrismorBlocked) {
    return Response.json({ error: e.message }, { status: 403 });
  }
  throw e;
}
```

## Per-user (multi-tenant)

Pass `subject` per request — no need to rebuild tool objects:

```typescript
// Next.js API route
export async function POST(req: Request) {
  const { prompt } = await req.json();
  const session = await getSession(req);

  const tools = prismorTools(myTools, {
    subject: `user:${session.userId}`,
    mode: "enforce",
  });

  const result = await generateText({ model, tools, prompt });
  return Response.json({ text: result.text });
}
```

## Options

| Option | Type | Default | Description |
|---|---|---|---|
| `evalUrl` | `string` | `http://127.0.0.1:7071` | Eval-server URL |
| `subject` | `string` | `""` | End-user: `"user:alice"` or `"user=alice;team=data"` |
| `mode` | `"enforce"\|"observe"` | `"enforce"` | Enforce blocks; observe logs only |
| `workspace` | `string` | `process.cwd()` | Project path for policy/IAM lookup |
| `agent` | `string` | `"vercel-ai"` | Agent identifier in telemetry |
| `eventType` | `string` | `"shell"` | Event type: `shell`, `network`, `file_write`, … |
