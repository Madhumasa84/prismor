/**
 * Prismor adapter for the Vercel AI SDK.
 *
 * Wraps tool `execute` functions to call the Prismor eval-server
 * (prismor eval-server) before the tool body runs. A denied call
 * throws PrismorBlocked (enforce mode) or logs and proceeds (observe mode).
 *
 * Quick start:
 *   const tools = prismorTools({ run_shell, search_web }, { subject: `user:${userId}` });
 *   const result = await generateText({ model, tools, prompt });
 */

export interface PrismorOptions {
  /** URL of the running eval-server. Default: http://127.0.0.1:7071 */
  evalUrl?: string;
  /** Subject for per-user attribution: "user:alice" or "user=alice;team=data" */
  subject?: string;
  /** "enforce" blocks denied calls; "observe" logs only. Default: "enforce" */
  mode?: "enforce" | "observe";
  /** Workspace path forwarded to the policy engine. Default: process.cwd() */
  workspace?: string;
  /** Framework identifier (e.g. "vercel-ai"). Default: "vercel-ai" */
  agent?: string;
  /**
   * Per-instance agent name — used for the dashboard kill-switch and per-agent
   * mode/IAM controls. Distinct from `agent` (the framework). Example: "support-bot".
   * Default: same as `agent`.
   */
  agentName?: string;
  /**
   * Map tool argument keys to a Prismor event type.
   * Default: "shell" (args serialised to command string).
   * Use "network" for URL-fetching tools, "file_write" for file-writing tools.
   */
  eventType?: "shell" | "network" | "file_write" | "file_read" | "tool_result";
}

export interface PrismorDecision {
  allow: boolean;
  reason: string | null;
  findings: unknown[];
  blocking: unknown | null;
  subject: { user_id: string | null; team_id: string | null } | null;
}

export class PrismorBlocked extends Error {
  decision: PrismorDecision;
  constructor(reason: string, decision: PrismorDecision) {
    super(`Blocked by Prismor: ${reason}`);
    this.name = "PrismorBlocked";
    this.decision = decision;
  }
}

async function evaluate(
  toolName: string,
  args: Record<string, unknown>,
  opts: Required<PrismorOptions>,
  sessionId: string,
): Promise<PrismorDecision> {
  const res = await fetch(`${opts.evalUrl}/v1/evaluate`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(opts.subject ? { "X-Prismor-Subject": opts.subject } : {}),
      ...(opts.agentName ? { "X-Prismor-Agent-Name": opts.agentName } : {}),
    },
    body: JSON.stringify({
      tool_name: toolName,
      arguments: args,
      event_type: opts.eventType,
      agent: opts.agent,
      agent_name: opts.agentName,
      mode: opts.mode,
      session_id: sessionId,
      subject: opts.subject,
      workspace: opts.workspace,
    }),
  });

  if (!res.ok) {
    // Server error — fail open (don't break the agent on infrastructure issues)
    console.warn(`[prismor] eval-server returned ${res.status} — failing open`);
    return { allow: true, reason: null, findings: [], blocking: null, subject: null };
  }
  return res.json() as Promise<PrismorDecision>;
}

function resolveOpts(opts: PrismorOptions): Required<PrismorOptions> {
  const agent = opts.agent ?? "vercel-ai";
  return {
    evalUrl: opts.evalUrl ?? "http://127.0.0.1:7071",
    subject: opts.subject ?? "",
    mode: opts.mode ?? "enforce",
    workspace: opts.workspace ?? process.cwd(),
    agent,
    agentName: opts.agentName ?? agent,
    eventType: opts.eventType ?? "shell",
  };
}

let _sessionCounter = 0;
function sessionId(): string {
  return `vercel-ai-${process.pid}-${++_sessionCounter}`;
}

/**
 * Wrap a single Vercel AI SDK tool so every call is evaluated by Prismor
 * before the tool body executes.
 *
 * @param toolName  The key name under which this tool is registered (used in telemetry).
 * @param tool      The tool object returned by the `tool()` helper.
 * @param opts      Prismor options (evalUrl, subject, mode, …).
 */
export function prismorTool<
  T extends { execute?: (...args: any[]) => any },
>(toolName: string, tool: T, opts: PrismorOptions = {}): T {
  if (!tool.execute) return tool;
  const resolved = resolveOpts(opts);
  const sid = sessionId();
  const original = tool.execute;

  const guarded = async (args: Record<string, unknown>, ctx: unknown) => {
    const decision = await evaluate(toolName, args, resolved, sid);
    if (!decision.allow) {  // honor the runtime decision (incl. org kill-switch), not the app-passed mode
      throw new PrismorBlocked(decision.reason ?? "policy violation", decision);
    }
    return original(args, ctx);
  };

  return { ...tool, execute: guarded };
}

/**
 * Wrap every tool in a record — the idiomatic Vercel AI SDK pattern.
 *
 * @example
 * const tools = prismorTools({ run_shell, search_web }, { subject: `user:${userId}` });
 * const result = await generateText({ model, tools, prompt });
 */
export function prismorTools<
  T extends Record<string, { execute?: (...args: any[]) => any }>,
>(tools: T, opts: PrismorOptions = {}): T {
  return Object.fromEntries(
    Object.entries(tools).map(([name, t]) => [name, prismorTool(name, t, opts)]),
  ) as T;
}
