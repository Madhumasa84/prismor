/**
 * Prismor Warden adapter for the Vercel AI SDK.
 *
 * Wraps tool `execute` functions to call the Warden eval-server
 * (immunity eval-server) before the tool body runs. A denied call
 * throws WardenBlocked (enforce mode) or logs and proceeds (observe mode).
 *
 * Quick start:
 *   const tools = wardenTools({ run_shell, search_web }, { subject: `user:${userId}` });
 *   const result = await generateText({ model, tools, prompt });
 */

export interface WardenOptions {
  /** URL of the running eval-server. Default: http://127.0.0.1:7071 */
  evalUrl?: string;
  /** Subject for per-user attribution: "user:alice" or "user=alice;team=data" */
  subject?: string;
  /** "enforce" blocks denied calls; "observe" logs only. Default: "enforce" */
  mode?: "enforce" | "observe";
  /** Workspace path forwarded to the policy engine. Default: process.cwd() */
  workspace?: string;
  /** Agent identifier recorded in telemetry. Default: "vercel-ai" */
  agent?: string;
  /**
   * Map tool argument keys to a Warden event type.
   * Default: "shell" (args serialised to command string).
   * Use "network" for URL-fetching tools, "file_write" for file-writing tools.
   */
  eventType?: "shell" | "network" | "file_write" | "file_read" | "tool_result";
}

export interface WardenDecision {
  allow: boolean;
  reason: string | null;
  findings: unknown[];
  blocking: unknown | null;
  subject: { user_id: string | null; team_id: string | null } | null;
}

export class WardenBlocked extends Error {
  decision: WardenDecision;
  constructor(reason: string, decision: WardenDecision) {
    super(`Blocked by Prismor Warden: ${reason}`);
    this.name = "WardenBlocked";
    this.decision = decision;
  }
}

async function evaluate(
  toolName: string,
  args: Record<string, unknown>,
  opts: Required<WardenOptions>,
  sessionId: string,
): Promise<WardenDecision> {
  const res = await fetch(`${opts.evalUrl}/v1/evaluate`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(opts.subject ? { "X-Warden-Subject": opts.subject } : {}),
    },
    body: JSON.stringify({
      tool_name: toolName,
      arguments: args,
      event_type: opts.eventType,
      agent: opts.agent,
      mode: opts.mode,
      session_id: sessionId,
      subject: opts.subject,
      workspace: opts.workspace,
    }),
  });

  if (!res.ok) {
    // Server error — fail open (don't break the agent on infrastructure issues)
    console.warn(`[prismor-warden] eval-server returned ${res.status} — failing open`);
    return { allow: true, reason: null, findings: [], blocking: null, subject: null };
  }
  return res.json() as Promise<WardenDecision>;
}

function resolveOpts(opts: WardenOptions): Required<WardenOptions> {
  return {
    evalUrl: opts.evalUrl ?? "http://127.0.0.1:7071",
    subject: opts.subject ?? "",
    mode: opts.mode ?? "enforce",
    workspace: opts.workspace ?? process.cwd(),
    agent: opts.agent ?? "vercel-ai",
    eventType: opts.eventType ?? "shell",
  };
}

let _sessionCounter = 0;
function sessionId(): string {
  return `vercel-ai-${process.pid}-${++_sessionCounter}`;
}

/**
 * Wrap a single Vercel AI SDK tool so every call is evaluated by Warden
 * before the tool body executes.
 *
 * @param toolName  The key name under which this tool is registered (used in telemetry).
 * @param tool      The tool object returned by the `tool()` helper.
 * @param opts      Warden options (evalUrl, subject, mode, …).
 */
export function wardenTool<
  T extends { execute?: (...args: any[]) => any },
>(toolName: string, tool: T, opts: WardenOptions = {}): T {
  if (!tool.execute) return tool;
  const resolved = resolveOpts(opts);
  const sid = sessionId();
  const original = tool.execute;

  const guarded = async (args: Record<string, unknown>, ctx: unknown) => {
    const decision = await evaluate(toolName, args, resolved, sid);
    if (!decision.allow && resolved.mode === "enforce") {
      throw new WardenBlocked(decision.reason ?? "policy violation", decision);
    }
    return original(args, ctx);
  };

  return { ...tool, execute: guarded };
}

/**
 * Wrap every tool in a record — the idiomatic Vercel AI SDK pattern.
 *
 * @example
 * const tools = wardenTools({ run_shell, search_web }, { subject: `user:${userId}` });
 * const result = await generateText({ model, tools, prompt });
 */
export function wardenTools<
  T extends Record<string, { execute?: (...args: any[]) => any }>,
>(tools: T, opts: WardenOptions = {}): T {
  return Object.fromEntries(
    Object.entries(tools).map(([name, t]) => [name, wardenTool(name, t, opts)]),
  ) as T;
}
