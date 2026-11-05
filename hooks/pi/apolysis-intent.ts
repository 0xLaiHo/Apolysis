import { spawnSync } from "node:child_process";

interface PiToolCall {
  toolName: string;
  toolCallId: string;
  input: { command?: string } & Record<string, unknown>;
}

interface PiContext {
  cwd: string;
  sessionManager: { getSessionId(): string };
}

export default function apolysisIntent(pi: {
  on(event: "tool_call", handler: (event: PiToolCall, ctx: PiContext) => void): void;
}) {
  pi.on("tool_call", (event, ctx) => {
    try {
      const sessionId = ctx.sessionManager.getSessionId();
      if (!sessionId || !event.toolCallId) {
        throw new Error("missing call identity");
      }
      const args = [
        "intent",
        "hook",
        "--harness",
        "pi",
        "--output",
        process.env.APOLYSIS_INTENT_OUTPUT ?? ".apolysis/intent.pi.jsonl",
        "--workspace-root",
        ctx.cwd,
      ];
      if (process.env.APOLYSIS_SESSION_ID) {
        args.push("--session", process.env.APOLYSIS_SESSION_ID);
      }
      if (process.env.APOLYSIS_SHELL_BRIDGE) {
        args.push("--shell-bridge", process.env.APOLYSIS_SHELL_BRIDGE);
      }
      if (process.env.APOLYSIS_REASON_OUTPUT) {
        args.push("--reason-output", process.env.APOLYSIS_REASON_OUTPUT);
      }
      if (process.env.APOLYSIS_REASON_SUMMARY === "1") {
        args.push("--allow-reason-summary");
      }
      const result = spawnSync(process.env.APOLYSIS_BIN ?? "apolysis", args, {
        input: JSON.stringify({
          session_id: sessionId,
          hook_event_name: "tool_call",
          tool_name: event.toolName,
          tool_use_id: event.toolCallId,
          tool_input: event.input,
        }),
        encoding: "utf8",
        timeout: 10_000,
      });
      if (result.status !== 0) {
        throw new Error("intent hook failed");
      }
      const response: unknown = JSON.parse(result.stdout || "{}");
      if (!response || typeof response !== "object" || Array.isArray(response)) {
        throw new Error("invalid hook response");
      }
      if ("command" in response) {
        if (typeof response.command !== "string" || response.command.length === 0) {
          throw new Error("invalid hook response");
        }
        event.input.command = response.command;
      }
    } catch {
      // A rejected retry can still contain another call's marker. Fail open
      // with its original body, never with a stale attribution header.
      if (event.toolName === "bash" && typeof event.input?.command === "string") {
        event.input.command = clearFailedIntentMarkers(event.input.command);
      }
      // Never echo child stderr or tool input: either may contain private data.
      console.warn(
        "[apolysis] Pi intent recording failed; the tool continues without a new intent marker.",
      );
    }
  });
}

// Remove only complete markers, including inside our canonical optional bridge.
// Preserve its explicit shell boundary and never evaluate quoted shell text.
function clearFailedIntentMarkers(command: string): string {
  const frames: { kind: "shell" | "reason"; value: string }[] = [];
  for (;;) {
    command = command.replace(/^(?:# APOLYSIS_INTENT_ID=[0-9a-f]{32}\n)+/, "");
    const reason = command.match(/^# APOLYSIS_REASON_CODE=(?:unknown|inspect_context|verify_change|reproduce_issue|implement_change|diagnose_failure|gather_evidence)\n/);
    if (reason) {
      frames.push({ kind: "reason", value: reason[0] });
      command = command.slice(reason[0].length);
      continue;
    }
    const match = command.match(/^((?:\/usr)?\/bin\/(?:bash|zsh|dash|sh)) -c ('[\s\S]*')$/);
    if (!match) break;
    const decoded = match[2].slice(1, -1).replaceAll("'\\''", "'");
    const encoded = "'" + decoded.replaceAll("'", "'\\''") + "'";
    if (encoded !== match[2] || !/^# APOLYSIS_INTENT_ID=[0-9a-f]{32}\n/.test(decoded)) break;
    frames.push({ kind: "shell", value: match[1] });
    command = decoded;
  }
  for (const frame of frames.reverse()) {
    command = frame.kind === "reason"
      ? frame.value + command
      : frame.value + " -c '" + command.replaceAll("'", "'\\''") + "'";
  }
  return command;
}
