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
      if (typeof event.input?.command === "string") {
        event.input.command = event.input.command.replace(
          /^(?:# APOLYSIS_INTENT_ID=[0-9a-f]{32}\n)+/,
          "",
        );
      }
      // Never echo child stderr or tool input: either may contain private data.
      console.warn(
        "[apolysis] Pi intent recording failed; the tool continues without a new intent marker.",
      );
    }
  });
}
