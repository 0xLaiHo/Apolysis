import { spawnSync } from "node:child_process";

export default function apolysisIntent(pi: {
  on(event: "tool_call", handler: (event: PiToolCall) => Promise<void> | void): void;
}) {
  pi.on("tool_call", (event) => {
    const command = typeof event.input?.command === "string" ? event.input.command : undefined;
    const result = spawnSync(
      process.env.APOLYSIS_BIN ?? "apolysis",
      [
        "intent",
        "hook",
        "--harness",
        "pi",
        "--output",
        process.env.APOLYSIS_INTENT_OUTPUT ?? ".apolysis/intent.pi.jsonl",
        "--workspace-root",
        process.cwd(),
      ],
      {
        input: JSON.stringify({
          session_id: event.sessionId ?? "pi",
          hook_event_name: "tool_call",
          tool_name: event.toolName,
          tool_use_id: event.toolCallId,
          tool_input: event.input ?? {},
        }),
        encoding: "utf8",
      },
    );
    if (result.status !== 0 || !command) {
      return;
    }
    const response = JSON.parse(result.stdout || "{}") as { command?: string };
    if (typeof response.command === "string") {
      event.input.command = response.command;
    }
  });
}

interface PiToolCall {
  toolName: string;
  toolCallId: string;
  sessionId?: string;
  input: { command?: string } & Record<string, unknown>;
}
