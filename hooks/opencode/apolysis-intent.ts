import { spawnSync } from "node:child_process";

type ToolInput = { tool: string; sessionID: string; callID?: string };
type ToolOutput = { args: { command?: string } & Record<string, unknown> };

export default function apolysisIntent() {
  return {
    "tool.execute.before": async (input: ToolInput, output: ToolOutput) => {
      const result = spawnSync(
        process.env.APOLYSIS_BIN ?? "apolysis",
        [
          "intent",
          "hook",
          "--harness",
          "opencode",
          "--output",
          process.env.APOLYSIS_INTENT_OUTPUT ?? ".apolysis/intent.opencode.jsonl",
          "--workspace-root",
          process.cwd(),
        ],
        {
          input: JSON.stringify({
            session_id: input.sessionID,
            hook_event_name: "tool.execute.before",
            tool_name: input.tool,
            tool_use_id: input.callID ?? "missing",
            tool_input: output.args,
          }),
          encoding: "utf8",
        },
      );
      if (result.status !== 0) {
        return;
      }
      const response = JSON.parse(result.stdout || "{}") as { command?: string };
      if (typeof response.command === "string") {
        output.args.command = response.command;
      }
    },
  };
}
