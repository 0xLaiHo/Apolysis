import assert from "node:assert/strict";
import childProcess from "node:child_process";
import { syncBuiltinESMExports } from "node:module";
import { after, beforeEach, test } from "node:test";

const originalSpawn = childProcess.spawnSync;
const originalWarn = console.warn;
const originalSession = process.env.APOLYSIS_SESSION_ID;
const originalReasonOutput = process.env.APOLYSIS_REASON_OUTPUT;
const originalReasonSummary = process.env.APOLYSIS_REASON_SUMMARY;
const originalShellBridge = process.env.APOLYSIS_SHELL_BRIDGE;
let calls = [];
let warnings = [];
let result;
let spawnError;
childProcess.spawnSync = (binary, args, options) => {
  if (spawnError) throw spawnError;
  calls.push({ binary, args, options, payload: JSON.parse(options.input) });
  return result;
};
syncBuiltinESMExports();
console.warn = (message) => warnings.push(message);
const { default: installPi } = await import("../pi/apolysis-intent.ts");
const { default: installOpenCode } = await import("../opencode/apolysis-intent.ts");

beforeEach(() => {
  calls = [];
  warnings = [];
  spawnError = undefined;
  result = { status: 0, stdout: JSON.stringify({ command: "# marker\nls" }), stderr: "" };
  delete process.env.APOLYSIS_SESSION_ID;
  delete process.env.APOLYSIS_REASON_OUTPUT;
  delete process.env.APOLYSIS_REASON_SUMMARY;
  delete process.env.APOLYSIS_SHELL_BRIDGE;
});
after(() => {
  childProcess.spawnSync = originalSpawn;
  syncBuiltinESMExports();
  console.warn = originalWarn;
  if (originalSession === undefined) delete process.env.APOLYSIS_SESSION_ID;
  else process.env.APOLYSIS_SESSION_ID = originalSession;
  if (originalReasonOutput === undefined) delete process.env.APOLYSIS_REASON_OUTPUT;
  else process.env.APOLYSIS_REASON_OUTPUT = originalReasonOutput;
  if (originalReasonSummary === undefined) delete process.env.APOLYSIS_REASON_SUMMARY;
  else process.env.APOLYSIS_REASON_SUMMARY = originalReasonSummary;
  if (originalShellBridge === undefined) delete process.env.APOLYSIS_SHELL_BRIDGE;
  else process.env.APOLYSIS_SHELL_BRIDGE = originalShellBridge;
});

function piHandler() {
  let handler;
  installPi({ on: (event, callback) => { assert.equal(event, "tool_call"); handler = callback; } });
  return handler;
}
const piContext = { cwd: "/workspace", sessionManager: { getSessionId: () => "real-pi-session" } };

// These shapes deliberately have no Pi event.sessionId and no invented OpenCode id.
test("Pi reads real context identity and retains unrelated input fields", () => {
  process.env.APOLYSIS_SESSION_ID = "capture-session";
  const event = { toolName: "bash", toolCallId: "parent/1", input: { command: "ls", timeout: 7 } };
  piHandler()(event, piContext);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].payload.session_id, "real-pi-session");
  assert.equal(calls[0].payload.tool_use_id, "parent/1");
  assert.equal(calls[0].args[calls[0].args.indexOf("--workspace-root") + 1], "/workspace");
  assert.equal(calls[0].args[calls[0].args.indexOf("--session") + 1], "capture-session");
  assert.deepEqual(event.input, { command: "# marker\nls", timeout: 7 });
  assert.equal(warnings.length, 0);
});

test("OpenCode uses before-execution output args and native call identity", async () => {
  const output = { args: { command: "ls", description: "retained" } };
  await installOpenCode()["tool.execute.before"](
    { tool: "bash", sessionID: "native-opencode", callID: "real-call" }, output,
  );
  assert.equal(calls.length, 1);
  assert.equal(calls[0].payload.session_id, "native-opencode");
  assert.equal(calls[0].payload.tool_use_id, "real-call");
  assert.deepEqual(output.args, { command: "# marker\nls", description: "retained" });
  assert.equal(calls[0].args.includes("--session"), false);
  assert.equal(calls[0].args[calls[0].args.indexOf("--workspace-root") + 1], process.cwd());
});

test("OpenCode uses its native project context when it differs from launcher cwd", async () => {
  const nativeDirectory = "/workspace/native project";
  const output = { args: { command: "ls", description: "retained" } };
  await installOpenCode({ directory: nativeDirectory })["tool.execute.before"](
    { tool: "bash", sessionID: "native-opencode", callID: "real-call" }, output,
  );
  assert.equal(calls[0].args[calls[0].args.indexOf("--workspace-root") + 1], nativeDirectory);
  assert.deepEqual(output.args, { command: "# marker\nls", description: "retained" });
  assert.equal(warnings.length, 0);
});

test("missing product identity produces a diagnostic without an invented id", async () => {
  const event = { toolName: "bash", toolCallId: "call", input: { command: "ls" } };
  piHandler()(event, { cwd: "/work", sessionManager: { getSessionId: () => undefined } });
  const output = { args: { command: "ls" } };
  await installOpenCode()["tool.execute.before"]({ tool: "bash", sessionID: "native" }, output);
  assert.equal(calls.length, 0);
  assert.equal(warnings.length, 2);
  assert.equal(event.input.command, "ls");
  assert.equal(output.args.command, "ls");
});

test("child failures and malformed responses never expose raw input or stderr", async () => {
  for (const failure of [
    { status: 1, stdout: "", stderr: "DO_NOT_LOG_CHILD_SECRET" },
    { status: 0, stdout: "DO_NOT_LOG_CHILD_SECRET", stderr: "" },
    { status: 0, stdout: "null", stderr: "" },
  ]) {
    result = failure;
    const event = { toolName: "bash", toolCallId: "call", input: { command: "DO_NOT_LOG_COMMAND" } };
    piHandler()(event, piContext);
    const output = { args: { command: "DO_NOT_LOG_COMMAND" } };
    await installOpenCode()["tool.execute.before"](
      { tool: "bash", sessionID: "native", callID: "call" }, output,
    );
    assert.equal(event.input.command, "DO_NOT_LOG_COMMAND");
    assert.equal(output.args.command, "DO_NOT_LOG_COMMAND");
  }
  assert.equal(warnings.length, 6);
  assert.equal(warnings.join(" ").includes("DO_NOT_LOG"), false);
});

test("semantic-only responses keep tool input unchanged", () => {
  result = { status: 0, stdout: "{}", stderr: "" };
  const event = { toolName: "read", toolCallId: "call", input: { path: "/private" } };
  piHandler()(event, piContext);
  assert.deepEqual(event.input, { path: "/private" });
  assert.equal(warnings.length, 0);
});


test("failed bridge calls discard all complete stale headers without changing the body", async () => {
  const header = "# APOLYSIS_INTENT_ID=0123456789abcdef0123456789abcdef\n";
  const other = "# APOLYSIS_INTENT_ID=fedcba9876543210fedcba9876543210\n";
  const body = "printf 'DO_NOT_LOG_COMMAND'\nprintf second";
  const failures = [
    { result: { status: 2, stdout: "", stderr: "conflicting identity DO_NOT_LOG" } },
    { result: { status: null, stdout: "", stderr: "DO_NOT_LOG", error: new Error("timeout DO_NOT_LOG") } },
    { error: new Error("spawn failed DO_NOT_LOG") },
    { result: { status: 0, stdout: "DO_NOT_LOG_INVALID_JSON", stderr: "" } },
    { result: { status: 0, stdout: JSON.stringify({ command: "" }), stderr: "" } },
    { result: { status: 0, stdout: JSON.stringify({ command: 42 }), stderr: "" } },
  ];
  const cases = [
    [header + body, body],
    [header + other + body, body],
    [header, ""],
    [body, body],
    ["", ""],
    ["# APOLYSIS_INTENT_ID=bad\n" + header + body, "# APOLYSIS_INTENT_ID=bad\n" + header + body],
    [header.trimEnd(), header.trimEnd()],
    [" # APOLYSIS_INTENT_ID=0123456789abcdef0123456789abcdef\n" + body,
      " # APOLYSIS_INTENT_ID=0123456789abcdef0123456789abcdef\n" + body],
  ];
  for (const failure of failures) {
    result = failure.result;
    spawnError = failure.error;
    for (const [original, expected] of cases) {
      const event = { toolName: "bash", toolCallId: "new-call", input: { command: original, timeout: 7 } };
      piHandler()(event, piContext);
      const output = { args: { command: original, description: "DO_NOT_LOG_DESCRIPTION" } };
      await installOpenCode()["tool.execute.before"](
        { tool: "bash", sessionID: "native", callID: "new-call" }, output,
      );
      assert.deepEqual(event.input, { command: expected, timeout: 7 });
      assert.deepEqual(output.args, { command: expected, description: "DO_NOT_LOG_DESCRIPTION" });
    }
    const missingCommand = { toolName: "read", toolCallId: "new-call", input: { path: "/private" } };
    piHandler()(missingCommand, piContext);
    assert.deepEqual(missingCommand.input, { path: "/private" });
    const output = { args: { path: "/private" } };
    await installOpenCode()["tool.execute.before"](
      { tool: "read", sessionID: "native", callID: "new-call" }, output,
    );
    assert.deepEqual(output.args, { path: "/private" });
  }
  assert.equal(warnings.length, failures.length * (cases.length + 1) * 2);
  assert.equal(warnings.join(" ").includes("DO_NOT_LOG"), false);
});

test("successful no-rewrite responses do not alter commands", async () => {
  result = { status: 0, stdout: "{}", stderr: "" };
  const original = "# APOLYSIS_INTENT_ID=0123456789abcdef0123456789abcdef\nprintf safe";
  const event = { toolName: "custom_bash", toolCallId: "call", input: { command: original } };
  piHandler()(event, piContext);
  const output = { args: { command: original } };
  await installOpenCode()["tool.execute.before"](
    { tool: "custom_bash", sessionID: "native", callID: "call" }, output,
  );
  assert.equal(event.input.command, original);
  assert.equal(output.args.command, original);
  assert.equal(warnings.length, 0);
});


test("reason options are explicit and do not modify native tool schemas", async () => {
  process.env.APOLYSIS_REASON_OUTPUT = "/private/DO_NOT_LOG/reasons.jsonl";
  process.env.APOLYSIS_REASON_SUMMARY = "1";
  result = { status: 0, stdout: "{}", stderr: "" };
  const input = { command: "# APOLYSIS_REASON_CODE=verify_change\nprintf safe", description: "DO_NOT_LOG_DESCRIPTION" };
  const event = { toolName: "bash", toolCallId: "call", input: { ...input } };
  piHandler()(event, piContext);
  const output = { args: { ...input } };
  await installOpenCode()["tool.execute.before"](
    { tool: "bash", sessionID: "native", callID: "call" }, output,
  );
  for (const call of calls) {
    assert.equal(call.args[call.args.indexOf("--reason-output") + 1], process.env.APOLYSIS_REASON_OUTPUT);
    assert.equal(call.args.includes("--allow-reason-summary"), true);
    assert.deepEqual(call.payload.tool_input, input);
    assert.equal("apolysis_reason" in call.payload, false);
  }
  assert.deepEqual(event.input, input);
  assert.deepEqual(output.args, input);
  assert.equal(warnings.length, 0);
});

test("reason summary stays disabled by default and for values other than one", async () => {
  result = { status: 0, stdout: "{}", stderr: "" };
  for (const option of [undefined, "", "0", "true"]) {
    if (option === undefined) delete process.env.APOLYSIS_REASON_SUMMARY;
    else process.env.APOLYSIS_REASON_SUMMARY = option;
    piHandler()({ toolName: "read", toolCallId: "call", input: {} }, piContext);
    await installOpenCode()["tool.execute.before"](
      { tool: "read", sessionID: "native", callID: "call" }, { args: {} },
    );
  }
  assert.equal(calls.length, 8);
  for (const call of calls) {
    assert.equal(call.args.includes("--reason-output"), false);
    assert.equal(call.args.includes("--allow-reason-summary"), false);
  }
});

test("reason options never expose private output paths or metadata on failure", async () => {
  process.env.APOLYSIS_REASON_OUTPUT = "/private/DO_NOT_LOG/reasons.jsonl";
  process.env.APOLYSIS_REASON_SUMMARY = "1";
  spawnError = new Error("DO_NOT_LOG spawn args or tool metadata");
  piHandler()({ toolName: "bash", toolCallId: "call", input: { description: "DO_NOT_LOG" } }, piContext);
  await installOpenCode()["tool.execute.before"](
    { tool: "bash", sessionID: "native", callID: "call" }, { args: { description: "DO_NOT_LOG" } },
  );
  assert.equal(warnings.length, 2);
  assert.equal(warnings.join(" ").includes("DO_NOT_LOG"), false);
});


test("shell bridge is forwarded only when explicitly selected", async () => {
  result = { status: 0, stdout: "{}", stderr: "" };
  for (const shell of [undefined, "/bin/bash"]) {
    if (shell) process.env.APOLYSIS_SHELL_BRIDGE = shell;
    else delete process.env.APOLYSIS_SHELL_BRIDGE;
    piHandler()({ toolName: "bash", toolCallId: "call", input: {command: "true"} }, piContext);
    await installOpenCode()["tool.execute.before"]({tool: "bash", sessionID: "native", callID: "call"}, {args: {command: "true"}});
    for (const call of calls.slice(-2)) {
      assert.equal(call.args.includes("--shell-bridge"), Boolean(shell));
      if (shell) assert.equal(call.args[call.args.indexOf("--shell-bridge") + 1], shell);
    }
  }
});

test("failed canonical bridge retries cannot execute stale nested intent markers", async () => {
  const quote = value => "'" + value.replaceAll("'", "'\\''") + "'";
  const wrap = value => "/bin/bash -c " + quote(value);
  const marker = "# APOLYSIS_INTENT_ID=0123456789abcdef0123456789abcdef\n";
  const body = "printf '%s' \"a'b\"";
  const command = wrap(marker + marker + wrap(marker + body));
  result = {status: 1, stdout: "", stderr: "DO_NOT_LOG"};
  const event = {toolName:"bash",toolCallId:"call",input:{command}};
  piHandler()(event, piContext);
  const output = {args:{command}};
  await installOpenCode()["tool.execute.before"]({tool:"bash",sessionID:"native",callID:"call"},output);
  assert.equal(event.input.command, wrap(wrap(body)));
  assert.equal(output.args.command, wrap(wrap(body)));
  assert.equal(warnings.join(" ").includes("DO_NOT_LOG"), false);
});

test("failed bash calls clear markers through known reason headers without changing reasons", async () => {
  const quote = value => "'" + value.replaceAll("'", "'\\''") + "'";
  const wrap = value => "/bin/bash -c " + quote(value);
  const marker = "# APOLYSIS_INTENT_ID=0123456789abcdef0123456789abcdef\n";
  const reason = "# APOLYSIS_REASON_CODE=verify_change\n";
  const body = "printf '%s' \"DO_NOT_LOG'a\"";
  for (const [command, expected] of [
    [reason + marker + body, reason + body],
    [reason + wrap(marker + body), reason + wrap(body)],
    [wrap(marker + reason + reason + wrap(marker + body)), wrap(reason + reason + wrap(body))],
    [reason + body, reason + body],
    ["# APOLYSIS_REASON_CODE=unsupported\n" + marker + body, "# APOLYSIS_REASON_CODE=unsupported\n" + marker + body],
  ]) {
    for (const failure of ["status", "timeout"]) {
      result = {status: 1, stdout: "", stderr: "DO_NOT_LOG"};
      spawnError = failure === "timeout" ? new Error("DO_NOT_LOG timeout") : undefined;
      const event = {toolName:"bash",toolCallId:"call",input:{command}};
      piHandler()(event, piContext);
      const output = {args:{command}};
      await installOpenCode()["tool.execute.before"]({tool:"bash",sessionID:"native",callID:"call"},output);
      assert.equal(event.input.command, expected);
      assert.equal(output.args.command, expected);
    }
  }
  assert.equal(warnings.join(" ").includes("DO_NOT_LOG"), false);
});

test("failed non-bash tools preserve marker-shaped command data byte for byte", async () => {
  const marker = "# APOLYSIS_INTENT_ID=0123456789abcdef0123456789abcdef\n";
  const reason = "# APOLYSIS_REASON_CODE=verify_change\n";
  for (const tool of ["read", "mcp_remote_exec", "shell", "Bash"]) {
    for (const command of [marker + "DO_NOT_LOG", reason + marker + "DO_NOT_LOG", "/bin/bash -c '" + marker + "DO_NOT_LOG'"]) {
      for (const failure of ["status", "exception"]) {
        result = {status: 1, stdout: "", stderr: "DO_NOT_LOG"};
        spawnError = failure === "exception" ? new Error("DO_NOT_LOG") : undefined;
        const event = {toolName:tool,toolCallId:"call",input:{command}};
        piHandler()(event, piContext);
        const output = {args:{command}};
        await installOpenCode()["tool.execute.before"]({tool,sessionID:"native",callID:"call"},output);
        assert.equal(event.input.command, command);
        assert.equal(output.args.command, command);
      }
    }
  }
  assert.equal(warnings.join(" ").includes("DO_NOT_LOG"), false);
});
