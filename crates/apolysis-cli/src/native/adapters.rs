// SPDX-License-Identifier: Apache-2.0

//! Native CLI integration. The application's original arguments remain one
//! unchanged suffix; only documented runtime hook/plugin switches are added.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

const PI_EXTENSION: &str = include_str!("../../../../hooks/pi/apolysis-intent.ts");
const OPENCODE_PLUGIN: &str = include_str!("../../../../hooks/opencode/apolysis-intent.ts");

pub(super) struct PrepareRequest<'a> {
    pub product: &'a str,
    pub apolysis: &'a Path,
    pub executable: &'a Path,
    pub native_args: &'a [String],
    /// The launch cwd. Native -C/--dir options are still interpreted by the app.
    pub workspace: &'a Path,
    pub control: &'a Path,
    pub evidence: &'a Path,
    pub session: &'a str,
    pub allow_reason_summary: bool,
    pub shell_bridge: Option<&'a str>,
}

#[derive(Debug)]
pub(super) struct Plan {
    pub executable: PathBuf,
    pub args: Vec<String>,
    pub environment: Vec<(String, String)>,
    /// Resolved observation metadata, not a replacement for the launch cwd.
    pub workspace: PathBuf,
    pub coverage_notes: Vec<String>,
}

pub(super) fn executable_name(product: &str) -> Result<&'static str, String> {
    match product {
        "claude" => Ok("claude"),
        "codex" => Ok("codex"),
        "pi" => Ok("pi"),
        "opencode" => Ok("opencode"),
        "cursor" => Ok("cursor-agent"),
        _ => Err("unsupported native agent; choose codex, claude, cursor, pi, or opencode".into()),
    }
}

/// Only unambiguous informational invocations bypass observation. In particular,
/// a prompt or an option value equal to --help is not consumed by Apolysis.
pub(super) fn informational_args(args: &[String]) -> bool {
    matches!(args, [one] if matches!(one.as_str(), "--help" | "-h" | "--version" | "-v" | "-V"))
        || (args.first().is_some_and(|arg| arg == "help")
            && args[1..].iter().all(|arg| !arg.starts_with('-')))
}

pub(super) fn prepare(request: &PrepareRequest<'_>) -> Result<Plan, String> {
    executable_name(request.product)?;
    if request.session.is_empty() || request.session.contains('\0') {
        return Err("native capture session is empty or invalid".into());
    }
    for path in [
        request.apolysis,
        request.executable,
        request.workspace,
        request.control,
        request.evidence,
    ] {
        path_text(path)?;
    }
    if let Some(shell) = request.shell_bridge {
        if !matches!(
            shell,
            "/bin/sh"
                | "/bin/bash"
                | "/bin/dash"
                | "/bin/zsh"
                | "/usr/bin/sh"
                | "/usr/bin/bash"
                | "/usr/bin/dash"
                | "/usr/bin/zsh"
        ) || !Path::new(shell).is_file()
        {
            return Err(
                "native shell bridge requires an installed supported absolute shell".into(),
            );
        }
    }

    let options = native_options(request.product, request.native_args);
    reject_incompatible_modes(request.product, &options)?;
    reject_detached_subcommand(request.product, request.native_args)?;
    let mut notes = vec![
        "Native UI, tools, permission prompts, credentials and application history remain managed by the selected application.".into(),
        "Tool descriptions are not verified motives; missing declared reasons remain unknown. Remote or built-in non-shell tools may be semantic-only.".into(),
        "Native policy, hook trust, or other hooks may prevent or change this hook; absence of declarations is a coverage gap.".into(),
    ];
    if request.shell_bridge.is_some() {
        notes.push("The explicitly selected shell bridge creates a shell inside each supported shell tool call; shell state changes do not propagate to the application's outer shell.".into());
    } else {
        notes.push("Marker-only mode does not add a tool shell. Native eval or command wrappers can prevent exact kernel attribution.".into());
    }
    let workspace = resolved_workspace(request, &options, &mut notes);
    let mut prefix = Vec::new();
    let mut environment = Vec::new();
    match request.product {
        "claude" => {
            let plugin = create_plugin(request, "claude", &hook_command(request)?)?;
            prefix.extend(["--plugin-dir".into(), path_text(&plugin)?]);
        }
        "cursor" => {
            let plugin = create_plugin(request, "cursor", &hook_command(request)?)?;
            prefix.extend(["--plugin-dir".into(), path_text(&plugin)?]);
        }
        "codex" => {
            // Codex merges hook sources from active config layers. CLI overrides
            // are their own session layer; user/project hooks remain loaded.
            // Explicit native overrides of the same session layer are rejected
            // below rather than silently replacing either hook definition.
            let command = serde_json::to_string(&hook_command(request)?)
                .map_err(|_| "cannot encode native hook command")?;
            // Clap rejects duplicate boolean switches; retain the native
            // caller's explicit flag rather than injecting another copy.
            if !options.iter().any(|option| option.name == "--no-daemon") {
                prefix.push("--no-daemon".into());
            }
            prefix.extend([
                "--enable".into(),
                "hooks".into(),
                "--config".into(),
                format!("hooks.PreToolUse=[{{matcher=\".*\",hooks=[{{type=\"command\",command={command}}}]}}]"),
            ]);
            notes.push("Codex is launched with --no-daemon so local execution stays in this process tree. Review the new hook in native /hooks if requested; Apolysis does not bypass hook trust.".into());
            notes.push("Codex hosted WebSearch does not use the local PreToolUse path and is not captured as a tool declaration by this integration.".into());
        }
        "pi" => {
            let extension = request.control.join("apolysis-pi.ts");
            private_file(&extension, PI_EXTENSION.as_bytes())?;
            prefix.extend(["--extension".into(), path_text(&extension)?]);
            environment = extension_environment(request)?;
        }
        "opencode" => {
            let plugin = request.control.join("apolysis-opencode");
            private_dir(&plugin)?;
            private_file(&plugin.join("index.ts"), OPENCODE_PLUGIN.as_bytes())?;
            if !options.iter().any(|option| option.name == "--standalone") {
                prefix.push("--standalone".into());
            }
            let content = match std::env::var("OPENCODE_CONFIG_CONTENT") {
                Ok(value) => Some(value),
                Err(std::env::VarError::NotPresent) => None,
                Err(_) => return Err("OPENCODE_CONFIG_CONTENT must be valid UTF-8".into()),
            };
            let merged = opencode_content(content.as_deref(), &file_url(&plugin)?)?;
            environment = extension_environment(request)?;
            environment.push(("OPENCODE_CONFIG_CONTENT".into(), merged));
        }
        _ => unreachable!(),
    }
    prefix.extend_from_slice(request.native_args);
    Ok(Plan {
        executable: request.executable.to_path_buf(),
        args: prefix,
        environment,
        workspace,
        coverage_notes: notes,
    })
}

fn path_text(path: &Path) -> Result<String, String> {
    path.to_str()
        .filter(|text| path.is_absolute() && !text.contains('\0'))
        .map(str::to_owned)
        .ok_or_else(|| {
            "native integration paths must be absolute UTF-8 paths without NUL bytes".into()
        })
}

fn quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn hook_command(request: &PrepareRequest<'_>) -> Result<String, String> {
    let args = [
        path_text(request.apolysis)?,
        "intent".into(),
        "hook".into(),
        "--harness".into(),
        request.product.into(),
        "--session".into(),
        request.session.into(),
        "--output".into(),
        path_text(&request.evidence.join("intent.jsonl"))?,
        "--reason-output".into(),
        path_text(&request.evidence.join("intent.jsonl.reasons.jsonl"))?,
    ];
    let mut command = args
        .iter()
        .map(|arg| quote(arg))
        .collect::<Vec<_>>()
        .join(" ");
    // Hook source cwd differs for plugins. Native workspace variables retain
    // the application's -C/resume/worktree choice without reinterpreting args.
    command.push_str(" --workspace-root ");
    command.push_str(match request.product {
        "claude" => "\"${CLAUDE_PROJECT_DIR:-$PWD}\"",
        "cursor" => "\"${CURSOR_PROJECT_DIR:-$PWD}\"",
        _ => "\"$PWD\"",
    });
    if request.allow_reason_summary {
        command.push_str(" --allow-reason-summary");
    }
    if let Some(shell) = request.shell_bridge {
        command.push_str(" --shell-bridge ");
        command.push_str(&quote(shell));
    }
    Ok(command)
}

fn private_file(path: &Path, data: &[u8]) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| "cannot create native integration file")?;
    file.write_all(data)
        .map_err(|_| "cannot write native integration file".into())
}

fn private_dir(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new()
        .mode(0o700)
        .create(path)
        .map_err(|_| "cannot create native integration directory".into())
}

fn create_plugin(
    request: &PrepareRequest<'_>,
    product: &str,
    command: &str,
) -> Result<PathBuf, String> {
    let plugin = request.control.join(format!("apolysis-{product}"));
    private_dir(&plugin)?;
    let manifest = plugin.join(format!(".{product}-plugin"));
    let hooks = plugin.join("hooks");
    private_dir(&manifest)?;
    private_dir(&hooks)?;
    private_file(
        &manifest.join("plugin.json"),
        b"{\"name\":\"apolysis-native-observe\",\"version\":\"1.0.0\",\"description\":\"Record tool declarations for this Apolysis capture\"}\n",
    )?;
    let value = if product == "claude" {
        json!({"hooks":{
            "UserPromptSubmit":[{"matcher":".*","hooks":[{"type":"command","command":command}]}],
            "PreToolUse":[{"matcher":".*","hooks":[{"type":"command","command":command}]}]
        }})
    } else {
        json!({"version":1,"hooks":{
            "beforeSubmitPrompt":[{"command":command}],
            "preToolUse":[{"command":command}],
            "beforeShellExecution":[{"command":command}]
        }})
    };
    let data = serde_json::to_vec(&value).map_err(|_| "cannot encode native hook configuration")?;
    private_file(&hooks.join("hooks.json"), &data)?;
    Ok(plugin)
}

fn extension_environment(request: &PrepareRequest<'_>) -> Result<Vec<(String, String)>, String> {
    Ok(vec![
        ("APOLYSIS_BIN".into(), path_text(request.apolysis)?),
        ("APOLYSIS_SESSION_ID".into(), request.session.into()),
        (
            "APOLYSIS_INTENT_OUTPUT".into(),
            path_text(&request.evidence.join("intent.jsonl"))?,
        ),
        (
            "APOLYSIS_REASON_OUTPUT".into(),
            path_text(&request.evidence.join("intent.jsonl.reasons.jsonl"))?,
        ),
        (
            "APOLYSIS_REASON_SUMMARY".into(),
            if request.allow_reason_summary {
                "1"
            } else {
                "0"
            }
            .into(),
        ),
        // An empty value must not inherit another run's explicit bridge. The
        // extension treats it as false, retaining the native default shell.
        (
            "APOLYSIS_SHELL_BRIDGE".into(),
            request.shell_bridge.unwrap_or("").into(),
        ),
    ])
}

fn file_url(path: &Path) -> Result<String, String> {
    let path = path_text(path)?;
    let mut url = String::from("file://");
    for byte in path.bytes() {
        if byte.is_ascii_alphanumeric() || b"/-._~".contains(&byte) {
            url.push(char::from(byte));
        } else {
            use std::fmt::Write;
            write!(&mut url, "%{byte:02X}").map_err(|_| "cannot encode plugin path")?;
        }
    }
    Ok(url)
}

fn opencode_content(existing: Option<&str>, plugin_url: &str) -> Result<String, String> {
    let mut value = match existing {
        Some(content) => serde_json::from_str::<Value>(content)
            .map_err(|_| "existing OPENCODE_CONFIG_CONTENT is not a valid JSON object")?,
        None => json!({}),
    };
    let object = value
        .as_object_mut()
        .ok_or("existing OPENCODE_CONFIG_CONTENT must be a JSON object")?;
    let key = if object.contains_key("plugins") && !object.contains_key("plugin") {
        "plugins"
    } else {
        "plugin"
    };
    let plugins = object.entry(key).or_insert_with(|| json!([]));
    let plugins = plugins
        .as_array_mut()
        .ok_or("existing OPENCODE_CONFIG_CONTENT plugin field must be an array")?;
    if !plugins
        .iter()
        .any(|entry| entry.as_str() == Some(plugin_url))
    {
        plugins.push(json!(plugin_url));
    }
    serde_json::to_string(&value).map_err(|_| "cannot encode native OpenCode configuration".into())
}

#[derive(Debug)]
struct NativeOption<'a> {
    name: &'a str,
    value: Option<&'a str>,
}

/// Read only integration-relevant flags. Native arguments are never normalized,
/// split, shell-evaluated, or serialized into a persisted launch manifest.
fn native_options<'a>(product: &str, args: &'a [String]) -> Vec<NativeOption<'a>> {
    let mut result = Vec::new();
    let mut index = 0;
    while let Some(arg) = args.get(index) {
        if arg == "--" {
            break;
        }
        if let Some((name, value)) = arg.split_once('=') {
            if name.starts_with("--") || (name.starts_with('-') && name.len() == 2) {
                result.push(NativeOption {
                    name,
                    value: Some(value),
                });
                index += 1;
                continue;
            }
        }
        if arg.starts_with('-') {
            if let Some((name, value)) = short_attached_option(product, arg) {
                result.push(NativeOption {
                    name,
                    value: Some(value),
                });
                index += 1;
                continue;
            }
            let consumes_value =
                consumes_next(product, arg, args.get(index + 1).map(String::as_str));
            let value = consumes_value
                .then(|| args.get(index + 1))
                .flatten()
                .map(String::as_str);
            result.push(NativeOption { name: arg, value });
            index += 1 + usize::from(value.is_some());
        } else {
            index += 1;
        }
    }
    result
}

fn short_attached_option<'a>(product: &str, arg: &'a str) -> Option<(&'a str, &'a str)> {
    if arg.starts_with("--") || arg.len() <= 2 || !arg.is_char_boundary(2) {
        return None;
    }
    // Pi has documented multi-letter short switches; they are not attached
    // values of -n, -t or -e.
    if product == "pi" && matches!(arg, "-ne" | "-nt" | "-nbt" | "-xt") {
        return None;
    }
    let (name, value) = arg.split_at(2);
    value_option(product, name).then_some((name, value.trim_start_matches('=')))
}

fn first_positional<'a>(product: &str, args: &'a [String]) -> Option<&'a str> {
    let mut index = 0;
    while let Some(arg) = args.get(index) {
        if arg == "--" {
            break;
        }
        if arg.starts_with('-') {
            let inline = arg.contains('=') || short_attached_option(product, arg).is_some();
            index += 1 + usize::from(
                !inline && consumes_next(product, arg, args.get(index + 1).map(String::as_str)),
            );
        } else {
            return Some(arg.as_str());
        }
    }
    None
}

fn reject_detached_subcommand(product: &str, args: &[String]) -> Result<(), String> {
    let first = first_positional(product, args);
    if matches!(
        (product, first),
        ("claude", Some("attach"))
            | ("codex", Some("cloud" | "queue" | "remote-control"))
            | ("opencode", Some("attach"))
            | ("cursor", Some("worker"))
    ) {
        return Err("the requested native subcommand executes through a detached or remote agent outside this local process-tree capture".into());
    }
    Ok(())
}

fn consumes_next(product: &str, name: &str, next: Option<&str>) -> bool {
    value_option(product, name)
        || (next.is_some_and(|value| !value.starts_with('-'))
            && match product {
                "claude" => matches!(
                    name,
                    "--resume"
                        | "-r"
                        | "--worktree"
                        | "-w"
                        | "--remote-control"
                        | "--debug"
                        | "-d"
                        | "--prompt-suggestions"
                ),
                "cursor" => matches!(name, "--resume" | "--worktree" | "-w"),
                _ => false,
            })
}

fn value_option(product: &str, name: &str) -> bool {
    let common = ["--model", "--api-key", "--plugin-dir", "--add-dir"];
    if common.contains(&name) {
        return true;
    }
    match product {
        "claude" => [
            "--settings",
            "--setting-sources",
            "--append-system-prompt",
            "--system-prompt",
            "--system-prompt-file",
            "--append-system-prompt-file",
            "--permission-mode",
            "--permission-prompts",
            "--output-format",
            "--input-format",
            "--mcp-config",
            "--tools",
            "--allowedTools",
            "--allowed-tools",
            "--disallowedTools",
            "--disallowed-tools",
            "--effort",
            "--agent",
            "--agents",
            "--name",
            "-n",
            "--session-id",
            "--max-budget-usd",
            "--json-schema",
            "--fallback-model",
            "--betas",
            "--autocompact",
            "--debug-file",
            "--remote-control-session-name-prefix",
            "--system-prompt-snapshot",
        ]
        .contains(&name),
        "codex" => [
            "-c",
            "--config",
            "--enable",
            "--disable",
            "--remote",
            "--remote-auth-token-env",
            "-m",
            "-p",
            "--profile",
            "-s",
            "--sandbox",
            "-C",
            "--cd",
            "-a",
            "--ask-for-approval",
            "--local-provider",
            "--output-last-message",
            "-o",
            "--output-schema",
            "--color",
        ]
        .contains(&name),
        "cursor" => [
            "--workspace",
            "--mode",
            "--output-format",
            "--sandbox",
            "--endpoint",
            "-e",
            "--header",
            "-H",
            "--worktree-base",
        ]
        .contains(&name),
        "pi" => [
            "--provider",
            "--system-prompt",
            "--append-system-prompt",
            "--mode",
            "--session",
            "--session-id",
            "--session-dir",
            "--fork",
            "--name",
            "-n",
            "--models",
            "--tools",
            "-t",
            "--exclude-tools",
            "-xt",
            "--thinking",
            "--extension",
            "-e",
            "--skill",
            "--prompt-template",
            "--theme",
        ]
        .contains(&name),
        "opencode" => [
            "--dir",
            "--attach",
            "--server",
            "--log-level",
            "--port",
            "--hostname",
            "--mdns-domain",
            "--cors",
            "-m",
            "--session",
            "-s",
            "--prompt",
            "--agent",
            "--format",
            "--title",
            "--file",
            "-f",
            "--password",
            "--replay-limit",
        ]
        .contains(&name),
        _ => false,
    }
}

fn reject_incompatible_modes(product: &str, options: &[NativeOption<'_>]) -> Result<(), String> {
    for option in options {
        match (product, option.name) {
            ("claude", "--bare" | "--safe-mode") => return Err("Claude bare/safe mode disables the runtime hook; omit that native option for intent observation".into()),
            ("claude", "--cloud" | "--desktop" | "--bg" | "--background") => return Err("Claude cloud/desktop/background execution is outside this foreground local capture; use a local native invocation".into()),
            ("codex", "--remote") => return Err("Codex remote execution is outside this local process-tree capture".into()),
            ("codex", "--disable") if option.value.is_some_and(|v| matches!(v, "hooks" | "codex_hooks")) => return Err("native hooks cannot be disabled while collecting tool declarations".into()),
            ("codex", "--config" | "-c") if option.value.is_some_and(codex_hook_override) => return Err("native Codex hook/daemon config overrides conflict with this capture; keep those hooks in the original user/project config instead".into()),
            ("opencode", "--pure") if option.value != Some("false") => return Err("OpenCode --pure disables the runtime plugin required for intent observation".into()),
            ("opencode", "--attach" | "--server") => return Err("OpenCode --attach/--server executes in an existing server outside this local process-tree capture".into()),
            _ => {}
        }
    }
    Ok(())
}

fn codex_hook_override(value: &str) -> bool {
    let (key, setting) = value.split_once('=').unwrap_or((value, ""));
    let (key, setting) = (key.trim(), setting.trim());
    key == "hooks"
        || key.starts_with("hooks.")
        || (matches!(key, "features.hooks" | "features.codex_hooks") && setting != "true")
        || (key == "allow_managed_hooks_only" && setting != "false")
}

fn resolved_workspace(
    request: &PrepareRequest<'_>,
    options: &[NativeOption<'_>],
    notes: &mut Vec<String>,
) -> PathBuf {
    let names: &[&str] = match request.product {
        "codex" => &["-C", "--cd"],
        "cursor" => &["--workspace"],
        "opencode" => &["--dir"],
        _ => &[],
    };
    let selected = options
        .iter()
        .rev()
        .find(|option| names.contains(&option.name))
        .and_then(|option| option.value)
        .or_else(|| {
            if request.product != "opencode" {
                return None;
            }
            first_positional(request.product, request.native_args).filter(|value| {
                !matches!(
                    *value,
                    "completion"
                        | "acp"
                        | "mcp"
                        | "attach"
                        | "run"
                        | "debug"
                        | "providers"
                        | "auth"
                        | "agent"
                        | "upgrade"
                        | "uninstall"
                        | "serve"
                        | "web"
                        | "models"
                        | "stats"
                        | "export"
                        | "import"
                        | "github"
                        | "pr"
                        | "session"
                        | "plugin"
                        | "plug"
                        | "db"
                        | "help"
                )
            })
        });
    if options
        .iter()
        .any(|option| matches!(option.name, "--worktree" | "-w"))
    {
        notes.push("The native application chooses its worktree dynamically; launch workspace metadata may differ from the final native workspace.".into());
    }
    let Some(selected) = selected else {
        return request.workspace.to_path_buf();
    };
    let path = Path::new(selected);
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        request.workspace.join(path)
    };
    match path.canonicalize() {
        Ok(path) if path.is_dir() => path,
        _ => {
            notes.push("A native workspace option is resolved by the application; Apolysis could not resolve it in advance and retains launch workspace metadata.".into());
            request.workspace.to_path_buf()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    struct Fixture {
        root: tempfile::TempDir,
        workspace: PathBuf,
        control: PathBuf,
        evidence: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let root = tempfile::tempdir().unwrap();
            let workspace = root.path().join("work space's");
            let control = root.path().join("control");
            let evidence = root.path().join("evidence");
            for path in [&workspace, &control, &evidence] {
                fs::create_dir(path).unwrap();
            }
            Self {
                root,
                workspace,
                control,
                evidence,
            }
        }

        fn request<'a>(&'a self, product: &'a str, args: &'a [String]) -> PrepareRequest<'a> {
            PrepareRequest {
                product,
                apolysis: Path::new("/opt/apolysis's binary"),
                executable: Path::new("/usr/bin/native-agent"),
                native_args: args,
                workspace: &self.workspace,
                control: &self.control,
                evidence: &self.evidence,
                session: "capture-1",
                allow_reason_summary: false,
                shell_bridge: None,
            }
        }
    }

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|v| (*v).into()).collect()
    }

    #[test]
    fn product_selection_is_explicit_and_information_does_not_consume_values() {
        assert!(executable_name("claude").is_ok());
        assert_eq!(executable_name("cursor").unwrap(), "cursor-agent");
        assert!(executable_name("").is_err());
        assert!(informational_args(&args(&["--help"])));
        assert!(informational_args(&args(&["help", "exec"])));
        assert!(!informational_args(&args(&["--model", "--help"])));
        assert!(!informational_args(&args(&["--", "--help"])));
    }

    #[test]
    fn every_adapter_keeps_native_arguments_as_an_unchanged_suffix() {
        for product in ["claude", "codex", "cursor", "pi", "opencode"] {
            let fixture = Fixture::new();
            let native = args(&[
                "--model",
                "quoted value",
                "--",
                "--help",
                "a'b $()",
                "",
                "中文",
            ]);
            let plan = prepare(&fixture.request(product, &native)).unwrap();
            assert!(plan.args.ends_with(&native), "{product}");
            assert_eq!(plan.executable, Path::new("/usr/bin/native-agent"));
        }
    }

    #[test]
    fn claude_plugin_preserves_settings_tools_and_permission_arguments() {
        let fixture = Fixture::new();
        let native = args(&[
            "--settings",
            "my.json",
            "--tools",
            "default",
            "--permission-mode",
            "plan",
            "--mcp-config",
            "mcp.json",
            "--resume",
        ]);
        let plan = prepare(&fixture.request("claude", &native)).unwrap();
        assert_eq!(&plan.args[..1], &["--plugin-dir"]);
        assert_eq!(&plan.args[2..], &native);
        let plugin = Path::new(&plan.args[1]);
        let hooks: Value =
            serde_json::from_slice(&fs::read(plugin.join("hooks/hooks.json")).unwrap()).unwrap();
        let command = hooks["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
            .as_str()
            .unwrap();
        assert!(command.contains("${CLAUDE_PROJECT_DIR:-$PWD}"));
        assert!(!command.contains("--allow-reason-summary"));
        assert!(!command.contains("--shell-bridge"));
        assert!(plugin.join(".claude-plugin/plugin.json").is_file());
        assert_eq!(
            fs::metadata(plugin.join("hooks/hooks.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }

    #[test]
    fn cursor_plugin_records_both_events_without_project_mutation() {
        let fixture = Fixture::new();
        let native = args(&["--plugin-dir", "existing-plugin", "--mode", "ask"]);
        let plan = prepare(&fixture.request("cursor", &native)).unwrap();
        let plugin = Path::new(&plan.args[1]);
        let hooks: Value =
            serde_json::from_slice(&fs::read(plugin.join("hooks/hooks.json")).unwrap()).unwrap();
        assert!(hooks["hooks"]["preToolUse"].is_array());
        assert!(hooks["hooks"]["beforeShellExecution"].is_array());
        assert!(!fixture.workspace.join(".cursor").exists());
        assert_eq!(&plan.args[2..], &native);
    }

    #[test]
    fn codex_uses_session_hooks_and_no_shared_daemon_without_bypassing_trust() {
        let fixture = Fixture::new();
        let native = args(&["--profile", "my-profile", "resume", "--last"]);
        let plan = prepare(&fixture.request("codex", &native)).unwrap();
        assert_eq!(plan.args[0], "--no-daemon");
        assert!(plan.args[4].starts_with("hooks.PreToolUse="));
        assert_eq!(&plan.args[5..], &native);
        assert!(!plan.args.iter().any(|a| a.contains("bypass")));
        assert!(!fixture.workspace.join(".codex").exists());
    }

    #[test]
    fn codex_native_no_daemon_is_not_duplicated() {
        let fixture = Fixture::new();
        let native = args(&["--no-daemon", "--model", "native-model"]);
        let plan = prepare(&fixture.request("codex", &native)).unwrap();
        assert_eq!(
            plan.args.iter().filter(|arg| *arg == "--no-daemon").count(),
            1
        );
        assert!(plan.args.ends_with(&native));
    }

    #[test]
    fn pi_explicit_extension_survives_no_discovery_and_resets_stale_bridge_env() {
        let fixture = Fixture::new();
        let native = args(&[
            "--no-extensions",
            "-e",
            "my-extension.ts",
            "--provider",
            "local",
            "--model",
            "demo",
        ]);
        let plan = prepare(&fixture.request("pi", &native)).unwrap();
        assert_eq!(plan.args[0], "--extension");
        assert_eq!(&plan.args[2..], &native);
        assert!(plan
            .environment
            .contains(&("APOLYSIS_SHELL_BRIDGE".into(), "".into())));
        assert!(plan
            .environment
            .contains(&("APOLYSIS_REASON_SUMMARY".into(), "0".into())));
        assert!(fs::read_to_string(&plan.args[1])
            .unwrap()
            .contains("tool_call"));
    }

    #[test]
    fn opencode_merges_inline_configuration_without_losing_native_values() {
        let source = r#"{"model":"local/model","permission":{"bash":"ask"},"plugin":["existing"],"mcp":{"demo":{"enabled":false}}}"#;
        let merged: Value =
            serde_json::from_str(&opencode_content(Some(source), "file:///temp/ours").unwrap())
                .unwrap();
        let original: Value = serde_json::from_str(source).unwrap();
        assert_eq!(merged["model"], original["model"]);
        assert_eq!(merged["permission"], original["permission"]);
        assert_eq!(merged["mcp"], original["mcp"]);
        assert_eq!(merged["plugin"], json!(["existing", "file:///temp/ours"]));
        let v2_source = r#"{"model":"local/model","plugins":["existing-v2"]}"#;
        let v2_merged: Value =
            serde_json::from_str(&opencode_content(Some(v2_source), "file:///temp/ours").unwrap())
                .unwrap();
        assert_eq!(
            v2_merged["plugins"],
            json!(["existing-v2", "file:///temp/ours"])
        );
        let fixture = Fixture::new();
        let native = args(&["--standalone", "run", "hi"]);
        let plan = prepare(&fixture.request("opencode", &native)).unwrap();
        assert_eq!(
            plan.args
                .iter()
                .filter(|arg| *arg == "--standalone")
                .count(),
            1
        );
        assert!(fixture.control.join("apolysis-opencode/index.ts").is_file());
        assert!(
            !opencode_content(Some("private malformed value"), "file:///p")
                .unwrap_err()
                .contains("private malformed value")
        );
        assert!(opencode_content(Some(r#"{"plugin":false}"#), "file:///p").is_err());
        assert!(opencode_content(Some(r#"{"plugins":false}"#), "file:///p").is_err());
    }

    #[test]
    fn observed_workspace_follows_native_cd_but_original_relative_argument_is_unchanged() {
        let fixture = Fixture::new();
        let child = fixture.workspace.join("child");
        fs::create_dir(&child).unwrap();
        for (product, option) in [
            ("codex", "-C"),
            ("cursor", "--workspace"),
            ("opencode", "--dir"),
        ] {
            let native = args(&[option, "child"]);
            let request = fixture.request(product, &native);
            let notes = &mut Vec::new();
            assert_eq!(
                resolved_workspace(&request, &native_options(product, &native), notes),
                child
            );
            assert_eq!(request.workspace, fixture.workspace);
            assert_eq!(native, args(&[option, "child"]));
        }
        for native in [args(&["child"]), args(&["--model", "local/model", "child"])] {
            let request = fixture.request("opencode", &native);
            assert_eq!(
                resolved_workspace(
                    &request,
                    &native_options("opencode", &native),
                    &mut Vec::new()
                ),
                child
            );
            assert_eq!(request.workspace, fixture.workspace);
        }
        let native = args(&["-Cchild"]);
        assert_eq!(
            resolved_workspace(
                &fixture.request("codex", &native),
                &native_options("codex", &native),
                &mut Vec::new()
            ),
            child
        );
    }

    #[test]
    fn conflict_detection_does_not_mistake_prompt_or_option_values_for_flags() {
        for (product, native) in [
            ("claude", args(&["--append-system-prompt", "--background"])),
            ("codex", args(&["--model", "--remote"])),
            ("opencode", args(&["--prompt", "--pure"])),
            ("claude", args(&["--", "--bare"])),
            ("codex", args(&["-c", "features.hooks=true"])),
            ("opencode", args(&["--pure=false"])),
        ] {
            assert!(reject_incompatible_modes(product, &native_options(product, &native)).is_ok());
        }
        for (product, native) in [
            ("claude", args(&["--background"])),
            ("claude", args(&["--bare"])),
            ("codex", args(&["--remote=unix:///tmp/server"])),
            ("codex", args(&["-c", "hooks.PreToolUse=[]"])),
            ("codex", args(&["-chooks.PreToolUse=[]"])),
            ("codex", args(&["--disable", "hooks"])),
            ("opencode", args(&["--pure"])),
            (
                "opencode",
                args(&["run", "--attach", "http://localhost:1234"]),
            ),
            (
                "opencode",
                args(&["run", "--server", "http://localhost:1234"]),
            ),
        ] {
            assert!(
                reject_incompatible_modes(product, &native_options(product, &native)).is_err(),
                "{product}: {native:?}"
            );
        }
        assert!(reject_detached_subcommand(
            "opencode",
            &args(&["--model", "local/model", "attach", "http://localhost:1234"])
        )
        .is_err());
        assert!(
            reject_detached_subcommand("codex", &args(&["-mcloud", "resume", "--last"])).is_ok()
        );
        assert!(reject_detached_subcommand("claude", &args(&["--", "attach"])).is_ok());
        assert!(reject_detached_subcommand("claude", &args(&["--worktree", "attach"])).is_ok());
        assert!(reject_detached_subcommand("claude", &args(&["--resume", "attach"])).is_ok());
    }

    #[test]
    fn hook_command_quotes_static_arguments_and_keeps_native_workspace_expansion() {
        let fixture = Fixture::new();
        let native = vec![];
        let mut request = fixture.request("claude", &native);
        request.allow_reason_summary = true;
        request.shell_bridge = Some("/bin/bash");
        let command = hook_command(&request).unwrap();
        assert!(command.starts_with("'/opt/apolysis'\\''s binary'"));
        assert!(command.ends_with("--allow-reason-summary --shell-bridge '/bin/bash'"));
        assert!(command.contains("\"${CLAUDE_PROJECT_DIR:-$PWD}\""));
        assert_eq!(
            file_url(Path::new("/tmp/a b#中文.ts")).unwrap(),
            "file:///tmp/a%20b%23%E4%B8%AD%E6%96%87.ts"
        );
    }

    #[test]
    fn integration_files_never_overwrite_existing_files_or_follow_symlinks() {
        let fixture = Fixture::new();
        let original = fixture.root.path().join("original");
        fs::write(&original, "keep").unwrap();
        let link = fixture.control.join("apolysis-pi.ts");
        symlink(&original, &link).unwrap();
        assert!(prepare(&fixture.request("pi", &[])).is_err());
        assert_eq!(fs::read_to_string(original).unwrap(), "keep");
    }
}
