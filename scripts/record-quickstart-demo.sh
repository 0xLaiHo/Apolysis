#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Record the README demo GIF/cast as a REAL terminal recording of the
# zero-privilege quickstart. Every line of output is produced by the real
# `apolysis` binary on the bundled fixture — nothing is hand-authored or
# re-rendered from a transcript.
#
# Requires: asciinema (pip install asciinema) and agg
# (https://github.com/asciinema/agg). Both are recording tools, not build deps.

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

for tool in asciinema agg; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "record-quickstart-demo: missing '$tool'." >&2
        echo "  asciinema: pip install asciinema" >&2
        echo "  agg:       https://github.com/asciinema/agg/releases" >&2
        exit 1
    }
done

asset_dir="docs/assets/codex-live-demo"
cast="$asset_dir/codex-live-demo.cast"
gif="$asset_dir/codex-live-demo.gif"
scene="$(mktemp)"
trap 'rm -f "$scene"' EXIT

# Warm the build so the recording shows the result, not compilation.
cargo build -q -p apolysis-cli
make quickstart >/dev/null 2>&1

# Framing comments and the prompt are cosmetic; the summary below them is the
# real, unedited output of `make quickstart`.
cat >"$scene" <<'SCENE'
#!/usr/bin/env bash
set -e
sleep 0.6
printf '# Your AI agent said it ran the tests. Did it also touch your credentials?\n'
sleep 1.4
printf '# make quickstart -- zero privileges: no root, no eBPF, a bundled fixture\n'
sleep 1.2
printf '$ make quickstart\n'
sleep 0.5
make quickstart
sleep 2.5
SCENE

asciinema rec -q --overwrite -c "bash $scene" "$cast"
agg --theme asciinema --font-size 18 --cols 90 --rows 12 --idle-time-limit 2 "$cast" "$gif"

echo "record-quickstart-demo: wrote $cast and $gif"
