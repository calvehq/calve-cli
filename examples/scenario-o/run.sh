#!/usr/bin/env bash
# §57 Scenario O — Console reconnect: the console engine against a real calved, restarted under it.
source "$(dirname "$0")/../lib.sh"

enable "$FILES_EXT"
for i in 1 2 3 4; do calve pack create "Open pack $i" >/dev/null; done
export CALVE_E2E_PROJECT="$PROJECT" CALVE_BIN
cd "$(dirname "$0")/../.."
cargo test -q --locked -p calve-console --test reconnect_e2e scenario_o_console_reconnect -- --ignored --nocapture
