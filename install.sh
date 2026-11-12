#!/bin/sh
# Install the sentrytower command from this clone, then start the guided setup. For macOS and Linux.
#
#   git clone https://github.com/National-Compute/sentrytower && cd sentrytower && ./install.sh
#
# The script never asks for administrator rights. It:
#   1. Uses uv from PATH, or installs uv for this user (https://docs.astral.sh/uv/). uv also supplies
#      Python 3.11 or later when the system has no such Python.
#   2. Installs the sentrytower command from this folder with `uv tool install`.
#   3. Installs the tools of the agent when it can do so without administrator rights: Node.js, ripgrep
#      and fd with Homebrew on macOS, and the pinned Pi agent with npm. For each tool that it cannot
#      install, and for another version of Pi that is installed, it prints the command to run.
#   4. Starts `sentrytower setup` when it runs in a terminal.
#
# Run it again after `git pull` to install the new version.

set -eu

PI_PACKAGE="@earendil-works/pi-coding-agent"

say() { printf '%s\n' "$*"; }
step() { printf '\n==> %s\n' "$*"; }
fail() {
	printf 'install.sh: %s\n' "$*" >&2
	exit 1
}
have() { command -v "$1" >/dev/null 2>&1; }

# The tools that the script cannot install: one command or one instruction per line.
todo=""
later() { todo="$todo  $*
"; }

# Node.js 22.19 or later: the Pi agent runs on it.
node_ok() {
	have node || return 1
	version=$(node --version 2>/dev/null | sed 's/^v//')
	major=${version%%.*}
	rest=${version#*.}
	minor=${rest%%.*}
	case "$major.$minor" in *[!0-9.]* | .* | *.) return 1 ;; esac
	[ "$major" -gt 22 ] || { [ "$major" -eq 22 ] && [ "$minor" -ge 19 ]; }
}

root=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
if [ ! -f "$root/pyproject.toml" ] || [ ! -d "$root/src/sentrytower" ]; then
	fail "run this script from a clone of https://github.com/National-Compute/sentrytower"
fi

case $(uname -s) in
Darwin) os=macos ;;
Linux) os=linux ;;
*) fail "this script supports macOS and Linux. On another system, use the image ghcr.io/national-compute/sentrytower" ;;
esac

# 1. uv
if ! have uv; then
	have curl || fail "uv is not installed, and curl is not available to install it. See https://docs.astral.sh/uv/getting-started/installation/"
	step "Installing uv for this user"
	curl -LsSf https://astral.sh/uv/install.sh | sh
	PATH="${XDG_BIN_HOME:-$HOME/.local/bin}:$HOME/.cargo/bin:$PATH"
	have uv || fail "uv is installed, but this shell cannot find it. Open a new terminal and run ./install.sh again"
fi

# 2. The sentrytower command. pyproject.toml requires Python 3.11 or later.
step "Installing the sentrytower command from $root"
uv tool install --reinstall --python '>=3.11' "$root"
bin=$(uv tool dir --bin)
sentrytower="$bin/sentrytower"
[ -x "$sentrytower" ] || fail "uv did not install $sentrytower"

# 3. The tools of the agent
if [ "$os" = macos ] && have brew; then
	formulas=""
	have rg || formulas="$formulas ripgrep"
	have fd || formulas="$formulas fd"
	have node || formulas="$formulas node"
	if [ -n "$formulas" ]; then
		step "Installing$formulas with Homebrew"
		# shellcheck disable=SC2086 # one word for each formula
		brew install $formulas || later "brew install$formulas"
	fi
else
	missing=""
	have rg || missing="$missing ripgrep"
	have fd || have fdfind || missing="$missing fd"
	# Debian, Ubuntu and Fedora call the fd package fd-find. fd is always the last word of the list.
	fd_find=$(say "$missing" | sed 's/ fd$/ fd-find/')
	if [ -z "$missing" ]; then
		:
	elif have apt-get; then
		later "sudo apt-get install$fd_find"
	elif have dnf; then
		later "sudo dnf install$fd_find"
	elif have pacman; then
		later "sudo pacman -S$missing"
	elif have brew; then
		later "brew install$missing"
	else
		later "install$missing (https://github.com/BurntSushi/ripgrep, https://github.com/sharkdp/fd)"
	fi
fi

pi_version=$("$sentrytower" version --json | sed -n 's/.*"pi_coding_agent": *"\([^"]*\)".*/\1/p')
[ -n "$pi_version" ] || fail "$sentrytower did not give the pinned version of the Pi agent"
if node_ok; then
	if ! have pi; then
		step "Installing the Pi agent $pi_version with npm"
		npm install -g "$PI_PACKAGE@$pi_version" || later "npm install -g $PI_PACKAGE@$pi_version"
	else
		# Another version of Pi can serve other work on this computer: print the command, do not replace it.
		found=$(PI_OFFLINE=1 pi --version 2>/dev/null || true)
		[ "$found" = "$pi_version" ] || later "npm install -g $PI_PACKAGE@$pi_version   # replaces Pi ${found:-of unknown version}"
	fi
else
	later "install Node.js 22.19 or later (https://nodejs.org/en/download)"
	have pi || later "npm install -g $PI_PACKAGE@$pi_version"
fi

if [ -n "$todo" ]; then
	step "Install these tools, then run sentrytower doctor"
	printf '%s' "$todo"
fi

on_path=no
case ":$PATH:" in *":$bin:"*) on_path=yes ;; esac

# 4. The guided setup. It asks questions, so it needs a terminal.
status=0
if [ -t 0 ] && [ -t 1 ]; then
	step "Starting sentrytower setup"
	"$sentrytower" setup || status=$?
else
	step "Installed. Run sentrytower setup in a terminal to choose your models and your key"
fi

if [ "$on_path" = no ]; then
	say ""
	say "The sentrytower command is in $bin, and that folder is not on PATH."
	say "Run 'uv tool update-shell', then open a new terminal."
fi
exit "$status"
