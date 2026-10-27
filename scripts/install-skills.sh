#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)

if ! command -v node >/dev/null 2>&1; then
  printf '%s\n' 'Node.js 22以上をインストールしてください。' >&2
  exit 1
fi

if ! node -e 'process.exit(Number(process.versions.node.split(".")[0]) >= 22 ? 0 : 1)'; then
  printf '%s\n' 'Node.js 22以上が必要です。' >&2
  exit 1
fi

if ! command -v npx >/dev/null 2>&1; then
  printf '%s\n' 'npm（npxを含む）をインストールしてください。' >&2
  exit 1
fi

if ! command -v git >/dev/null 2>&1; then
  printf '%s\n' 'Gitをインストールしてください。' >&2
  exit 1
fi

cd -- "$repo_root"

# latestでは導入内容が変わるため、CLIと導入元のコミットを固定する。
skills_cli_version='1.7.4'
cloudflare_ref='86505e44f87d801aa1864a3c4109e9a8ae5c409f'

DISABLE_TELEMETRY=1 npx --yes "skills@$skills_cli_version" add \
  "https://github.com/cloudflare/skills/tree/$cloudflare_ref" \
  --skill cloudflare workers-best-practices wrangler \
  --agent codex \
  --copy \
  --yes

for skill in cloudflare workers-best-practices wrangler; do
  if [ ! -f ".agents/skills/$skill/SKILL.md" ]; then
    printf 'skillの導入を確認できません: %s\n' "$skill" >&2
    exit 1
  fi
done

printf '%s\n' '外部skillsを .agents/skills/ に導入しました。次のターンから利用できます。'
