#!/usr/bin/env bash
# The release's version and commit. An empty dispatch ships the version
# Cargo.toml declares from the checked-out commit, so pressing the button once
# re-releases that commit instead of resolving an older tag of the same name.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

valid_version() {
  printf '%s' "$1" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$'
}

tag_commit() {
  git rev-parse --verify "refs/tags/$1^{commit}" 2>/dev/null
}

fail() {
  printf '::error::%s\n' "$1" >&2
  exit 1
}

plan() {
  local event="$1" ref="$2" want="${3:-}" version commit declared
  case "$event" in
    push)
      valid_version "$ref" || fail "the pushed tag must be vX.Y.Z, got: $ref"
      version="$ref"
      commit="$(git rev-parse HEAD)"
      ;;
    workflow_dispatch)
      if [ -n "$want" ]; then
        valid_version "$want" || fail "the tag input must name an existing vX.Y.Z tag, got: $want"
        commit="$(tag_commit "$want")" || fail "the tag input names no tag: $want"
        version="$want"
      else
        declared="$(sed -n 's/^version = "\([^"]*\)".*/\1/p' Cargo.toml | head -1)"
        [ -n "$declared" ] || fail "cannot read the workspace version from Cargo.toml"
        valid_version "v$declared" || fail "Cargo.toml declares a non-vX.Y.Z version: $declared"
        version="v$declared"
        commit="$(git rev-parse HEAD)"
      fi
      ;;
    *)
      fail "release-plan: unknown event '$event'"
      ;;
  esac
  printf 'version=%s\ncommit=%s\n' "$version" "$commit"
}

selftest() {
  local old new out script
  SELFTEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/ferrox-release-plan.XXXXXX")"
  root="$SELFTEST_ROOT"
  script="$here/release-plan.sh"
  trap 'rm -rf "$SELFTEST_ROOT"' EXIT
  printf '[workspace]\nversion = "0.0.1"\n' >"$root/Cargo.toml"
  git -C "$root" init -q
  git -C "$root" config user.email selftest@ferrox.invalid
  git -C "$root" config user.name selftest
  git -C "$root" add Cargo.toml
  git -C "$root" commit -qm old
  old="$(git -C "$root" rev-parse HEAD)"
  git -C "$root" tag v0.0.1 "$old"
  printf '\n# moved\n' >>"$root/Cargo.toml"
  git -C "$root" commit -qam new
  new="$(git -C "$root" rev-parse HEAD)"

  out="$(cd "$root" && "$script" workflow_dispatch refs/heads/main "")"
  grep -qx 'version=v0.0.1' <<<"$out" ||
    { echo "selftest: empty dispatch named the wrong version: $out" >&2; return 1; }
  grep -qx "commit=$new" <<<"$out" ||
    { echo "selftest: empty dispatch used the old tag commit: $out" >&2; return 1; }

  out="$(cd "$root" && "$script" workflow_dispatch refs/heads/main v0.0.1)"
  grep -qx 'version=v0.0.1' <<<"$out" ||
    { echo "selftest: named tag named the wrong version: $out" >&2; return 1; }
  grep -qx "commit=$old" <<<"$out" ||
    { echo "selftest: named tag did not resolve its own commit: $out" >&2; return 1; }

  out="$(cd "$root" && "$script" push v0.0.2 "")"
  grep -qx 'version=v0.0.2' <<<"$out" ||
    { echo "selftest: a pushed tag named the wrong version: $out" >&2; return 1; }
  grep -qx "commit=$new" <<<"$out" ||
    { echo "selftest: a pushed tag did not use HEAD: $out" >&2; return 1; }

  echo "release-plan: selftest ok"
}

case "${1:-}" in
  --selftest) selftest ;;
  "") echo "usage: release-plan.sh <push|workflow_dispatch> <ref_name> [tag]" >&2; exit 2 ;;
  *) plan "$@" ;;
esac
