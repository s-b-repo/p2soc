# Shared by the installed launchers and old releases during migration.
# Call with the release root. Prefer a binary from that release to a build
# from the checkout, so the live symlink and its executable roll back together.
soc_native_path() {
  [ "${SOC_LEGACY_PYTHON:-0}" != 1 ] || return 1
  if [ -n "${SOC_WALL_BIN:-}" ]; then
    [ -x "$SOC_WALL_BIN" ] || return 1
    printf '%s\n' "$SOC_WALL_BIN"
    return
  fi
  for soc_candidate in "$1/bin/soc-wall" "$1/rust/target/release/soc-wall"; do
    if [ -x "$soc_candidate" ]; then
      printf '%s\n' "$soc_candidate"
      return
    fi
  done
  return 1
}
