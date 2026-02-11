#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
DIST_DIR="$ROOT_DIR/dist"
VERSION="${VERSION:-$(cd "$ROOT_DIR" && node -p "require('./package.json').version")}" 
SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-946684800}"

usage() {
  cat <<USAGE
Usage: scripts/package-portable-dist.sh [--platform <linux|windows|macos|all>]

Packages deterministic portable distribution archives and emits manifests/checksums.
USAGE
}

PLATFORM="all"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --platform)
      PLATFORM="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [[ ! -d "$DIST_DIR" ]]; then
  echo "Missing dist/ directory. Run pnpm build first." >&2
  exit 1
fi

copy_runtime_tree() {
  local dest="$1"
  rm -rf "$dest/runtime"
  mkdir -p "$dest/runtime"

  rsync -a --delete \
    --exclude '.DS_Store' \
    --exclude 'OpenClaw.app' \
    --exclude 'OpenClaw-*' \
    --exclude '.portable-stage' \
    --exclude '*.zip' \
    --exclude '*.dmg' \
    --exclude '*.tar.gz' \
    "$DIST_DIR/" "$dest/runtime/dist/"

  cp "$ROOT_DIR/openclaw.mjs" "$dest/runtime/openclaw.mjs"
  cp "$ROOT_DIR/package.json" "$dest/runtime/package.json"
  cp "$ROOT_DIR/LICENSE" "$dest/runtime/LICENSE"
  cp "$ROOT_DIR/README.md" "$dest/runtime/README.md"

  if [[ -d "$ROOT_DIR/assets" ]]; then
    rsync -a "$ROOT_DIR/assets/" "$dest/runtime/assets/"
  fi

  if [[ -d "$ROOT_DIR/extensions" ]]; then
    rsync -a \
      --exclude 'node_modules' \
      --exclude '.turbo' \
      --exclude 'dist' \
      "$ROOT_DIR/extensions/" "$dest/runtime/extensions/"
  fi
}

write_linux_launchers() {
  local dest="$1"
  cat > "$dest/runtime/openclaw" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec node "$SELF_DIR/openclaw.mjs" "$@"
SH
  chmod +x "$dest/runtime/openclaw"

  cat > "$dest/runtime/onboard.sh" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "$SELF_DIR/openclaw" onboard --install-daemon "$@"
SH
  chmod +x "$dest/runtime/onboard.sh"
}

write_windows_launchers() {
  local dest="$1"
  cat > "$dest/runtime/openclaw.cmd" <<'CMD'
@echo off
setlocal
set "SELF_DIR=%~dp0"
node "%SELF_DIR%openclaw.mjs" %*
CMD

  cat > "$dest/runtime/onboard.cmd" <<'CMD'
@echo off
setlocal
set "SELF_DIR=%~dp0"
call "%SELF_DIR%openclaw.cmd" onboard --install-daemon %*
CMD
}

write_macos_launcher() {
  local dest="$1"
  cat > "$dest/runtime/Launch OpenClaw.command" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
open "$SELF_DIR/OpenClaw.app"
SH
  chmod +x "$dest/runtime/Launch OpenClaw.command"
}

build_deterministic_archive() {
  local platform="$1"
  local ext="$2"
  local stage_root="$3"
  local package_root="OpenClaw-$VERSION-$platform"
  local output="$DIST_DIR/$package_root.$ext"
  local manifest="$DIST_DIR/$package_root.manifest.json"
  local checksums="$DIST_DIR/$package_root.sha256"

  rm -f "$output" "$manifest" "$checksums"

  python3 - <<'PY' "$platform" "$ext" "$stage_root/runtime" "$output" "$manifest" "$checksums" "$VERSION" "$package_root" "$SOURCE_DATE_EPOCH"
import gzip
import hashlib
import io
import json
import os
import stat
import tarfile
import zipfile
from pathlib import Path
import sys

platform, ext, source_dir, output, manifest_path, checksums_path, version, package_root, source_epoch = sys.argv[1:10]
source_epoch = int(source_epoch)
source = Path(source_dir)
output_path = Path(output)
manifest = []

entries = []
for path in sorted(source.rglob('*')):
    rel = path.relative_to(source).as_posix()
    archive_rel = f"{package_root}/{rel}"
    entries.append((archive_rel, path, path.is_dir()))

if ext == 'zip':
    with zipfile.ZipFile(output_path, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        for archive_rel, path, is_dir in entries:
            zip_name = archive_rel + ('/' if is_dir else '')
            zi = zipfile.ZipInfo(zip_name)
            zi.date_time = (2000, 1, 1, 0, 0, 0)
            zi.create_system = 3
            if is_dir:
                zi.external_attr = (stat.S_IFDIR | 0o755) << 16
                zf.writestr(zi, b'')
                continue
            mode = 0o755 if os.access(path, os.X_OK) else 0o644
            zi.external_attr = (stat.S_IFREG | mode) << 16
            data = path.read_bytes()
            zf.writestr(zi, data)
            manifest.append({'path': archive_rel, 'size': len(data), 'sha256': hashlib.sha256(data).hexdigest()})
elif ext == 'tar.gz':
    tar_buffer = io.BytesIO()
    with tarfile.open(fileobj=tar_buffer, mode='w', format=tarfile.PAX_FORMAT) as tf:
        for archive_rel, path, is_dir in entries:
            ti = tarfile.TarInfo(name=archive_rel)
            ti.uid = 0
            ti.gid = 0
            ti.uname = 'root'
            ti.gname = 'root'
            ti.mtime = source_epoch
            if is_dir:
                ti.type = tarfile.DIRTYPE
                ti.mode = 0o755
                tf.addfile(ti)
                continue
            data = path.read_bytes()
            ti.size = len(data)
            ti.mode = 0o755 if os.access(path, os.X_OK) else 0o644
            tf.addfile(ti, fileobj=io.BytesIO(data))
            manifest.append({'path': archive_rel, 'size': len(data), 'sha256': hashlib.sha256(data).hexdigest()})
    tar_buffer.seek(0)
    with output_path.open('wb') as fh:
        with gzip.GzipFile(filename='', mode='wb', fileobj=fh, mtime=source_epoch, compresslevel=9) as gz:
            gz.write(tar_buffer.read())
else:
    raise SystemExit(f'Unsupported archive extension: {ext}')

archive_digest = hashlib.sha256(output_path.read_bytes()).hexdigest()
Path(manifest_path).write_text(json.dumps({
    'name': output_path.name,
    'platform': platform,
    'version': version,
    'sourceDateEpoch': source_epoch,
    'files': manifest,
}, indent=2) + '\n', encoding='utf-8')
Path(checksums_path).write_text(f"{archive_digest}  {output_path.name}\n", encoding='utf-8')
PY

  echo "Created: $output"
  echo "Manifest: $manifest"
  echo "Checksums: $checksums"
}

package_linux() {
  local stage="$DIST_DIR/.portable-stage/linux"
  rm -rf "$stage"
  mkdir -p "$stage"
  copy_runtime_tree "$stage"
  write_linux_launchers "$stage"
  build_deterministic_archive "linux" "tar.gz" "$stage"
}

package_windows() {
  local stage="$DIST_DIR/.portable-stage/windows"
  rm -rf "$stage"
  mkdir -p "$stage"
  copy_runtime_tree "$stage"
  write_windows_launchers "$stage"
  build_deterministic_archive "windows" "zip" "$stage"
}

package_macos() {
  local stage="$DIST_DIR/.portable-stage/macos"
  rm -rf "$stage"
  mkdir -p "$stage/runtime"

  "$ROOT_DIR/scripts/package-mac-dist.sh"

  cp -R "$DIST_DIR/OpenClaw.app" "$stage/runtime/OpenClaw.app"
  write_macos_launcher "$stage"

  build_deterministic_archive "macos" "zip" "$stage"
}

case "$PLATFORM" in
  linux)
    package_linux
    ;;
  windows)
    package_windows
    ;;
  macos)
    package_macos
    ;;
  all)
    package_linux
    package_windows
    if [[ "$(uname -s)" == "Darwin" ]]; then
      package_macos
    else
      echo "Skipping macOS packaging on non-macOS host"
    fi
    ;;
  *)
    echo "Invalid platform: $PLATFORM" >&2
    exit 1
    ;;
esac
