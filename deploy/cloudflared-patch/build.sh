#!/bin/sh
set -eu

patch_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH='' cd -- "$patch_dir/../.." && pwd)
source="$repo_root/dist/cloudflared-src"
output="$repo_root/dist/cloudflared"
patch="$patch_dir/vanora-pinned-origin.patch"

lock_value() {
    awk -v key="$1" -F= '
        $1 == key {
            value = substr($0, length(key) + 2)
            sub(/\r$/, "", value)
            print value
            count++
        }
        END { if (count != 1) exit 1 }
    ' "$patch_dir/upstream.lock"
}

sha256() {
    if command -v sha256sum >/dev/null 2>&1; then
        checksum=$(sha256sum < "$1")
    else
        checksum=$(shasum -a 256 < "$1")
    fi
    printf '%s\n' "${checksum%% *}"
}

repo=$(lock_value repo)
tag=$(lock_value tag)
commit=$(lock_value commit)
expected_patch_hash=$(lock_value patch_sha256)
if [ "$repo" != "https://github.com/cloudflare/cloudflared.git" ] ||
    ! printf '%s\n' "$tag" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$' ||
    ! printf '%s\n' "$commit" | grep -Eq '^[0-9a-f]{40}$' ||
    ! printf '%s\n' "$expected_patch_hash" | grep -Eq '^[0-9a-f]{64}$'; then
    printf '%s\n' 'Invalid upstream.lock' >&2
    exit 1
fi

patch_hash=$(sha256 "$patch")
if [ "$patch_hash" != "$expected_patch_hash" ]; then
    printf '%s\n' 'Patch SHA-256 does not match upstream.lock' >&2
    exit 1
fi
printf 'Verified patch SHA-256 %s\n' "$patch_hash"

if [ ! -e "$source/.git" ]; then
    git init --quiet "$source"
fi
tag_ref="refs/tags/$tag"
if ! tag_commit=$(git -C "$source" rev-parse --quiet --verify "$tag_ref^{commit}") ||
    [ "$tag_commit" != "$commit" ]; then
    git -C "$source" fetch --no-tags --depth=1 "$repo" "$tag_ref:$tag_ref"
    tag_commit=$(git -C "$source" rev-parse --verify "$tag_ref^{commit}")
fi
if [ "$tag_commit" != "$commit" ]; then
    printf '%s\n' 'Upstream tag does not resolve to the locked commit' >&2
    exit 1
fi
printf 'Verified cloudflared %s %s\n' "$tag" "$tag_commit"

host_os=$(go env GOHOSTOS)
host_arch=$(go env GOHOSTARCH)
target_os=${GOOS:-"$host_os"}
target_arch=${GOARCH:-"$host_arch"}
binary_name=cloudflared-vanora
if [ "$target_os" = windows ]; then
    binary_name="$binary_name.exe"
fi

checkout=$(mktemp -d "$repo_root/dist/cloudflared-build-XXXXXXXX")
git -C "$source" worktree add --quiet --detach "$checkout" "$commit"
trap 'git -C "$source" worktree remove --force "$checkout"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
if [ "$(git -C "$checkout" rev-parse HEAD)" != "$commit" ]; then
    printf '%s\n' 'Build checkout is at the wrong commit' >&2
    exit 1
fi
git -C "$checkout" apply --check "$patch"
printf '%s\n' 'git apply --check passed'
git -C "$checkout" apply "$patch"

(
    cd -- "$checkout"
    export CGO_ENABLED=0 GOWORK=off
    GOOS="$host_os" GOARCH="$host_arch" go test -mod=readonly ./ingress ./orchestration ./cmd/cloudflared/tunnel
    GOOS="$target_os" GOARCH="$target_arch" go build -mod=readonly -buildvcs=false -trimpath \
        -ldflags "-s -w -X main.Version=$tag-vanora" -o "$binary_name" ./cmd/cloudflared
)

digest=$(sha256 "$checkout/$binary_name")
printf '%s  %s\n' "$digest" "$binary_name" > "$checkout/$binary_name.sha256"
mkdir -p -- "$output"
artifact="$output/$binary_name"
mv -f -- "$checkout/$binary_name" "$artifact"
mv -f -- "$checkout/$binary_name.sha256" "$artifact.sha256"
if [ "$(sha256 "$artifact")" != "$digest" ]; then
    printf '%s\n' 'Packaged binary SHA-256 verification failed' >&2
    exit 1
fi
printf 'Built %s/%s %s\nSHA-256 %s\n' "$target_os" "$target_arch" "$artifact" "$digest"
