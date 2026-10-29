#!/usr/bin/env bash
# The GitHub side of publishing, one step per subcommand, with the rules that
# keep a release immutable:
#   - a release is created as a DRAFT, filled, verified, and only then
#     published; a run that fails leaves an unpublished draft, which is the
#     quarantine (drafts are invisible to anyone without write access);
#   - a run that finds any release for its tag, draft or published, fails:
#     nothing is replaced, re-uploaded or overwritten (no --clobber anywhere);
#     a published release is never changed, and a quarantined draft is
#     inspected and deleted by a maintainer before a re-run;
#   - only a stable release may become "latest", and only when its version is
#     the highest stable one among the published releases: a nightly or a
#     release candidate is published as a prerelease and never moves that
#     pointer, and a patch for an older line (v5.3.1 after v5.4.0) is
#     published with --latest=false so it cannot pull the pointer backwards.
#
#   github-release.sh precheck     REPO TAG
#   github-release.sh nightly-tag  REPO TAG SHA        # create the nightly tag at SHA
#   github-release.sh draft        REPO TAG CHANNEL NOTES.md
#   github-release.sh upload       REPO TAG DIR
#   github-release.sh publish      REPO TAG CHANNEL SHA
#
# Needs gh and GH_TOKEN with contents: write (the publishing job's token).
set -euo pipefail
cmd=${1:-}; shift || true
die() { echo "github-release: $*" >&2; exit 1; }

releases_for_tag() { # REPO TAG -> "id draft" lines, drafts included
  gh api --paginate "repos/$1/releases?per_page=100" --jq ".[] | select(.tag_name == \"$2\") | \"\(.id) \(.draft)\""
}

# Is TAG (a stable vX.Y.Z) the highest stable version among the published
# releases? Drafts and prereleases do not count, and neither does any tag that
# is not exactly vX.Y.Z (a release candidate published without the prerelease
# flag, a nightly): they are not stable versions. A failed listing is an error,
# never a default either way.
is_highest_stable() { # REPO TAG
  local listing published top
  listing=$(gh release list --repo "$1" --limit 1000 --json tagName,isDraft,isPrerelease \
    --jq '.[] | "\(.tagName) \(.isDraft) \(.isPrerelease)"') || die "could not list the releases of $1"
  published=$(awk '$2 == "false" && $3 == "false" { print $1 }' <<<"$listing")
  top=$(printf '%s\n%s\n' "$published" "$2" | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' | sort -t. -k1.2,1n -k2,2n -k3,3n | tail -n 1)
  [ "$top" = "$2" ]
}

case "$cmd" in
  precheck)
    repo=$1 tag=$2
    found=$(releases_for_tag "$repo" "$tag")
    if [ -n "$found" ]; then
      if grep -q ' true$' <<<"$found"; then
        die "an unpublished draft for $tag exists (a quarantined earlier run). Inspect it; delete it with 'gh release delete $tag --repo $repo' (the tag stays) and re-run. Nothing is overwritten."
      fi
      die "release $tag is already published; a published release is never replaced. Fix forward with a new version."
    fi
    echo "github-release: no release for $tag yet"
    ;;
  nightly-tag)
    repo=$1 tag=$2 sha=$3
    [[ $tag =~ ^nightly-[0-9]{8}-[0-9a-f]{12}$ ]] || die "not a nightly tag: $tag"
    [ "${tag##*-}" = "${sha:0:12}" ] || die "$tag does not name $sha"
    gh api -X POST "repos/$repo/git/refs" -f "ref=refs/tags/$tag" -f "sha=$sha" >/dev/null \
      || die "could not create tag $tag (it may already exist: a nightly tag is never moved)"
    got=$(gh api "repos/$repo/git/ref/tags/$tag" --jq .object.sha)
    [ "$got" = "$sha" ] || die "tag $tag points at $got, not $sha"
    echo "github-release: tag $tag -> $sha"
    ;;
  draft)
    repo=$1 tag=$2 channel=$3 notes=$4
    args=(--repo "$repo" --verify-tag --draft --title "$tag" --notes-file "$notes" --latest=false)
    [ "$channel" = stable ] || args+=(--prerelease)
    gh release create "$tag" "${args[@]}"
    ;;
  upload)
    repo=$1 tag=$2 dir=$3
    mapfile -t files < <(find "$dir" -maxdepth 1 -type f | LC_ALL=C sort)
    [ "${#files[@]}" -gt 0 ] || die "nothing to upload in $dir"
    # Without --clobber, gh refuses an asset name that already exists.
    gh release upload "$tag" --repo "$repo" "${files[@]}"
    n=$(gh release view "$tag" --repo "$repo" --json assets --jq '.assets | length')
    [ "$n" = "${#files[@]}" ] || die "the draft holds $n asset(s), $dir has ${#files[@]}"
    echo "github-release: uploaded ${#files[@]} asset(s) to the draft of $tag"
    ;;
  publish)
    repo=$1 tag=$2 channel=$3 sha=$4
    if [ "$channel" = stable ]; then
      if is_highest_stable "$repo" "$tag"; then
        gh release edit "$tag" --repo "$repo" --draft=false --latest
      else
        echo "github-release: $tag is not the highest stable version; it is published without becoming latest"
        gh release edit "$tag" --repo "$repo" --draft=false --latest=false
      fi
    else
      gh release edit "$tag" --repo "$repo" --draft=false --prerelease --latest=false
    fi
    commit=$(gh api "repos/$repo/commits/$tag" --jq .sha)
    [ "$commit" = "$sha" ] || die "published $tag resolves to $commit, not the built commit $sha"
    echo "github-release: published $tag ($channel) at $sha"
    ;;
  *)
    sed -n '2,23p' "$0" | sed 's/^# \{0,1\}//' >&2
    exit 2
    ;;
esac
