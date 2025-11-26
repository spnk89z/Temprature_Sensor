#!/usr/bin/env bash
set -euo pipefail

# git_push.sh - Add, commit and push changes safely
# Usage:
#   ./scripts/git_push.sh -b feat/ota-signing -m "commit message" -p
# Options:
#  -b | --branch  : branch name to push to (default: feat/ota-signing)
#  -m | --message : commit message (default: "chore: add OTA signing & docs")
#  -p | --pr      : create a GitHub PR using gh cli after pushing
#  -f | --force   : push with --force (be careful)
#  -d | --dry-run : show commands without executing

BRANCH="feat/ota-signing"
MESSAGE="chore(ota): add signing, verify, generator, docs"
PUSH_PR=false
FORCE=false
DRY=false

print_usage() {
  echo "Usage: $0 [-b branch] [-m commit-message] [-p] [-f] [-d]"
  echo "  -p | --pr  Create a GitHub PR using gh (if installed)"
}

while [[ $# -gt 0 ]]; do
  case $1 in
    -b|--branch) BRANCH="$2"; shift 2 ;;
    -m|--message) MESSAGE="$2"; shift 2 ;;
    -p|--pr) PUSH_PR=true; shift ;;
    -f|--force) FORCE=true; shift ;;
    -d|--dry-run) DRY=true; shift ;;
    -h|--help) print_usage; exit 0;;
    *) echo "Unknown arg: $1"; print_usage; exit 1;;
  esac
done

echo "Branch: $BRANCH"
echo "Message: $MESSAGE"

if [ "$DRY" = true ]; then
  echo "DRY RUN: Commands will only be displayed"
fi

# Check git repo
if ! git rev-parse --git-dir > /dev/null 2>&1; then
  echo "Not inside a git repo. Please run this script from repo root."; exit 1
fi

# Show status
echo "Current status:"; git status --short || true

# Create or checkout branch
if git show-ref --verify --quiet refs/heads/$BRANCH; then
  echo "Branch $BRANCH exists locally, switching to it"
  CMD=(git checkout "$BRANCH")
else
  echo "Creating branch $BRANCH"
  CMD=(git checkout -b "$BRANCH")
fi
if [ "$DRY" = false ]; then "${CMD[@]}"; else echo "+ ${CMD[*]}"; fi

# Add files
CMD=(git add -A)
if [ "$DRY" = false ]; then "${CMD[@]}"; else echo "+ ${CMD[*]}"; fi

# Commit if there are changes
if git diff --cached --quiet; then
  echo "Nothing to commit. No changes staged.";
else
  CMD=(git commit -m "$MESSAGE")
  if [ "$DRY" = false ]; then "${CMD[@]}"; else echo "+ ${CMD[*]}"; fi
fi

# Push
PUSH_CMD=(git push -u origin "$BRANCH")
if [ "$FORCE" = true ]; then PUSH_CMD+=(--force); fi
if [ "$DRY" = false ]; then "${PUSH_CMD[@]}"; else echo "+ ${PUSH_CMD[*]}"; fi

# Create PR if requested and gh available
if [ "$PUSH_PR" = true ]; then
  if command -v gh > /dev/null 2>&1; then
    PR_TITLE="$MESSAGE"
    PR_BODY="Automatic PR created by scripts/git_push.sh"
    CMD=(gh pr create --title "$PR_TITLE" --body "$PR_BODY" --base main --head "$BRANCH")
    if [ "$DRY" = false ]; then "${CMD[@]}"; else echo "+ ${CMD[*]}"; fi
  else
    echo "gh CLI not found. Install 'gh' if you want PR creation automatic.
  fi
fi

# Final status
echo "Done. Run 'git status' and 'git log -n 3' to verify." 
