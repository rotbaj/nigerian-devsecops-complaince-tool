#!/bin/sh
# One-time setup after cloning: points git at the repo's versioned hooks
# so every commit is scanned for compliance issues before it is created.
cd "$(git rev-parse --show-toplevel)" || exit 1
git config core.hooksPath scripts/hooks
chmod +x scripts/hooks/*
echo "✅ Git hooks installed. Every commit will now run the compliance scan."
echo "   To uninstall: git config --unset core.hooksPath"
