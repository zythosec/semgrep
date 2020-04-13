set -e
curl https://api.github.com/repos/returntocorp/sgrep/releases/latest > release.json
cat release.json | jq -r '.tag_name' | sed 's/^v//' > release-version

echo "Installing via homebrew"
brew tap returntocorp/sgrep https://github.com/returntocorp/sgrep.git
brew install semgrep

echo "Running homebrew recipe checks"
brew test semgrep

echo "Validating the version"
brew info semgrep --json | jq -r '.[0].installed[0].version' | tee brew-version
diff brew-version release-version
