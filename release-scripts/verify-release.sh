set -eox
curl https://api.github.com/repos/returntocorp/sgrep/releases/latest > release.json

# Look for release notes
cat release.json | jq '.body' | grep -o "Changed"
cat release.json | jq '.body' | grep -o "Added"

cat release.json | jq -r '.tag_name' | sed 's/^v//' > version
cat release.json | jq -r '.assets[].name'
echo "Looking for version: $(cat version)"

# Look for ubuntu binary
cat release.json | jq '.assets[].name' | grep "sgrep-$(cat version)-ubuntu-16.04.tgz"

# Look for OSX binary
cat release.json | jq '.assets[].name' | grep "sgrep-$(cat version)-osx.zip"


