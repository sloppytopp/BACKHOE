# Homebrew formula draft for BACKHOE — NOT ready to use as-is.
#
# This cannot be finished until a real release exists (see the TODOs below)
# and cannot be tested at all in this dev environment (no Homebrew/macOS
# here). Treat every `sha256` below as a placeholder that WILL be wrong
# until you regenerate it for real — a wrong sha256 makes `brew install`
# fail loudly (Homebrew verifies it), it won't silently install bad bits.
#
# --- How to actually finish and ship this ---
#
# 1. Cut a real release first (tag + GitHub Release, and ideally publish
#    to PyPI per .github/workflows/publish.yml) — this formula needs a
#    real tarball URL and its real sha256, which don't exist yet.
#
# 2. On a Mac (or Linuxbrew) with Homebrew installed:
#      brew install python@3.12
#      pip install homebrew-pypi-poet
#      pip install backhoe-osint  # or: pip install -e . from a checkout
#      poet backhoe-osint
#    `poet` prints ready-to-paste `resource` blocks with correct sha256
#    hashes for backhoe-osint and every one of its dependencies
#    (click, rich, requests, dnspython, plus their own transitive deps).
#    Replace the placeholder `resource` blocks below with poet's real
#    output — don't hand-write these hashes.
#
# 3. Get the release tarball's own sha256:
#      curl -sL https://github.com/sloppytopp/BACKHOE/archive/refs/tags/vX.Y.Z.tar.gz | sha256sum
#    Put that in the top-level `sha256` below, and fix `url` to match
#    the real tag.
#
# 4. Create a SEPARATE repo named `homebrew-backhoe` under the sloppytopp
#    GitHub account (this is Homebrew's convention for a personal tap —
#    it must be a distinct repo, not a folder in this one) with this file
#    at `Formula/backhoe.rb`. This repo has to be created manually — no
#    working GitHub repo-creation access was available when this draft
#    was written.
#
# 5. Test locally before telling anyone it works:
#      brew install --build-from-source sloppytopp/backhoe/backhoe
#      brew test backhoe
#
# 6. Once it works, users install with:
#      brew tap sloppytopp/backhoe
#      brew install backhoe

class Backhoe < Formula
  include Language::Python::Virtualenv

  desc "OSINT recon that gives you an answer, not a data dump"
  homepage "https://github.com/sloppytopp/BACKHOE"
  # TODO: replace with the real release tag and its real sha256 (step 3 above)
  url "https://github.com/sloppytopp/BACKHOE/archive/refs/tags/vX.Y.Z.tar.gz"
  sha256 "PLACEHOLDER_REPLACE_WITH_REAL_TARBALL_SHA256"
  license "AGPL-3.0-or-later"

  depends_on "python@3.12"

  # TODO: replace every resource block below with `poet`'s real output
  # (step 2 above) — these are placeholders and WILL be wrong.
  resource "click" do
    url "https://files.pythonhosted.org/packages/PLACEHOLDER/click-PLACEHOLDER.tar.gz"
    sha256 "PLACEHOLDER"
  end

  resource "rich" do
    url "https://files.pythonhosted.org/packages/PLACEHOLDER/rich-PLACEHOLDER.tar.gz"
    sha256 "PLACEHOLDER"
  end

  resource "requests" do
    url "https://files.pythonhosted.org/packages/PLACEHOLDER/requests-PLACEHOLDER.tar.gz"
    sha256 "PLACEHOLDER"
  end

  resource "dnspython" do
    url "https://files.pythonhosted.org/packages/PLACEHOLDER/dnspython-PLACEHOLDER.tar.gz"
    sha256 "PLACEHOLDER"
  end

  # `poet` will also emit resource blocks for transitive dependencies of
  # the above (e.g. rich's own deps: markdown-it-py, pygments, etc.) —
  # paste all of them in, not just the four direct ones listed here.

  def install
    virtualenv_install_with_resources
  end

  test do
    # A real smoke test, not just "did it install" — person-check is the
    # zero-API-key command, safe to run in Homebrew's CI sandbox.
    assert_match "BACKHOE", shell_output("#{bin}/backhoe --help")
  end
end
