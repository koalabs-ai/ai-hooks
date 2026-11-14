# Template for a tap formula (koalabs-ai/homebrew-tap/Formula/ai-hooks.rb). Fill the versions and
# sha256 values from the release's checksums.txt. Untested here: Homebrew is not installed on this machine.
class AiHooks < Formula
  desc "Command guard and output redactor that keep secrets out of AI agent transcripts"
  homepage "https://github.com/koalabs-ai/ai-hooks"
  version "0.1.0"
  license "Apache-2.0"

  on_macos do
    on_arm do
      url "https://github.com/koalabs-ai/ai-hooks/releases/download/v#{version}/ai-hooks_#{version}_darwin_arm64.tar.gz"
      sha256 "REPLACE_WITH_SHA256_darwin_arm64"
    end
    on_intel do
      url "https://github.com/koalabs-ai/ai-hooks/releases/download/v#{version}/ai-hooks_#{version}_darwin_amd64.tar.gz"
      sha256 "REPLACE_WITH_SHA256_darwin_amd64"
    end
  end
  on_linux do
    on_arm do
      url "https://github.com/koalabs-ai/ai-hooks/releases/download/v#{version}/ai-hooks_#{version}_linux_arm64.tar.gz"
      sha256 "REPLACE_WITH_SHA256_linux_arm64"
    end
    on_intel do
      url "https://github.com/koalabs-ai/ai-hooks/releases/download/v#{version}/ai-hooks_#{version}_linux_amd64.tar.gz"
      sha256 "REPLACE_WITH_SHA256_linux_amd64"
    end
  end

  def install
    bin.install "ai-hooks"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/ai-hooks version")
    assert_match "REDACTED:aws-access-key", pipe_output("#{bin}/ai-hooks redact", "AKIAIOSFODNN7EXAMPLE\n")
  end
end
