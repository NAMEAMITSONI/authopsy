class Authopsy < Formula
  desc "RBAC vulnerability scanner for REST APIs"
  homepage "https://github.com/burakozcn01/authopsy"
  url "https://github.com/burakozcn01/authopsy/archive/refs/tags/v1.0.0.tar.gz"
  sha256 "8695f502537f14cab5036fd8e5cde42e76a18a60dfe109e39439c068b10d17bb"
  license "MIT"
  head "https://github.com/burakozcn01/authopsy.git", branch: "main"

  depends_on "rust" => :build

  def install
    system "cargo", "install", *std_cargo_args
  end

  test do
    assert_match "authopsy #{version}", shell_output("#{bin}/authopsy --version")
  end
end
