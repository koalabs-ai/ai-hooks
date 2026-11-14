# Minimal flake. Untested: Nix is not installed on the machine this was prepared on.
# Put it at the repository root as flake.nix (it builds from the checkout), run `nix build`,
# and replace vendorHash with the hash Nix reports on the first build (there are no external
# dependencies, so vendorHash = null should work).
{
  description = "Command guard and output redactor that keep secrets out of AI agent transcripts";
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
      forAll = f: nixpkgs.lib.genAttrs systems (s: f nixpkgs.legacyPackages.${s});
    in {
      packages = forAll (pkgs: {
        default = pkgs.buildGoModule {
          pname = "ai-hooks";
          version = "0.1.0";
          src = ./.;
          vendorHash = null;
          subPackages = [ "cmd/ai-hooks" ];
          env.CGO_ENABLED = 0;
          ldflags = [ "-s" "-w" "-X main.version=0.1.0" ];
          meta = {
            description = "Command guard and output redactor that keep secrets out of AI agent transcripts";
            license = pkgs.lib.licenses.asl20;
            mainProgram = "ai-hooks";
          };
        };
      });
    };
}
