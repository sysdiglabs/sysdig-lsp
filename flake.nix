{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };
  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
    }:
    let
      overlays.default = final: prev: {
        sysdig-lsp = prev.pkgsStatic.callPackage ./package.nix { };
      };

      flake = flake-utils.lib.eachDefaultSystem (
        system:
        let
          pkgs = import nixpkgs {
            inherit system;
            config.allowUnfree = true;
            overlays = [ self.overlays.default ];
          };
        in
        {
          packages = with pkgs; {
            inherit sysdig-lsp;
            default = sysdig-lsp;

            sysdig-lsp-linux-amd64 = pkgsCross.gnu64.sysdig-lsp;
            sysdig-lsp-linux-arm64 = pkgsCross.aarch64-multiplatform.sysdig-lsp;
            sysdig-lsp-darwin-amd64 = pkgsCross.x86_64-darwin.sysdig-lsp;
            sysdig-lsp-darwin-arm64 = pkgsCross.aarch64-darwin.sysdig-lsp;
          };

          devShells.default =
            with pkgs;
            mkShell {
              packages = [
                cargo
                rustc
                rustfmt
                cargo-audit
                cargo-watch
                cargo-nextest
                cargo-expand
                clippy
                just
                rust-analyzer
                lldb
                pre-commit
                sysdig-cli-scanner
              ];

              inputsFrom = [ sysdig-lsp ];

              shellHook = ''
                pre-commit install
                export PATH="$PWD/target/debug:$PWD/target/release:$PATH"
              '';

            };

          formatter = pkgs.nixfmt-rfc-style;
        }
      );
    in
    flake // { inherit overlays; };
}
