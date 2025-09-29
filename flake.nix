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
        sysdig-lsp = prev.callPackage ./package.nix { };
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

            sysdig-lsp-linux-amd64 = pkgsCross.gnu64.pkgsStatic.sysdig-lsp;
            sysdig-lsp-linux-arm64 = pkgsCross.aarch64-multiplatform.pkgsStatic.sysdig-lsp;
            sysdig-lsp-darwin-amd64 = pkgsCross.x86_64-darwin.sysdig-lsp;
            sysdig-lsp-darwin-arm64 = pkgsCross.aarch64-darwin.sysdig-lsp;
            sysdig-lsp-windows-amd64 = pkgsCross.mingwW64.sysdig-lsp;
          };

          devShells.default =
            with pkgs;
            mkShell {
              packages = [
                cargo
                cargo-audit
                cargo-expand
                cargo-nextest
                cargo-tarpaulin
                cargo-watch
                clippy
                just
                lldb
                pre-commit
                rust-analyzer
                rustc
                rustfmt
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
