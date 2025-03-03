{ rustPlatform, ... }:
let
  cargoFile = builtins.fromTOML (builtins.readFile ./Cargo.toml);
in
rustPlatform.buildRustPackage {
  pname = cargoFile.package.name;
  version = cargoFile.package.version;
  src = ./.;
  cargoLock = {
    lockFile = ./Cargo.lock;
  };

  doCheck = false;
  meta.mainProgram = "sysdig-lsp";
}
