{
  rustPlatform,
  pkg-config,
  openssl,
  ...
}:
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

  nativeBuildInputs = [
    pkg-config
  ];

  buildInputs = [
    openssl.dev
  ];

  doCheck = false;
  meta.mainProgram = "sysdig-lsp";
}
