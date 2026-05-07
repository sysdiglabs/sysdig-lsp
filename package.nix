{
  naersk,
  pkgsStatic,
  lib,
  stdenv,
  pkg-config,
  openssl,
}:
let
  cargoFile = builtins.fromTOML (builtins.readFile ./Cargo.toml);
in
naersk.buildPackage {
  pname = cargoFile.package.name;
  version = cargoFile.package.version;
  src = ./.;

  nativeBuildInputs = [
    pkg-config
  ];

  buildInputs = [
    openssl.dev
  ]
  ++ lib.optionals stdenv.hostPlatform.isDarwin (with pkgsStatic; [ libiconv ]);

  doCheck = false;
  meta.mainProgram = "sysdig-lsp";
}
