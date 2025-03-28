# Sysdig LSP

**Sysdig LSP** is a Language Server Protocol implementation that integrates vulnerability scanning directly into your editor.
It enables quick scans of Dockerfiles, Docker Compose files, Kubernetes manifests, and Infrastructure-as-Code (IaC) files,
helping you detect vulnerabilities and misconfigurations earlier in the development process.

> [!NOTE]
> For Visual Studio Code users, we highly recommend the [Sysdig VSCode Extension](https://marketplace.visualstudio.com/items?itemName=sysdig.sysdig-vscode-ext).
>
> This extension currently provides full LSP functionality and additional features for the best experience.
>
> In the future, the extension will internally leverage the Sysdig LSP implementation, ensuring consistent features and a unified experience across all editors.
>
> Repository: [https://github.com/sysdiglabs/sysdig-lsp](https://github.com/sysdiglabs/sysdig-lsp)

## Features

| Feature                         | **[VSCode Extension](https://github.com/sysdiglabs/vscode-extension)** | **Sysdig LSP**                                           |
|---------------------------------|------------------------------------------------------------------------|----------------------------------------------------------|
| Scan base image in Dockerfile   | Supported                                                              | [Supported](./docs/features/scan_base_image.md) (0.1.0+) |
| Code lens support               | Supported                                                              | [Supported](./docs/features/code_lens.md) (0.2.0+)       |
| Build and Scan Dockerfile       | Supported                                                              | In roadmap                                               |
| Layered image analysis          | Supported                                                              | In roadmap                                               |
| Docker-compose image analysis   | Supported                                                              | In roadmap                                               |
| K8s Manifest image analysis     | Supported                                                              | In roadmap                                               |
| Infrastructure-as-code analysis | Supported                                                              | In roadmap                                               |
| Vulnerability explanation       | Supported                                                              | In roadmap                                               |

## Build

Sysdig LSP is developed in Rust and can be built using Cargo or Nix (a flake is provided). Follow these steps for your preferred method:

### Building with Cargo

1. **Install Rust and Cargo:**
   Ensure you have [Rust](https://www.rust-lang.org/tools/install) installed.

2. **Clone the Repository:**
   ```bash
   git clone https://github.com/sysdiglabs/sysdig-lsp.git
   cd sysdig-lsp
   ```

3. **Build in Release Mode:**
   ```bash
   cargo build --release
   ```

### Building with Nix

1. **Install Nix:**
   Follow the instructions at [Nix Installation](https://nixos.org/download.html).

2. **Clone the Repository:**
   ```bash
   git clone https://github.com/sysdiglabs/sysdig-lsp.git
   cd sysdig-lsp
   ```

3. **Build Using the Flake:**
   ```bash
   nix build .#sysdig-lsp
   ```

#### Cross-compiling with Nix

Cross-compilation is made easy with Nix, we have prepared some targets that you can execute to build the binaries as static files.
Not all cross-compilations are supported though:

|                    | **Target Linux** | **Target MacOS** | **Target Windows** |
|--------------------|------------------|------------------|--------------------|
| **Host Linux**     |        ✅        |        ❌        |         ✅         |
| **Host MacOS**     |        ✅        |        ✅        |         ✅         |
| **Host Windows**   |        ❌        |        ❌        |         ❌         |

The following binaries are built:

- Linux x86_64: `nix build .#sysdig-lsp-linux-amd64`
- Linux aarch64: `nix build .#sysdig-lsp-linux-arm64`
- Darwin x86_64: `nix build .#sysdig-lsp-darwin-amd64`
- Darwin aarch64: `nix build .#sysdig-lsp-darwin-arm64`

Windows is not yet supported because the Sysdig CLI Scanner is not releasing a .exe for now, but you can still build it with `nix build .#sysdig-lsp-windows-amd64`

The result of the compilation will be saved in `./result/bin`.

## Configuration Options

Sysdig LSP supports two configuration options for connecting to Sysdig’s services:

| **Option**         | **Description**                                                                                            | **Example Value**                       |
|--------------------|------------------------------------------------------------------------------------------------------------|-----------------------------------------|
| `sysdig.api_url`   | The URL endpoint for Sysdig's API. Set this to your instance's API endpoint.                               | `https://secure.sysdig.com`             |
| `sysdig.api_token` | The API token for authentication. If omitted, the `SECURE_API_TOKEN` environment variable is used instead. | `"your token"` (if required)            |

## Editor Configurations

Below are detailed instructions for configuring Sysdig LSP in various editors.

### Helix Editor

Add the following configuration to your `languages.toml` file:

```toml
[[language]]
language-servers = ["docker-langserver", "sysdig-lsp"]
name = "dockerfile"

[language-server.sysdig-lsp]
command = "sysdig-lsp"

[language-server.sysdig-lsp.config]
sysdig.api_url = "https://secure.sysdig.com" # Replace with your API URL.
# sysdig.api_token = "your token" # If omitted, the SECURE_API_TOKEN environment variable will be used.
```

### Kate Editor

Navigate to **Settings > Configure Kate > LSP Client > User Server Settings** and add:

```json
{
    "servers": {
        "01-sysdig-lsp": {
            "command": ["sysdig-lsp"],
            "root": "",
            "highlightingModeRegex": "^Dockerfile$",
            "initializationOptions": {
                "sysdig": {
                    "api_url": "https://secure.sysdig.com"
                }
            }
        }
    }
}
```

### JetBrains IDEs


> [!WARNING]
> The configuration for JetBrains IDEs is not definitive.
> In the future, we plan to develop a dedicated plugin that will automatically manage the LSP and expand its functionalities.
> In the meantime, you can use the [LSP4IJ](https://plugins.jetbrains.com/plugin/23257-lsp4ij) plugin for initial day-one support.

1. Install the [LSP4IJ](https://plugins.jetbrains.com/plugin/23257-lsp4ij) plugin.
2. Open the LSP Client config (usually near the Terminal), click **New Language Server** and configure:
   - **Server > Command**: `sysdig-lsp`
   - **Mappings > File name patterns**: Include `Dockerfile`
   - **Language ID**: `dockerfile`
   - **Configuration > Initialization Options**:
     ```json
     {
       "sysdig": {
         "api_url": "https://secure.sysdig.com"
       }
     }
     ```

### Vim with coc.nvim

Add the following to your `coc.nvim` configuration:

```json
"languageserver": {
  "sysdig-lsp": {
    "command": "sysdig-lsp",
    "filetypes": ["dockerfile"],
    "initializationOptions": {
      "sysdig": {
        "api_url": "https://secure.sysdig.com"
      }
    }
  }
}
```

### Neovim with nvim-lspconfig

Refer to the [Neovim LSP configuration guide](https://neovim.io/doc/user/lsp.html#lsp-config) and add:

```lua
return {
  default_config = {
    cmd = { 'sysdig-lsp' },
    root_dir = util.root_pattern('.git'),
    filetypes = {
      'dockerfile',
    },
    single_file_support = true,
    init_options = {
      activateSnykCode = 'true',
    },
  },
}
```

## Hacking

For contributors, using `nix develop` provides a fully managed development environment that includes all the necessary dependencies and tools—using the same versions as the development team. Simply run:

```bash
nix develop
```

from the repository root to enter a shell configured for building, testing, and editing Sysdig LSP.

## Contributing

Contributions are welcome. Please open issues or submit pull requests to help enhance Sysdig LSP.

## License

This project is licensed under the [Apache License 2.0](LICENSE).
