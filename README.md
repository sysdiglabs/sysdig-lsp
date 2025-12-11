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

| Feature                         | **[VSCode Extension](https://github.com/sysdiglabs/vscode-extension)** | **[Sysdig LSP](./docs/features/README.md)**                            |
|---------------------------------|------------------------------------------------------------------------|------------------------------------------------------------------------|
| Scan base image in Dockerfile   | Supported                                                              | [Supported](./docs/features/scan_base_image.md) (0.1.0+)               |
| Code lens support               | Supported                                                              | [Supported](./docs/features/code_lens.md) (0.2.0+)                     |
| Build and Scan Dockerfile       | Supported                                                              | [Supported](./docs/features/build_and_scan.md) (0.4.0+)                |
| Layered image analysis          | Supported                                                              | [Supported](./docs/features/layered_analysis.md) (0.5.0+)              |
| Docker-compose image analysis   | Supported                                                              | [Supported](./docs/features/docker_compose_image_analysis.md) (0.6.0+) |
| Vulnerability explanation       | Supported                                                              | [Supported](./docs/features/vulnerability_explanation.md) (0.7.0+)     |
| K8s Manifest image analysis     | Supported                                                              | [Supported](./docs/features/k8s_manifest_image_analysis.md) (0.8.0+)  |
| Infrastructure-as-code analysis | Supported                                                              | In roadmap                                                             |

## Installation

### Pre-built Binaries (Recommended)

The easiest way to install Sysdig LSP is to download a pre-built binary from the [GitHub Releases](https://github.com/sysdiglabs/sysdig-lsp/releases) page.

1. **Download the binary for your platform:**
   - Linux x86_64: `sysdig-lsp-linux-amd64`
   - Linux ARM64: `sysdig-lsp-linux-arm64`
   - macOS x86_64 (Intel): `sysdig-lsp-darwin-amd64`
   - macOS ARM64 (Apple Silicon): `sysdig-lsp-darwin-arm64`

2. **Make it executable and move to your PATH:**
   ```bash
   # Example for Linux x86_64
   chmod +x sysdig-lsp-linux-amd64
   sudo mv sysdig-lsp-linux-amd64 /usr/local/bin/sysdig-lsp
   ```

3. **Verify the installation:**
   ```bash
   sysdig-lsp --version
   ```

### Building from Source

If you prefer to build from source or need a custom build, see the [Building from Source](#building-from-source) section below.

## Building from Source

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

[[language]]
language-servers = ["sysdig-lsp"]
name = "yaml"

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
            "highlightingModeRegex": "^(Dockerfile|YAML)$",
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
   - **Mappings > Language**:
     | Language | Language Id |
     |----------|-------------|
     | YAML     |             |
   - **Mappings > File name patterns**:
     | File name patterns  | Language ID    |
     |---------------------|----------------|
     | Dockerfile          | dockerfile     |
     | docker-compose.yml  | docker-compose |
     | compose.yml         | docker-compose |
     | docker-compose.yaml | docker-compose |
     | compose.yaml        | docker-compose |
   - **Configuration > Initialization Options**:
     ```json
     {
       "sysdig": {
         "api_url": "https://secure.sysdig.com"
       }
     }
     ```

### Vim with coc.nvim (to be reviewed)

Add the following to your `coc.nvim` configuration:

```json
"languageserver": {
  "sysdig-lsp": {
    "command": "sysdig-lsp",
    "filetypes": ["dockerfile", "yaml"],
    "initializationOptions": {
      "sysdig": {
        "api_url": "https://secure.sysdig.com"
      }
    }
  }
}
```

### Neovim with nvim-lspconfig

Install [nvim-lspconfig](https://github.com/neovim/nvim-lspconfig?tab=readme-ov-file#install):

```bash
git clone https://github.com/neovim/nvim-lspconfig ~/.config/nvim/pack/plugins/start/nvim-lspconfig
```

Now you can use `require("lspconfig")`, so add in your `~/.config/nvim/init.lua`:

```lua
local lspconfig = require("lspconfig")
local configs = require("lspconfig.configs")

if not configs.sysdig then
  configs.sysdig = {
    default_config = {
      cmd = { "sysdig-lsp" },
      root_dir = lspconfig.util.root_pattern(".git"),
      filetypes = { "dockerfile", "yaml" },
      single_file_support = true,
      init_options = {
        sysdig = {
          api_url = "https://us2.app.sysdig.com",
          -- api_token = "my_token", -- if not specified, will be retrieved from the SYSDIG_API_TOKEN env var.
        },
      },
    },
  }
end

lspconfig.sysdig.setup({})
```

### Neovim 0.11+ (without plugins)

Refer to the [Neovim LSP configuration guide](https://neovim.io/doc/user/lsp.html#lsp-config) and add the following config in `~/.config/nvim/init.lua`:

```lua
vim.lsp.config.sysdig = {
  cmd = {"sysdig-lsp"},
  root_markers = {"Dockerfile", "docker-compose.yml", "compose.yml"},
  filetypes = { "dockerfile", "yaml" },
  init_options = {
    sysdig = {
      api_url = "https://us2.app.sysdig.com",
      -- api_token = "my_token", -- if not specified, will be retrieved from the SYSDIG_API_TOKEN env var.
    },
  },
}
vim.lsp.enable("sysdig")
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
