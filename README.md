# Linux Gate Proxy

A Linux-based authentication gateway proxy that provides secure access to internal resources with LDAP/Active Directory integration, WebAuthn support, and Cloudflare Tunnel integration.

## Prerequisites

Before setting up Linux Gate Proxy, ensure you have:

- Linux system (Ubuntu/Debian recommended)
- Node.js 20.x (LTS) - **Required**
- `sudo` privileges for installation
- Git (for cloning the repository)

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/fourtytwo42/linuxGateProxy.git gateProxy
cd gateProxy
```

### 2. Install System Prerequisites

**IMPORTANT:** Run the prerequisites installation script first. This installs required system packages:

```bash
chmod +x scripts/install-prereqs.sh
sudo scripts/install-prereqs.sh
```

This script installs:
- `cloudflared` - Required for Cloudflare Tunnel integration
- `samba` - Optional, for Samba share functionality
- `zip` - Required for creating script archives

### 3. Install Node.js 20 (via nvm)

If you don't have Node.js 20 installed, use nvm:

```bash
# Install nvm if not already installed
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.0/install.sh | bash

# Load nvm in current shell
export NVM_DIR="$HOME/.nvm"
[ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"

# Install and use Node.js 20
nvm install 20
nvm use 20
nvm alias default 20
```

To make nvm available in new shells, add to your `~/.bashrc`:
```bash
export NVM_DIR="$HOME/.nvm"
[ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"
```

### 4. Install Build Tools (for Native Modules)

Some npm packages require build tools to compile native modules:

```bash
sudo apt update
sudo apt install -y build-essential libkrb5-dev python3-dev
```

### 5. Install npm Dependencies

```bash
npm install
```

This will install all required dependencies, including:
- Express web framework
- better-sqlite3 (database)
- kerberos (authentication)
- ldapts (LDAP client)
- @simplewebauthn/server (WebAuthn)
- And other dependencies

**Note:** The `kerberos` package requires Node.js 20.x for compatibility. If you encounter build errors, ensure you're using Node.js 20.

## Configuration

### Default Settings

The server defaults to:
- **Listen Address:** `0.0.0.0` (all interfaces)
- **Listen Port:** `5000` (no root privileges required)
- **HTTPS Port:** `443` (requires root if used)

### First Run Setup

1. Start the development server:
   ```bash
   npm run dev
   ```

2. Open your browser to:
   ```
   http://localhost:5000/setup
   ```

3. Complete the setup wizard to configure:
   - Site settings (listen address, port, public URL)
   - LDAP/Active Directory authentication
   - Admin portal settings
   - SMTP (for email notifications)
   - Cloudflare Tunnel (optional)

## Running the Server

### Development Mode (with auto-reload)

```bash
npm run dev
```

### Production Mode

```bash
npm start
```

The npm scripts automatically load nvm and use Node.js 20, so you don't need to manually switch versions.

## Project Structure

```
gateProxy/
├── src/
│   ├── config/          # Configuration management
│   ├── middleware/      # Express middleware
│   ├── routes/          # API routes
│   ├── services/        # Business logic services
│   └── utils/           # Utility functions
├── public/              # Static assets and frontend
├── scripts/              # Setup and configuration scripts
├── tests/               # Test files
└── package.json
```

## Key Features

- **LDAP/Active Directory Integration** - Authenticate users against your domain
- **WebAuthn Support** - Hardware security keys and biometric authentication
- **Multi-Resource Proxy** - Proxy multiple internal resources through a single gateway
- **Cloudflare Tunnel Integration** - Secure external access without exposing ports
- **Admin Portal** - Web-based administration interface
- **Samba Share** - Optional file sharing functionality
- **Certificate Management** - Automatic certificate discovery and management

## Troubleshooting

### Port Permission Errors

If you see `EACCES: permission denied` on port 80 or 443:
- Change the listen port to 5000 or higher (no root required)
- Or run with `sudo` if you need to use ports < 1024

### Native Module Build Errors

If `kerberos` or `better-sqlite3` fail to build:
1. Ensure you have build tools installed: `sudo apt install build-essential libkrb5-dev python3-dev`
2. Ensure you're using Node.js 20: `nvm use 20`
3. Rebuild: `npm rebuild kerberos better-sqlite3`

### Missing cloudflared

If you see errors about `cloudflared` not being found:
- Run: `sudo scripts/install-prereqs.sh`
- Or install manually: `sudo apt install cloudflared`

### Missing zip utility

If you see errors about `spawnSync zip ENOENT`:
- Install: `sudo apt install zip`

## Development

### Running Tests

```bash
npm test
```

### Environment Variables

- `GATE_DATA_DIR` - Override the default data directory location
- `NODE_ENV` - Set to `development` or `production`

## License

ISC

## Support

For issues and questions, please open an issue on the GitHub repository.

