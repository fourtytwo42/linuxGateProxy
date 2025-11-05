# Setup Guide

This guide walks you through the complete setup process for Linux Gate Proxy.

## Step-by-Step Installation

### Step 1: Clone the Repository

```bash
git clone https://github.com/fourtytwo42/linuxGateProxy.git gateProxy
cd gateProxy
```

### Step 2: Install System Prerequisites

**CRITICAL:** This step must be run before installing npm dependencies. The script installs:
- `cloudflared` - Required for Cloudflare Tunnel functionality
- `samba` - Optional, enables Samba share features
- `zip` - Required for creating script archives

```bash
chmod +x scripts/install-prereqs.sh
sudo scripts/install-prereqs.sh
```

**Note:** You will need sudo privileges and your sudo password.

### Step 3: Install Node.js Version Manager (nvm)

If you don't have Node.js 20 installed:

```bash
# Install nvm
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.0/install.sh | bash

# Reload your shell configuration
source ~/.bashrc
# OR start a new terminal session
```

### Step 4: Install Node.js 20

```bash
# Load nvm (if not already loaded)
export NVM_DIR="$HOME/.nvm"
[ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"

# Install Node.js 20 LTS
nvm install 20
nvm use 20
nvm alias default 20

# Verify installation
node --version  # Should show v20.x.x
npm --version
```

### Step 5: Install Build Tools

Some npm packages (like `kerberos` and `better-sqlite3`) are native modules that need to be compiled:

```bash
sudo apt update
sudo apt install -y build-essential libkrb5-dev python3-dev
```

### Step 6: Install npm Dependencies

```bash
npm install
```

This will:
- Download and install all npm packages
- Compile native modules (`kerberos`, `better-sqlite3`)
- Set up the project structure

**Expected output:** You should see "added 213 packages" or similar. If you see build errors for `kerberos`, ensure you're using Node.js 20 and have build tools installed.

### Step 7: Verify Installation

Check that native modules compiled successfully:

```bash
node -e "require('kerberos'); console.log('Kerberos: OK')"
node -e "require('better-sqlite3'); console.log('better-sqlite3: OK')"
```

Both should print "OK" without errors.

### Step 8: Start the Server

```bash
npm run dev
```

You should see:
```
Now using node v20.19.5 (npm v10.8.2)
Server listening { listenAddress: '0.0.0.0', listenPort: 5000 }
```

### Step 9: Complete Initial Setup

1. Open your browser: `http://localhost:5000/setup`
2. Follow the setup wizard to configure:
   - **Site Settings**: Listen address, port, public URL
   - **Authentication**: LDAP/Active Directory connection details
   - **Admin Portal**: Access settings
   - **SMTP**: Email server configuration (optional)
   - **Cloudflare Tunnel**: Tunnel configuration (optional)

## Common Issues and Solutions

### Issue: "EACCES: permission denied 0.0.0.0:80"

**Solution:** The default port was changed to 5000. If you still see this:
- Check if you have a saved config with port 80
- The server will fall back to port 5000 if no config exists
- To use port 80, run with `sudo` or configure via the setup page

### Issue: "spawnSync zip ENOENT"

**Solution:** Install the zip utility:
```bash
sudo apt install zip
```

### Issue: "kerberos module build failed"

**Causes:**
- Wrong Node.js version (need v20)
- Missing build tools

**Solution:**
```bash
# Ensure Node.js 20
nvm use 20
node --version  # Verify it's v20.x

# Ensure build tools
sudo apt install -y build-essential libkrb5-dev python3-dev

# Rebuild
npm rebuild kerberos better-sqlite3
```

### Issue: "cloudflared binary is not installed"

**Solution:** Run the prerequisites script:
```bash
sudo scripts/install-prereqs.sh
```

### Issue: "The module was compiled against a different Node.js version"

**Solution:** This happens when switching Node.js versions:
```bash
# Ensure you're using Node.js 20
nvm use 20

# Rebuild native modules
npm rebuild
```

## Verification Checklist

After installation, verify:

- [ ] `cloudflared --version` shows version info
- [ ] `node --version` shows v20.x.x
- [ ] `npm install` completed without errors
- [ ] Native modules load without errors
- [ ] Server starts on port 5000
- [ ] Setup page accessible at `http://localhost:5000/setup`

## Production Deployment

For production:

1. Set `NODE_ENV=production`
2. Use a process manager like `pm2` or `systemd`
3. Configure reverse proxy (nginx/Apache) if needed
4. Set up SSL certificates
5. Configure firewall rules
6. Set up log rotation
7. Configure monitoring

Example with pm2:
```bash
npm install -g pm2
pm2 start npm --name "gateproxy" -- start
pm2 save
pm2 startup
```

## Next Steps

After successful setup:
1. Complete the initial setup wizard
2. Configure LDAP/Active Directory authentication
3. Add resources to proxy
4. Configure Cloudflare Tunnel (if using)
5. Test authentication flow
6. Set up admin users

## Getting Help

If you encounter issues:
1. Check the error messages in the console
2. Review the [README.md](README.md) troubleshooting section
3. Check GitHub issues for similar problems
4. Open a new issue with:
   - Error messages
   - Node.js version (`node --version`)
   - OS version
   - Steps you've already taken

