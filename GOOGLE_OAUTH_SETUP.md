# Google OAuth 2.0 Setup Guide

## How to Get Google OAuth Credentials

### Step 1: Go to Google Cloud Console
1. Visit: https://console.cloud.google.com/
2. Sign in with your Google account

### Step 2: Create a New Project (or select existing)
1. Click "Select a project" at the top
2. Click "New Project"
3. Give it a name like "Virtual Lab"

### Step 3: Enable Google+ API
1. Go to "APIs & Services" > "Library"
2. Search for "Google+ API" or "OAuth"
3. Click on it and click "Enable"

### Step 4: Configure OAuth Consent Screen
1. Go to "APIs & Services" > "OAuth consent screen"
2. Choose "External" and click "Create"
3. Fill in:
   - App name: Virtual Lab
   - User support email: your-email@gmail.com
   - Developer contact: your-email@gmail.com
4. Click "Save and Continue"

### Step 5: Create OAuth Credentials
1. Go to "APIs & Services" > "Credentials"
2. Click "Create Credentials" > "OAuth client ID"
3. Application type: "Web application"
4. Name: "Virtual Lab Client"
5. Authorized redirect URIs: Add your server URL
   - For local: `http://localhost:5000/login/google/callback`
   - For production: `https://your-domain.com/login/google/callback`
6. Click "Create"
7. Copy the **Client ID** and **Client Secret**

### Step 6: Add to Environment Variables

On your server, create or edit the environment file:

```bash
# Create .env file in admin-pi directory
nano /home/abhi/admin-pi/.env
```

Add these lines:
```bash
GOOGLE_CLIENT_ID="your-client-id-here.apps.googleusercontent.com"
GOOGLE_CLIENT_SECRET="your-client-secret-here"
```

Or set them system-wide:
```bash
# Add to /etc/environment or ~/.bashrc
export GOOGLE_CLIENT_ID="your-client-id-here.apps.googleusercontent.com"
export GOOGLE_CLIENT_SECRET="your-client-secret-here"
```

### Step 7: Restart the Service
```bash
sudo systemctl restart vlab-master.service
```

## Testing
1. Go to your login page: http://your-server:5000/login
2. Click "Continue with Google" button
3. You should be redirected to Google's sign-in page

## Troubleshooting

### Error: "redirect_uri_mismatch"
- Make sure the redirect URI in Google Console matches exactly with your server URL
- For local testing, add both localhost and your actual IP

### Error: "Internal Server Error"
- Check that credentials are correctly set
- Check server logs: `journalctl -u vlab-master.service -f`

### Error: "Google OAuth not configured"
- Make sure environment variables are set and service is restarted