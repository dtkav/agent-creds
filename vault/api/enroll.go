package api

import (
	"net/http"
)

// handleEnrollPage serves the enrollment page
func (s *Server) handleEnrollPage(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("user")
	if username == "" {
		http.Error(w, "Missing user parameter", http.StatusBadRequest)
		return
	}

	// Verify user exists
	user, err := s.db.GetUserByName(username)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	if user == nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}
	if !user.Active {
		http.Error(w, "User is not active", http.StatusForbidden)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(enrollmentHTML))
}

const enrollmentHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Enroll Security Key - Agent Credentials</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #0a0a0a;
            color: #e0e0e0;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        .container {
            max-width: 400px;
            width: 100%;
        }
        .card {
            background: #1a1a1a;
            border-radius: 12px;
            padding: 32px;
            border: 1px solid #333;
        }
        h1 {
            font-size: 24px;
            font-weight: 600;
            margin-bottom: 8px;
            color: #fff;
        }
        .subtitle {
            color: #888;
            margin-bottom: 24px;
        }
        .username {
            font-family: monospace;
            background: #2a2a2a;
            padding: 2px 8px;
            border-radius: 4px;
            color: #4ade80;
        }
        .status {
            padding: 16px;
            border-radius: 8px;
            margin-bottom: 24px;
            display: none;
        }
        .status.info {
            background: #1e3a5f;
            border: 1px solid #3b82f6;
            color: #93c5fd;
            display: block;
        }
        .status.success {
            background: #14532d;
            border: 1px solid #22c55e;
            color: #86efac;
            display: block;
        }
        .status.error {
            background: #450a0a;
            border: 1px solid #ef4444;
            color: #fca5a5;
            display: block;
        }
        .status.waiting {
            background: #422006;
            border: 1px solid #f59e0b;
            color: #fcd34d;
            display: block;
        }
        button {
            width: 100%;
            padding: 14px 24px;
            font-size: 16px;
            font-weight: 500;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            background: #4ade80;
            color: #0a0a0a;
            transition: background 0.2s;
        }
        button:hover:not(:disabled) {
            background: #22c55e;
        }
        button:disabled {
            opacity: 0.5;
            cursor: not-allowed;
        }
        .icon {
            font-size: 48px;
            text-align: center;
            margin-bottom: 16px;
        }
        .instructions {
            margin-top: 24px;
            padding-top: 24px;
            border-top: 1px solid #333;
        }
        .instructions h3 {
            font-size: 14px;
            font-weight: 600;
            margin-bottom: 12px;
            color: #888;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .instructions ol {
            padding-left: 20px;
            color: #aaa;
            line-height: 1.8;
        }
        .credentials-list {
            margin-top: 16px;
            padding: 12px;
            background: #2a2a2a;
            border-radius: 8px;
        }
        .credentials-list h4 {
            font-size: 12px;
            color: #888;
            margin-bottom: 8px;
            text-transform: uppercase;
        }
        .credential-item {
            font-family: monospace;
            font-size: 12px;
            color: #aaa;
            padding: 4px 0;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="card">
            <div class="icon">🔐</div>
            <h1>Enroll Security Key</h1>
            <p class="subtitle">Register a FIDO2 security key for <span class="username" id="username"></span></p>

            <div id="status" class="status"></div>

            <button id="enrollBtn" onclick="startEnrollment()">
                Register Security Key
            </button>

            <div class="instructions">
                <h3>Instructions</h3>
                <ol>
                    <li>Insert your YubiKey or other FIDO2 security key</li>
                    <li>Click "Register Security Key"</li>
                    <li>Touch your security key when it blinks</li>
                    <li>Done! Your key is now registered</li>
                </ol>
            </div>

            <div id="credentialsList" class="credentials-list" style="display: none;">
                <h4>Registered Keys</h4>
                <div id="credentials"></div>
            </div>
        </div>
    </div>

    <script>
        const username = new URLSearchParams(window.location.search).get('user');
        document.getElementById('username').textContent = username;

        function setStatus(type, message) {
            const status = document.getElementById('status');
            status.className = 'status ' + type;
            status.textContent = message;
        }

        function setButtonState(disabled, text) {
            const btn = document.getElementById('enrollBtn');
            btn.disabled = disabled;
            if (text) btn.textContent = text;
        }

        async function startEnrollment() {
            if (!username) {
                setStatus('error', 'No username specified');
                return;
            }

            try {
                setButtonState(true, 'Starting...');
                setStatus('info', 'Initializing registration...');

                // Begin registration
                const beginResp = await fetch('/api/webauthn/register/begin', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username })
                });

                if (!beginResp.ok) {
                    const err = await beginResp.json();
                    throw new Error(err.error || 'Failed to start registration');
                }

                const { options, sessionId } = await beginResp.json();

                // Convert base64url to ArrayBuffer
                options.publicKey.challenge = base64urlToBuffer(options.publicKey.challenge);
                options.publicKey.user.id = base64urlToBuffer(options.publicKey.user.id);
                if (options.publicKey.excludeCredentials) {
                    options.publicKey.excludeCredentials = options.publicKey.excludeCredentials.map(c => ({
                        ...c,
                        id: base64urlToBuffer(c.id)
                    }));
                }

                setStatus('waiting', 'Touch your security key...');

                // Create credential
                const credential = await navigator.credentials.create(options);

                setStatus('info', 'Verifying with server...');

                // Prepare the response
                const response = {
                    sessionId,
                    response: {
                        id: credential.id,
                        rawId: bufferToBase64url(credential.rawId),
                        type: credential.type,
                        response: {
                            clientDataJSON: bufferToBase64url(credential.response.clientDataJSON),
                            attestationObject: bufferToBase64url(credential.response.attestationObject)
                        }
                    }
                };

                // Finish registration
                const finishResp = await fetch('/api/webauthn/register/finish', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(response)
                });

                if (!finishResp.ok) {
                    const err = await finishResp.json();
                    throw new Error(err.error || 'Failed to complete registration');
                }

                setStatus('success', 'Security key registered successfully!');
                setButtonState(false, 'Register Another Key');

            } catch (err) {
                console.error('Enrollment error:', err);
                if (err.name === 'NotAllowedError') {
                    setStatus('error', 'Registration cancelled or timed out');
                } else if (err.name === 'SecurityError') {
                    setStatus('error', 'Security error: Make sure you are using HTTPS');
                } else {
                    setStatus('error', err.message || 'Registration failed');
                }
                setButtonState(false, 'Try Again');
            }
        }

        function base64urlToBuffer(base64url) {
            const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
            const padding = '='.repeat((4 - base64.length % 4) % 4);
            const binary = atob(base64 + padding);
            const bytes = new Uint8Array(binary.length);
            for (let i = 0; i < binary.length; i++) {
                bytes[i] = binary.charCodeAt(i);
            }
            return bytes.buffer;
        }

        function bufferToBase64url(buffer) {
            const bytes = new Uint8Array(buffer);
            let binary = '';
            for (let i = 0; i < bytes.length; i++) {
                binary += String.fromCharCode(bytes[i]);
            }
            return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
        }
    </script>
</body>
</html>`
