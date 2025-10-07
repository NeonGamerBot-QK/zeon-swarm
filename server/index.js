const express = require("express");
const SocketIo = require("socket-io");
const io = SocketIo();
const app = express();
const http = require("http");
const server = http.createServer(app);
const crypto = require('crypto');
const PORT = process.env.PORT || 3000;
const publicKeyStore = new Map(); // userId -> publicKeyPEM
const pendingChallenges = new Map(); // socketId -> {nonce, expiresAt, userId}
const authenticatedSockets = new Map(); // socketId -> userId
app.use(express.static("public"));
// Utility: create a random nonce (base64)
function makeNonce() {
    return crypto.randomBytes(32).toString('base64');
}

// Utility: verify RSA-PSS signature (SHA-256)
function verifySignature(publicKeyPem, message, signatureBase64) {
    const verify = crypto.createVerify('SHA256');
    verify.update(message);
    verify.end();
    const signature = Buffer.from(signatureBase64, 'base64');

    // Using RSA-PSS
    return verify.verify(
        {
            key: publicKeyPem,
            padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
            saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST
        },
        signature
    );
}

io.attach(server);
io.on('connection', (socket) => {
    console.log('socket connected', socket.id);

    // Step 1: Client sends its public key and optional userId to "public_key"
    // data: { userId: 'alice', publicKey: '-----BEGIN PUBLIC KEY-----\n...' }
    socket.on('public_key', (data) => {
        try {
            if (!data || !data.publicKey || !data.userId) {
                socket.emit('auth_error', { message: 'publicKey and userId required' });
                return;
            }

            const { userId, publicKey } = data;

            // (Optional) register the public key for this userId (persist in DB)
            publicKeyStore.set(userId, publicKey);

            // Create challenge (nonce) and expire it in e.g. 60 seconds
            const nonce = makeNonce();
            const expiresAt = Date.now() + 60_000; // 60s
            pendingChallenges.set(socket.id, { nonce, expiresAt, userId });

            // Send challenge to client
            socket.emit('challenge', { nonce, expiresAt });
            console.log(`Sent challenge to ${socket.id} for user=${userId}`);
        } catch (err) {
            console.error(err);
            socket.emit('auth_error', { message: 'server error creating challenge' });
        }
    });

    // Step 3: Client responds with signed nonce
    // data: { userId: 'alice', nonce: '...', signature: 'base64' }
    socket.on('challenge_response', (data) => {
        try {
            const pending = pendingChallenges.get(socket.id);
            if (!pending) {
                socket.emit('auth_error', { message: 'no pending challenge' });
                return;
            }

            const { userId, nonce: expectedNonce, expiresAt } = pending;
            if (Date.now() > expiresAt) {
                pendingChallenges.delete(socket.id);
                socket.emit('auth_error', { message: 'challenge expired' });
                return;
            }

            if (!data || data.userId !== userId || data.nonce !== expectedNonce || !data.signature) {
                socket.emit('auth_error', { message: 'invalid response' });
                return;
            }

            const publicKeyPem = publicKeyStore.get(userId);
            if (!publicKeyPem) {
                socket.emit('auth_error', { message: 'unknown user or public key' });
                return;
            }

            const ok = verifySignature(publicKeyPem, expectedNonce, data.signature);
            if (!ok) {
                socket.emit('auth_failed', { message: 'signature invalid' });
                return;
            }

            // Auth success
            authenticatedSockets.set(socket.id, userId);
            pendingChallenges.delete(socket.id);
            socket.emit('auth_success', { userId });
            console.log(`Socket ${socket.id} authenticated as ${userId}`);
        } catch (err) {
            console.error(err);
            socket.emit('auth_error', { message: 'server verify error' });
        }
    });

    // Example of verifying authenticated access for other events
    socket.on('private_action', (payload) => {
        const userId = authenticatedSockets.get(socket.id);
        if (!userId) {
            socket.emit('auth_required', { message: 'authenticate first' });
            return;
        }
        // ... handle action for userId
        socket.emit('private_action_ok', { message: `action done for ${userId}` });
    });

    socket.on('disconnect', () => {
        pendingChallenges.delete(socket.id);
        authenticatedSockets.delete(socket.id);
        console.log('socket disconnected', socket.id);
    });
})
server.listen(PORT, () => {
    console.log(`Server listening on port ${PORT}`);
});
