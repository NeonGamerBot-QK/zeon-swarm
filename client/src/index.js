// client.js
require("dotenv").config();
const { io } = require("socket.io-client");
const crypto = require("crypto");

const socket = io(process.env.SOCKET_IO_URL || "http://localhost:3000");

function decryptFromServer(privateKey, packet) {
    const { encryptedKey, iv, tag, encryptedData } = packet;

    // Decrypt AES key using our private RSA key
    const aesKey = crypto.privateDecrypt(
        {
            key: privateKey,
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: "sha256",
        },
        Buffer.from(encryptedKey, "base64")
    );

    // Decrypt payload with AES-GCM
    const decipher = crypto.createDecipheriv("aes-256-gcm", aesKey, Buffer.from(iv, "base64"));
    decipher.setAuthTag(Buffer.from(tag, "base64"));

    const decrypted = Buffer.concat([
        decipher.update(Buffer.from(encryptedData, "base64")),
        decipher.final(),
    ]);

    return JSON.parse(decrypted.toString("utf8"));
}

socket.on("connect", () => {
    console.log("Connected to server:", socket.id);
});

socket.on("server_public_key", async (serverPub) => {
    console.log("Received server public key:", serverPub);

    // Generate a keypair (KeyObject form)
    const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
        modulusLength: 2048,
    });

    // Export public key as SPKI PEM (recommended)
    const publicKeyPem = publicKey.export({ type: "spki", format: "pem" });

    const metadata = { username: "saahil", timestamp: Date.now() };
    const message = JSON.stringify(metadata);

    // Sign using RSA-PSS + SHA-256 to match the server verification
    const signature = crypto.sign(
        "sha256",
        Buffer.from(message),
        {
            key: privateKey,
            padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
            saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST,
        }
    ).toString("base64");

    socket.emit("client_auth", {
        publicKey: publicKeyPem,
        metadata,
        signature,
    });
});

socket.on("auth_success", (data) => {
    console.log("✅ Auth success:", data.message);
    socket.emit("private_action", { do: "something" });
});

socket.on("auth_failed", (data) => {
    console.error("❌ Auth failed:", data.message);
});

socket.on("private_action_ok", (data) => {
    console.log(data.message);
});

socket.on("auth_required", (data) => {
    console.warn("⚠️ Need auth:", data.message);
});
socket.on("payout_encrypted", (packet) => {
    try {
        const payout = decryptFromServer(privateKey, packet);
        console.log("💸 Decrypted payout:", payout);
    } catch (err) {
        console.error("❌ Failed to decrypt payout:", err.message);
    }
});