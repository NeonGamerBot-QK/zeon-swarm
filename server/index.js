// server.js
const express = require("express");
const http = require("http");
const SocketIo = require("socket.io");
const crypto = require("crypto");
const fs = require("fs");

const app = express();
const server = http.createServer(app);

// create io *after* server exists
const io = SocketIo(server, {
  cors: { origin: "*" },
});

const serverPub = fs.readFileSync("./data/host.pub", "utf8");
const serverPriv = fs.readFileSync("./data/host.key", "utf8");
const PORT = process.env.PORT || 3000;
const pendingChallenges = new Map();
const authenticatedSockets = new Map();

app.use(express.static("public"));

function makeNonce() {
  return crypto.randomBytes(32).toString("base64");
}

// Encrypt JSON data for a specific client
function encryptForClient(clientPublicKeyPem, payload) {
  const json = JSON.stringify(payload);

  // Generate a random AES key for this message
  const aesKey = crypto.randomBytes(32); // AES-256
  const iv = crypto.randomBytes(16);

  // Encrypt payload with AES-GCM
  const cipher = crypto.createCipheriv("aes-256-gcm", aesKey, iv);
  const encrypted = Buffer.concat([cipher.update(json, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();

  // Encrypt AES key with client’s RSA public key (RSA-OAEP)
  const encryptedKey = crypto.publicEncrypt(
    {
      key: clientPublicKeyPem,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: "sha256",
    },
    aesKey
  );

  // Return packet for client
  return {
    encryptedKey: encryptedKey.toString("base64"),
    iv: iv.toString("base64"),
    tag: tag.toString("base64"),
    encryptedData: encrypted.toString("base64"),
  };
}

// Verify RSA-PSS signature (SHA-256)
function verifySignature(publicKeyPem, message, signatureBase64) {
  try {
    const pubKeyObj = crypto.createPublicKey(publicKeyPem);
    const verify = crypto.createVerify("sha256");
    verify.update(message);
    verify.end();
    const signature = Buffer.from(signatureBase64, "base64");

    return verify.verify(
      {
        key: pubKeyObj,
        padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
        saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST,
      },
      signature
    );
  } catch (err) {
    console.error("verifySignature error:", err.message);
    return false;
  }
}

io.on("connection", (socket) => {
  console.log("socket connected", socket.id);
  socket.emit("server_public_key", serverPub);

  socket.on("client_auth", (data) => {
    const { publicKey, metadata, signature } = data;
    const message = JSON.stringify(metadata);

    const valid = verifySignature(publicKey, message, signature);
    if (valid) {
      console.log("✅ Client authenticated successfully");
      console.log("Client metadata:", metadata);
      authenticatedSockets.set(socket.id, metadata.username || socket.id);
      socket.emit("auth_success", { message: "Authenticated!" });
    } else {
      console.log("❌ Invalid signature from client");
      socket.emit("auth_failed", { message: "Invalid signature" });
    }
  });

  socket.on("private_action", (payload) => {
    const userId = authenticatedSockets.get(socket.id);
    if (!userId) {
      socket.emit("auth_required", { message: "authenticate first" });
      return;
    }
    socket.emit("private_action_ok", { message: `action done for ${userId}` });
  });

  // encrypted events
  socket.on("request_payout", (payload) => {
    const userId = authenticatedSockets.get(socket.id);
    const clientPub = publicKeyStore.get(userId);
    if (!clientPub) {
      return socket.emit("payout_error", { message: "No saved public key" });
    }

    const encryptedPacket = encryptForClient(clientPub, {
      to: userId,
      amount: payload.amount,
      currency: payload.currency,
      timestamp: Date.now(),
    });

    socket.emit("payout_encrypted", encryptedPacket);
  });
  socket.on("disconnect", () => {
    pendingChallenges.delete(socket.id);
    authenticatedSockets.delete(socket.id);
    console.log("socket disconnected", socket.id);
  });
});

app.get("/pubkey", (req, res) => {
  res.type("text/plain").send(serverPub);
});

server.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});
