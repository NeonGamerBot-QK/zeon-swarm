const express = require("express");
const SocketIo = require("socket.io");
const io = SocketIo();
const app = express();
const http = require("http");
const server = http.createServer(app);
const crypto = require("crypto");
const fs = require("fs");
const serverPub = fs.readFileSync("./data/host.pub").toString();
const serverPriv = fs.readFileSync("./data/host.key").toString();
const PORT = process.env.PORT || 3000;
const publicKeyStore = new Map(); // userId -> publicKeyPEM
const pendingChallenges = new Map(); // socketId -> {nonce, expiresAt, userId}
const authenticatedSockets = new Map(); // socketId -> userId
app.use(express.static("public"));
// Utility: create a random nonce (base64)
function makeNonce() {
  return crypto.randomBytes(32).toString("base64");
}


// Utility: verify RSA-PSS signature (SHA-256)
function verifySignature(publicKeyPem, message, signatureBase64) {
  const verify = crypto.createVerify("SHA256");
  verify.update(message);
  verify.end();
  const signature = Buffer.from(signatureBase64, "base64");

  // Using RSA-PSS
  return verify.verify(
    {
      key: publicKeyPem,
      padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
      saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST,
    },
    signature,
  );
}

io.attach(server);
io.on("connection", (socket) => {
  console.log("socket connected", socket.id);
  // Send the server's public key
  socket.emit("server_public_key", serverPub);

  // Listen for client's auth event
  socket.on("client_auth", (data) => {
    const { publicKey, metadata, signature } = data;
    const message = JSON.stringify(metadata);

    const valid = verifySignature(publicKey, message, signature);
    if (valid) {
      console.log("✅ Client authenticated successfully");
      console.log("Client metadata:", metadata);
      socket.emit("auth_success", { message: "Authenticated!" });
    } else {
      console.log("❌ Invalid signature from client");
      socket.emit("auth_failed", { message: "Invalid signature" });
    }
  });

  // Example of verifying authenticated access for other events
  socket.on("private_action", (payload) => {
    const userId = authenticatedSockets.get(socket.id);
    if (!userId) {
      socket.emit("auth_required", { message: "authenticate first" });
      return;
    }
    // ... handle action for userId
    socket.emit("private_action_ok", { message: `action done for ${userId}` });
  });

  socket.on("disconnect", () => {
    pendingChallenges.delete(socket.id);
    authenticatedSockets.delete(socket.id);
    console.log("socket disconnected", socket.id);
  });
});
server.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});
