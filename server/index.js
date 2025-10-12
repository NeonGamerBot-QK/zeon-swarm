// server.js
const express = require("express");
const http = require("http");
const SocketIo = require("socket.io");
const fs = require("fs");
const openpgp = require("openpgp");
const app = express();
const server = http.createServer(app);
; (async () => {
  const PORT = process.env.PORT || 4000;
  const publicKey = await openpgp.readKey({
    armoredKey: fs.readFileSync("./data/host.pub", "utf-8"),
  });
  const privKey = await openpgp.readPrivateKey({
    armoredKey: fs.readFileSync("./data/host.key", "utf-8"),
  });
  // create io *after* server exists
  const io = SocketIo(server, {
    cors: { origin: "*" },
  });
  const users = new Map();

  io.on("connection", (socket) => {
    console.log(`New client connected: ${socket.id}`);
    users.set(socket.id, socket);

    socket.on("public_key", async (data) => {
      console.log("Received public key from client:", data);
      // Here you can store the client's public key for future use
      socket.public_key = data;
      const code = Math.floor(100000 + Math.random() * 900000); // generate a 6-digit code
      socket.auth_code = code;
      // send auth challange
      const msg = await openpgp.createMessage({
        text: `${code}`,
      });
      const encrypted = await openpgp.encrypt({
        message: msg,
        encryptionKeys: await openpgp.readKey({ armoredKey: data }),
        signingKeys: privKey,
        format: "armored",
      });
      socket.emit("auth_challenge", encrypted);
    });
    socket.on("auth_response", async (data) => {
      const msg = await openpgp.readMessage({
        armoredMessage: data,
      });
      const { data: text } = await openpgp.decrypt({
        message: msg,
        verificationKeys: await openpgp.readKey({ armoredKey: socket.public_key }),
        decryptionKeys: privKey,
      });
      if (text === `${socket.auth_code}`) {
        socket.authenticated = true;
        socket.emit("auth_success");
        console.log(`Client ${socket.id} authenticated successfully.`);
      } else {
        socket.emit("auth_failure");
        console.log(`Client ${socket.id} failed to authenticate.`);
      }
    })
    function decryptMessage(encryptedMessage) {
      return openpgp.readMessage({
        armoredMessage: encryptedMessage,
      }).then((message) =>
        openpgp.decrypt({
          message,
          verificationKeys: publicKey,
          decryptionKeys: privKey,
        })
      ).then(({ data }) => data);
    }

    socket.on("on_math_response", async (data) => {
      if (!socket.authenticated) {
        console.log(`Client ${socket.id} is not authenticated. Ignoring message.`);
        return;
      }
      const msg = await decryptMessage(data);
      console.log(`Received math response from ${socket.id}:`, msg);
      socket.emit("math_response_received");
    })
  });



  app.get("/pubkey", (req, res) => {
    res.type("text/plain").send(serverPub);
  });
  app.get('/clients', (req, res) => {
    res.json({ clients: Array.from(users.keys()) });
  })

  server.listen(PORT, () => {
    console.log(`Server listening on port ${PORT}`);
  });

})();
