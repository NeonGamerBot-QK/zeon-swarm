// client.js
require("dotenv").config();
const { io } = require("socket.io-client");
const openpgp = require("openpgp");
const fs = require("fs");
const path = require("path");
const HOST_URL = process.env.SOCKET_IO_URL || "http://localhost:4000";
const socket = io(HOST_URL);

(async () => {
  if (
    !fs.existsSync("./data/client.pub") ||
    !fs.existsSync("./data/client.key")
  ) {
    console.log(
      "Client keys not found! Please generate keys first using 'node scripts/gen_key.js'",
    );
    // require file
    require("../scripts/gen_key.js");
    console.log("Client keys generated!");
    // wait 2 seconds
    await new Promise((resolve) => setTimeout(resolve, 2000));
  }

  const ipInfo = await fetch("https://ipinfo.io/json").then((r) => r.json());
  let serverPubKey = await fetch(HOST_URL + "/pubkey").then((r) => r.text());
  const publicKey = await openpgp.readKey({
    armoredKey: fs.readFileSync("./data/client.pub", "utf-8"),
  });
  const privKey = await openpgp.readPrivateKey({
    armoredKey: fs.readFileSync("./data/client.key", "utf-8"),
  });
  socket.on("connect", () => {
    console.log(`Connected to server with ID: ${socket.id}`);
  });
  socket.on("auth_challenge", async (data) => {
    console.log(`Received auth challenge from server`);
    // console.log(data, 'auth code')
    // decrypt ts
    const msg = await openpgp.readMessage({
      armoredMessage: data,
    });
    const { data: text } = await openpgp.decrypt({
      message: msg,
      verificationKeys: publicKey,
      decryptionKeys: privKey,
    });
    // encrypt and send back
    const responseMsg = await openpgp.createMessage({
      text: text,
    });
    const encrypted = await openpgp.encrypt({
      message: responseMsg,
      encryptionKeys: await openpgp.readKey({ armoredKey: serverPubKey }),
      signingKeys: privKey,
      format: "armored",
    });
    socket.on("on_ping", (data) => {
      console.log("Ping from server");
      // decrypt payload
      const decrypted = openpgp
        .readMessage({
          armoredMessage: data,
        })
        .then(async (msg) => {
          const { data: text } = await openpgp.decrypt({
            message: msg,
            verificationKeys: publicKey,
            decryptionKeys: privKey,
          });
          console.log("Decrypted ping payload");
          // reply with pong
          const pongMsg = await openpgp.createMessage({
            text: text,
          });
          const encryptedPong = await openpgp.encrypt({
            message: pongMsg,
            encryptionKeys: await openpgp.readKey({ armoredKey: serverPubKey }),
            signingKeys: privKey,
            format: "armored",
          });
          socket.emit("response_ping", encryptedPong);
        });
    });
    socket.emit("auth_response", encrypted);
    const metadata = {
      os: process.platform,
      node: process.version,
      version: require("../package.json").version,
      country: ipInfo.country ?? "UNK",
    };
    console.log("Sending metadata:", metadata);
    socket.emit(
      "metadata",
      await openpgp.encrypt({
        message: await openpgp.createMessage({
          text: JSON.stringify(metadata),
        }),
        encryptionKeys: await openpgp.readKey({ armoredKey: serverPubKey }),
        signingKeys: privKey,
        format: "armored",
      }),
    );
  });

  socket.emit("public_key", publicKey.armor());
  socket.on("auth_success", (data) => {
    console.log("Authentication successful!");
    socket.authenticated = true;
  });
  socket.on("disconnect", () => {
    console.log("Disconnected from server");
  });
  socket.on("reconnect", () => {
    console.log("Reconnecting to server...");
  });

  console.log("Client setup complete, waiting for authentication...");
  // socket.on("");
})();
