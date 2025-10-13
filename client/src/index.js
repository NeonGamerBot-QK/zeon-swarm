// client.js
require("dotenv").config();
const { io } = require("socket.io-client");
const openpgp = require("openpgp");
const fs = require("fs");
const path = require("path");
const HOST_URL = process.env.SOCKET_IO_URL || "http://localhost:4000";
const socket = io(HOST_URL);
(async () => {
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
    socket.emit("auth_response", encrypted);
    const metadata = {
      os: process.platform,
      node: process.version,
      version: require(path.join(__dirname, "..", "/package.json")).version,
      country: ipInfo.country ?? "UNK",
    };
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
  // socket.on("");
})();
