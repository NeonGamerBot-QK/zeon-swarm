// client.js
require("dotenv").config();
const { io } = require("socket.io-client");
const openpgp = require("openpgp");
const fs = require("fs");
const socket = io(process.env.SOCKET_IO_URL || "http://localhost:4000");
(async () => {
    let serverPubKey;
    const publicKey = await openpgp.readKey({
        armoredKey: fs.readFileSync("./data/host.pub", "utf-8"),
    });
    const privKey = await openpgp.readPrivateKey({
        armoredKey: fs.readFileSync("./data/host.key", "utf-8"),
    });
    socket.on("connect", () => {
        console.log(`Connected to server with ID: ${socket.id}`);
    });
    socket.on("");
})();
