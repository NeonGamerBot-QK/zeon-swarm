// client.js
require("dotenv").config();
const { io } = require("socket.io-client");
const crypto = require("crypto");

const socket = io(process.env.SOCKET_IO_URL || "http://localhost:3000");
