// a server needs keys! share keys! trade keys!
const crypto = require("crypto");
const { writeFileSync, existsSync } = require("fs");
if (existsSync("./data/host.pub") || existsSync("./data/host.key")) {
  console.log(
    `Keys exist already!, if you want to replace them remove the old ones!!`,
  );
  return;
}
// Generate RSA key pair (2048-bit is standard; 3072 or 4096 is stronger)
const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
  modulusLength: 4096,
  publicKeyEncoding: {
    type: "spki", // Recommended format for RSA public keys
    format: "pem",
  },
  privateKeyEncoding: {
    type: "pkcs8", // Recommended format for RSA private keys
    format: "pem",
  },
});

console.log("Public Key:\n", publicKey);
console.log("Private Key:\n", privateKey);
writeFileSync("./data/host.pub", publicKey);
writeFileSync("./data/host.key", privateKey);
