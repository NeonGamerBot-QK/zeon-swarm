// a server needs keys! share keys! trade keys!
const crypto = require("crypto");
const { writeFileSync, existsSync } = require("fs");
const openpgp = require("openpgp");
if (existsSync("./data/host.pub") || existsSync("./data/host.key")) {
  console.log(
    `Keys exist already!, if you want to replace them remove the old ones!!`,
  );
  return;
}
(async () => {
  const { privateKey, publicKey, revocationCertificate } = await openpgp.generateKey({
    type: 'ecc', // Type of the key, defaults to ECC
    curve: 'curve25519', // ECC curve name, defaults to curve25519
    userIDs: [{ name: 'Jon Smith', email: 'jon@example.com' }], // you can pass multiple user IDs
    passphrase: 'super long and hard to guess secret', // protects the private key
    format: 'armored' // output key format, defaults to 'armored' (other options: 'binary' or 'object')
  });

  console.log(privateKey);     // '-----BEGIN PGP PRIVATE KEY BLOCK ... '
  console.log(publicKey);      // '-----BEGIN PGP PUBLIC KEY BLOCK ... '
  console.log(revocationCertificate); // '-----BEGIN PGP PUBLIC KEY BLOCK ... '
  writeFileSync("./data/host.pub", publicKey);
  writeFileSync("./data/host.key", privateKey);
  writeFileSync("./data/revocation.crt", revocationCertificate);
  console.log(`Keys generated and saved to ./data/host.pub and ./data/host.key`)
})();

