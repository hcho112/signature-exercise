const express = require("express");
const app = express();
const cors = require("cors");
const secp = require("ethereum-cryptography/secp256k1");
const { toHex, utf8ToBytes } = require("ethereum-cryptography/utils");
const { keccak256 } = require("ethereum-cryptography/keccak");
const port = 3042;

app.use(cors());
app.use(express.json());

const balances = {
  "03010660d3797b360ba72c6b27c10bf9842bf4a55ab8528fa73545cb3f2851f239": 100,
  "02da2f2428af4d6544174d0109548a933a22115f3b457451c91115fb66bb0446e4": 50,
  "02c10f2a5ef7b9e4d475f81be569b3905f53ebbfe931bccb371c6b5929b7927913": 75,
};

app.get("/balance/:address", (req, res) => {
  const { address } = req.params;
  const balance = balances[address] || 0;
  res.send({ balance });
});

app.post("/send", (req, res) => {
  const {
    rHex,
    sHex,
    recovery,
    hashMessage,
    transferData,
  } = req.body;
  const r = BigInt('0x' + rHex);
  const s = BigInt('0x' + sHex);
  const signature = new secp.secp256k1.Signature(r, s, recovery);
  const publicKeyPoint = signature.recoverPublicKey(hashMessage);
  const publicKeyBytes = publicKeyPoint.toRawBytes(true);
  const recoveredPublicKey = toHex(publicKeyBytes);
  const verify = secp.secp256k1.verify(signature, hashMessage, recoveredPublicKey);
  const checkHash = hashMessage === toHex(keccak256(utf8ToBytes(JSON.stringify(transferData))));
  // check if sender is the owner of the private key
  const {
    sender, recipient, amount
  } = transferData;
 
  if (recoveredPublicKey !== sender || !verify || !checkHash) {
    res.status(400).send({ message: "Invalid signature!" });
  }

  // check if the sender has enough funds
  if(balances[sender] < amount) {
    res.status(400).send({ message: "Not enough funds!" });
  }

  // transfer the funds
  setInitialBalance(sender);
  setInitialBalance(recipient);
  balances[sender] -= amount;
  balances[recipient] += amount;
  res.send({ balance: balances[sender] });

});

app.listen(port, () => {
  console.log(`Listening on port ${port}!`);
});

function setInitialBalance(address) {
  if (!balances[address]) {
    balances[address] = 0;
  }
}
