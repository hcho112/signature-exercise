import { useState } from "react";
import server from "./server";
import * as secp from "ethereum-cryptography/secp256k1";
import { utf8ToBytes, toHex } from "ethereum-cryptography/utils";
import { sha256 } from "ethereum-cryptography/sha256.js";
import { keccak256 } from "ethereum-cryptography/keccak";


function Transfer({ address, setBalance, privateKey }) {
  const [sendAmount, setSendAmount] = useState("");
  const [recipient, setRecipient] = useState("");

  const setValue = (setter) => (evt) => setter(evt.target.value);

  async function transfer(evt) {
    evt.preventDefault();

    try {
      const transferData = { sender: address, recipient, amount: parseInt(sendAmount) };
      const hashMessage = keccak256(utf8ToBytes(JSON.stringify(transferData)))
      const {r, s, recovery } = await secp.secp256k1.sign(hashMessage, privateKey, {
        recoverable: true,
      });
      const rHex = r.toString(16).padStart(64, '0');
      const sHex = s.toString(16).padStart(64, '0');
      const {
        data: { balance },
      } = await server.post(`send`, {
        rHex,
        sHex,
        recovery,
        hashMessage: toHex(hashMessage),
        transferData,
      });
      if (balance) {
        setBalance(balance);
      }
      
    } catch (ex) {
      alert(ex);
    }
  }

  return (
    <form className="container transfer" onSubmit={transfer}>
      <h1>Send Transaction</h1>

      <label>
        Send Amount
        <input
          placeholder="1, 2, 3..."
          value={sendAmount}
          onChange={setValue(setSendAmount)}
        ></input>
      </label>

      <label>
        Recipient
        <input
          placeholder="Type an address, for example: 0x2"
          value={recipient}
          onChange={setValue(setRecipient)}
        ></input>
      </label>

      <input type="submit" className="button" value="Transfer" />
    </form>
  );
}

export default Transfer;
