const express = require("express");
const crypto = require("crypto");

const app = express();
app.use(express.json({ limit: "1mb" }));

function getKeyValue(ticket, transaction_id, iterators) {
  try {
    const key = crypto.pbkdf2Sync(ticket, transaction_id, Number(iterators), 64, "sha256");
    let base64 = key.toString("base64");
    base64 = base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    return base64;
  } catch (error) {
    console.error("getKeyValue Error:", error.message);
    return "";
  }
}

function getSha256MacBase64Value(value, hmac_key) {
  try {
    const hmac = crypto.createHmac("sha256", hmac_key);
    const hashValue = hmac.update(value).digest();
    let base64Value = hashValue.toString("base64");
    base64Value = base64Value.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    return base64Value;
  } catch (error) {
    console.error("getSha256MacBase64Value Error:", error.message);
    return null;
  }
}

function aesGcmDec(enc_data, key) {
  try {
    const cipherEnc = Buffer.from(
      enc_data.replace(/-/g, "+").replace(/_/g, "/"),
      "base64"
    );

    const iv = cipherEnc.slice(0, 16);
    const cipherAndTag = cipherEnc.slice(16);
    const cipherLen = cipherAndTag.length - 16;
    const cipherText = cipherAndTag.slice(0, cipherLen);
    const tag = cipherAndTag.slice(cipherLen, cipherLen + 16);

    // key는 문자열 32자리 그대로 사용
    const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
    decipher.setAuthTag(tag);

    const decrypted = Buffer.concat([
      decipher.update(cipherText),
      decipher.final()
    ]);

    return decrypted.toString("utf8");
  } catch (error) {
    console.error("AES GCM Decryption Error:", error.message);
    return null;
  }
}

app.get("/health", (req, res) => {
  res.json({ ok: true });
});

app.post("/nice/decrypt", (req, res) => {
  try {
    const {
      ticket,
      iterators,
      transaction_id,
      enc_data,
      integrity_value,
    } = req.body || {};

    if (!ticket || !iterators || !transaction_id || !enc_data || !integrity_value) {
      return res.status(400).json({
        ok: false,
        msg: "missing params",
      });
    }

    const keyString = getKeyValue(ticket, transaction_id, iterators);
    const key = keyString.substring(0, 32);
    const hmac_key = keyString.substring(48, 48 + 32);

    const integrity = getSha256MacBase64Value(enc_data, hmac_key);

    if (integrity !== integrity_value) {
      return res.status(400).json({
        ok: false,
        msg: "integrity mismatch",
        calc: integrity,
        recv: integrity_value,
        debug: {
          keyString,
          key,
          hmac_key
        }
      });
    }

    const plain = aesGcmDec(enc_data, key);

    if (!plain) {
      return res.status(400).json({
        ok: false,
        msg: "decrypt fail"
      });
    }

    let parsed;
    try {
      parsed = JSON.parse(plain);
    } catch (e) {
      return res.json({
        ok: false,
        msg: "json parse fail",
        plain
      });
    }

    return res.json({
      ok: true,
      data: parsed
    });
  } catch (err) {
    return res.status(500).json({
      ok: false,
      msg: err.message || "decrypt error",
    });
  }
});

const port = process.env.PORT || 10000;
app.listen(port, () => {
  console.log(`NICE helper listening on ${port}`);
});
