const express = require("express");
const crypto = require("crypto");

const app = express();
app.use(express.json({ limit: "1mb" }));

function toBase64UrlNoPadding(buf) {
  return buf
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function fromBase64Url(str) {
  const normalized = str.replace(/-/g, "+").replace(/_/g, "/");
  const padding = "=".repeat((4 - (normalized.length % 4)) % 4);
  return Buffer.from(normalized + padding, "base64");
}

/*
 * NICE 문서 기준:
 * 1) PBKDF2로 "문자열" kdfValue 생성
 * 2) 앞 32byte = key
 * 3) 48번째부터 32byte = hmacKey
 *
 * 주의:
 * "48번째부터"는 1-base 표현이므로 JS에서는 index 47부터 slice
 */
function deriveKdfValue(ticket, iterators, transactionId) {
  // 문서 흐름상 ticket + iterators + transaction_id를 사용
  // PBEKeySpec 스타일에 맞춰 ticket을 password, transaction_id를 salt로 사용
  const dk = crypto.pbkdf2Sync(
    Buffer.from(ticket, "utf8"),
    Buffer.from(transactionId, "utf8"),
    Number(iterators),
    64,
    "sha256"
  );

  // 문서에서 문자열 기반으로 잘라 쓰므로 base64url 문자열화
  return toBase64UrlNoPadding(dk);
}

function deriveKeys(ticket, iterators, transactionId) {
  const kdfValue = deriveKdfValue(ticket, iterators, transactionId);

  const keyStr = kdfValue.slice(0, 32);
  const hmacKeyStr = kdfValue.slice(47, 79); // 48번째부터 32byte

  return {
    kdfValue,
    keyStr,
    hmacKeyStr,
    key: Buffer.from(keyStr, "utf8"),
  };
}

function verifyIntegrity(encData, hmacKeyStr, integrityValue) {
  const digest = crypto.createHmac("sha256", hmacKeyStr).update(encData, "utf8").digest();
  const calc = toBase64UrlNoPadding(digest);
  return {
    ok: calc === integrityValue,
    calc,
  };
}

function decryptEncData(encData, key) {
  const cipherEnc = fromBase64Url(encData);

  // 문서 기준: enc_data 디코딩 결과 앞 16byte = IV
  const iv = cipherEnc.subarray(0, 16);
  const cipherAndTag = cipherEnc.subarray(16);

  const cipherLen = cipherAndTag.length - 16;
  if (cipherLen <= 0) {
    throw new Error("invalid cipher length");
  }

  const cipherText = cipherAndTag.subarray(0, cipherLen);
  const tag = cipherAndTag.subarray(cipherLen);

  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(tag);

  const plain = Buffer.concat([
    decipher.update(cipherText),
    decipher.final(),
  ]);

  return plain.toString("utf8");
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

    const { kdfValue, keyStr, hmacKeyStr, key } = deriveKeys(ticket, iterators, transaction_id);

    const verify = verifyIntegrity(enc_data, hmacKeyStr, integrity_value);
    if (!verify.ok) {
      return res.status(400).json({
        ok: false,
        msg: "integrity mismatch",
        calc: verify.calc,
        recv: integrity_value,
        debug: {
          kdfValue,
          keyStr,
          hmacKeyStr
        }
      });
    }

    const plain = decryptEncData(enc_data, key);

    let parsed;
    try {
      parsed = JSON.parse(plain);
    } catch {
      return res.status(200).json({
        ok: false,
        msg: "json parse fail after decrypt",
        plain,
      });
    }

    return res.json({
      ok: true,
      plain,
      data: parsed,
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
