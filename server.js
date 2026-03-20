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

/**
 * NICE 문서 기준 요약
 * - KDF: PBKDF2
 * - input: ticket, transaction_id
 * - iterators 사용
 * - 생성 결과 64byte 중 일부를 key / hmacKey로 사용
 *
 * 주의:
 * 실제 문서 원문 코드와 1:1 정확히 일치해야 하므로,
 * 필요 시 password/salt 순서를 바꿔 테스트해야 할 수 있음.
 * 현재는 문서 캡처 흐름 기준으로 transaction_id를 password,
 * ticket을 salt로 사용.
 */
function deriveKeys(ticket, iterators, transactionId) {
  const dk = crypto.pbkdf2Sync(
    Buffer.from(transactionId, "utf8"),
    Buffer.from(ticket, "utf8"),
    Number(iterators),
    64,
    "sha256"
  );

  // 문서 캡처 기준: 앞 32byte = 대칭키, 뒤쪽 구간 = hmacKey
  const key = dk.subarray(0, 32);
  const hmacKey = dk.subarray(32, 64);

  return { key, hmacKey };
}

function verifyIntegrity(encData, hmacKey, integrityValue) {
  const digest = crypto.createHmac("sha256", hmacKey).update(encData, "utf8").digest();
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

  // GCM tag 16byte
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

    const { key, hmacKey } = deriveKeys(ticket, iterators, transaction_id);

    const verify = verifyIntegrity(enc_data, hmacKey, integrity_value);
    if (!verify.ok) {
      return res.status(400).json({
        ok: false,
        msg: "integrity mismatch",
        calc: verify.calc,
        recv: integrity_value,
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

const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`NICE helper listening on ${port}`);
});