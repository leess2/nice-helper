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

function hmacBase64Url(value, hmacKey) {
  const digest = crypto.createHmac("sha256", hmacKey).update(value, "utf8").digest();
  return toBase64UrlNoPadding(digest);
}

function decryptEncData(encData, keyBuf) {
  const cipherEnc = fromBase64Url(encData);

  // NICE 문서: enc_data 디코딩 결과 앞 16byte = IV
  const iv = cipherEnc.subarray(0, 16);
  const cipherAndTag = cipherEnc.subarray(16);

  const cipherLen = cipherAndTag.length - 16;
  if (cipherLen <= 0) {
    throw new Error("invalid cipher length");
  }

  const cipherText = cipherAndTag.subarray(0, cipherLen);
  const tag = cipherAndTag.subarray(cipherLen);

  const decipher = crypto.createDecipheriv("aes-256-gcm", keyBuf, iv);
  decipher.setAuthTag(tag);

  const plain = Buffer.concat([
    decipher.update(cipherText),
    decipher.final(),
  ]);

  return plain.toString("utf8");
}

/**
 * 후보 KDF 조합 자동 탐색
 * - PBKDF2(password, salt, iterators, 64, sha256)
 * - NICE 문서상 key/hmacKey 추출 규칙이 표현상 애매해서 후보를 전부 시도
 * - integrity_value가 맞는 조합만 채택
 */
function buildCandidates(ticket, iterators, transactionId) {
  const candidates = [];

  // 문서 정답 조합
  const dk = crypto.pbkdf2Sync(
    Buffer.from(ticket, "utf8"),
    Buffer.from(transactionId, "utf8"),
    Number(iterators),
    64,
    "sha256"
  );

  const kdfValue = toBase64UrlNoPadding(dk);

  const keyStr32 = kdfValue.slice(0, 32);

  // 문서 "48번째부터 32byte" 기준
  const hmacStr32_from48 = kdfValue.slice(48, 80);

  candidates.push({
    mode: "doc-final / str[0:32] + str[48:80]",
    keyBuf: Buffer.from(keyStr32, "utf8"),
    hmacKey: Buffer.from(hmacStr32_from48, "utf8"),
    debug: {
      kdfValue,
      keyStr32,
      hmacStr32_from48
    }
  });

  // 비교용으로 하나만 더 두자 (혹시 문서 해석 차이 대비)
  const hmacStr32_from47 = kdfValue.slice(47, 79);

  candidates.push({
    mode: "doc-check / str[0:32] + str[47:79]",
    keyBuf: Buffer.from(keyStr32, "utf8"),
    hmacKey: Buffer.from(hmacStr32_from47, "utf8"),
    debug: {
      kdfValue,
      keyStr32,
      hmacStr32_from47
    }
  });

  return candidates;
}

function findMatchingCandidate(ticket, iterators, transactionId, encData, integrityValue) {
  const candidates = buildCandidates(ticket, iterators, transactionId);

  for (const c of candidates) {
    const calc = hmacBase64Url(encData, c.hmacKey);
    if (calc === integrityValue) {
      return {
        ok: true,
        candidate: c,
        calc,
      };
    }
  }

  return {
    ok: false,
    tried: candidates.map((c) => ({
      mode: c.mode,
      calc: hmacBase64Url(encData, c.hmacKey),
      debug: c.debug || null,
    })),
  };
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

    const matched = findMatchingCandidate(
      ticket,
      iterators,
      transaction_id,
      enc_data,
      integrity_value
    );

    if (!matched.ok) {
      return res.status(400).json({
        ok: false,
        msg: "integrity mismatch",
        recv: integrity_value,
        tried: matched.tried,
      });
    }

    const plain = decryptEncData(enc_data, matched.candidate.keyBuf);

    let parsed;
    try {
      parsed = JSON.parse(plain);
    } catch {
      return res.status(200).json({
        ok: false,
        msg: "json parse fail after decrypt",
        mode: matched.candidate.mode,
        plain,
      });
    }

    return res.json({
      ok: true,
      mode: matched.candidate.mode,
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
