#!/usr/bin/env node
// Erzeugt eine Client-Assertion (RFC 7523) für den easyTI hub.
// Nutzung: CLIENT_ID=<cognito-client-id> node scripts/create-assertion.mjs
// Optional: AUD (Default PU), PRIVATE_KEY (Pfad), TTL_SECONDS (Default 300)
import { createPrivateKey, sign, randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("..", import.meta.url));
const jwks = JSON.parse(readFileSync(`${root}docs/.well-known/jwks.json`, "utf8"));
const oidc = JSON.parse(readFileSync(`${root}docs/.well-known/openid-configuration`, "utf8"));

const clientId = process.env.CLIENT_ID;
if (!clientId) {
  console.error("CLIENT_ID fehlt");
  process.exit(1);
}

const aud = process.env.AUD ?? "https://hub.easy-ti.cloud/";
const ttl = Number(process.env.TTL_SECONDS ?? 300);
const key = createPrivateKey(readFileSync(process.env.PRIVATE_KEY ?? `${root}private/private.pem`));

const b64 = (obj) => Buffer.from(JSON.stringify(obj)).toString("base64url");
const now = Math.floor(Date.now() / 1000);

const header = { alg: "ES256", typ: "JWT", kid: jwks.keys[0].kid };
const payload = { iss: oidc.issuer, sub: clientId, aud, iat: now, exp: now + ttl, jti: randomUUID() };

const input = `${b64(header)}.${b64(payload)}`;
const signature = sign("sha256", Buffer.from(input), { key, dsaEncoding: "ieee-p1363" }).toString("base64url");

process.stdout.write(`${input}.${signature}\n`);
