#!/usr/local/bin/node
// tested with node v19.3.0

const { subtle } = require('node:crypto').webcrypto;
const assert = require('assert');

async function sha256(data) {
	const enc = new TextEncoder("utf-8");
	return await subtle.digest("SHA-256", enc.encode(data));
}

function base64UrlEncode(data) {
	return Buffer.from(data).toString('base64url')
}

(function verify_dpop_jwk_thumbprint() {
	const dpop_ordered_jwk = {
		"crv": "P-256",
		"kty": "EC",
		"x": "l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs",
		"y": "9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA"
	};
	sha256(JSON.stringify(dpop_ordered_jwk))
		.then((hash) => {
			console.log("verify_dpop_jwk_thumbprint: ", base64UrlEncode(hash))
			assert.strictEqual(base64UrlEncode(hash),
				"0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I",
				"verify_dpop_jwk_thumbprint")
		})
		.catch((err) => {
			assert.fail("verify_dpop_jwk_thumbprint");
		});
}
)();

(function verify_rfc7638_jwk_thumbprint() {
	const rfc7638_ordered_jwk = {
		"e": "AQAB",
		"kty": "RSA",
		"n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
	};
	sha256(JSON.stringify(rfc7638_ordered_jwk))
		.then((hash) => {
			console.log("verify_rfc7638_jwk_thumbprint:", base64UrlEncode(hash))
			assert.strictEqual(base64UrlEncode(hash),
				"NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs",
				"verify_rfc7638_jwk_thumbprint")
		})
		.catch((err) => {
			assert.fail("verify_rfc7638_jwk_thumbprint");
		});
}
)();
