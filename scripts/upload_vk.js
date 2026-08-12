#!/usr/bin/env node
/**
 * Upload the payroll_aggregator VK to the groth16_verifier contract.
 * Wire format: alpha(64) | beta(128) | gamma(128) | delta(128) | n_ic(4) | IC[](64 each)
 * G2: x_im(32) | x_re(32) | y_im(32) | y_re(32)
 * G1: x(32) | y(32)
 */

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const VK_PATH = process.argv[2] || path.join(__dirname, '../build/payroll/payroll_aggregator_vkey.json');
const VERIFIER_ID = process.argv[3] || process.env.NEXT_PUBLIC_VERIFIER_CONTRACT_ID ||
  'CBT4QOMJFDYVJMJMHLGWSX5GZI4UMTYNLB7MIVMUIDX2MH73OEENUAYK';
const NETWORK = process.env.STELLAR_NETWORK || 'testnet';
const SOURCE = process.env.DEPLOYER_KEY_NAME || 'deployer';

const vkey = JSON.parse(fs.readFileSync(VK_PATH, 'utf8'));

function bigIntToBytes32(s) {
  const n = BigInt(s);
  const hex = n.toString(16).padStart(64, '0');
  return Buffer.from(hex, 'hex');
}

function g1ToBytes(p) {
  return Buffer.concat([bigIntToBytes32(p[0]), bigIntToBytes32(p[1])]);
}

function g2ToBytes(p) {
  // wire: x_im | x_re | y_im | y_re
  return Buffer.concat([
    bigIntToBytes32(p[0][1]), bigIntToBytes32(p[0][0]),
    bigIntToBytes32(p[1][1]), bigIntToBytes32(p[1][0]),
  ]);
}

const parts = [
  g1ToBytes(vkey.vk_alpha_1),   // 64 bytes
  g2ToBytes(vkey.vk_beta_2),    // 128 bytes
  g2ToBytes(vkey.vk_gamma_2),   // 128 bytes
  g2ToBytes(vkey.vk_delta_2),   // 128 bytes
];

// n_ic as big-endian u32
const n_ic = vkey.IC.length;
const n_ic_buf = Buffer.alloc(4);
n_ic_buf.writeUInt32BE(n_ic);
parts.push(n_ic_buf);

for (const ic of vkey.IC) {
  parts.push(g1ToBytes(ic));
}

const vkBytes = Buffer.concat(parts);
const totalExpected = 64 + 128 + 128 + 128 + 4 + n_ic * 64;
if (vkBytes.length !== totalExpected) {
  console.error(`Length mismatch: got ${vkBytes.length}, expected ${totalExpected}`);
  process.exit(1);
}

console.log(`VK bytes: ${vkBytes.length} bytes (n_ic=${n_ic})`);

// Stellar CLI expects hex WITHOUT 0x prefix for Bytes type
const hexStr = vkBytes.toString('hex');
console.log('Uploading VK to verifier contract...');

try {
  const result = execSync(
    `stellar contract invoke --id ${VERIFIER_ID} --network ${NETWORK} --source-account ${SOURCE} -- set_vk --vk_bytes ${hexStr}`,
    { encoding: 'utf8', stdio: 'pipe' }
  );
  console.log('VK uploaded successfully:', result.trim());
} catch (err) {
  console.error('Upload failed:', err.message);
  if (err.stderr) console.error(err.stderr);
  process.exit(1);
}
