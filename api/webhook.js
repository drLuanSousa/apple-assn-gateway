import { jwtVerify, decodeProtectedHeader, importJWK, importX509 } from 'jose';
import fs from 'fs';
import path from 'path';

// Load Apple JWKS locally (apple_keys.json must be in the /api folder)
const appleKeysPath = path.join(process.cwd(), 'api', 'apple_keys.json');
const appleKeys = JSON.parse(fs.readFileSync(appleKeysPath, 'utf8')).keys;

async function verifyAndDecode(jws) {
  if (typeof jws !== 'string') {
    console.error('❌ verifyAndDecode got non-string JWS:', jws);
    throw new Error('Invalid JWS input');
  }

  console.log('📜 Raw JWS sample:', jws.slice(0, 40));

  const header = decodeProtectedHeader(jws);
  console.log('🔑 Decoding JWS header:', header);

  if (header.kid) {
    // ✅ Normal case (production) → verify against local JWKS
    const jwk = appleKeys.find(k => k.kid === header.kid);
    if (!jwk) throw new Error(`No matching JWK found for kid=${header.kid}`);
    const key = await importJWK(jwk, 'ES256');
    const { payload } = await jwtVerify(jws, key, { algorithms: ['ES256'] });
    return payload;
  }

  if (header.x5c && header.x5c.length > 0) {
    // ✅ Sandbox test case → verify against cert in x5c
    const cert = `-----BEGIN CERTIFICATE-----\n${header.x5c[0]}\n-----END CERTIFICATE-----`;
    const key = await importX509(cert, 'ES256');
    const { payload } = await jwtVerify(jws, key, { algorithms: ['ES256'] });
    return payload;
  }

  throw new Error('No kid or x5c found in JWS header');
}

function msToIso(ms) {
  if (!ms) return null;
  const n = Number(ms);
  return new Date(n > 1e12 ? n : n * 1000).toISOString();
}

function mapOperation(note, renInfo) {
  const t = (note?.notificationType || '').toUpperCase();
  switch (t) {
    case 'SUBSCRIBED': return 'purchase';
    case 'DID_RENEW': return 'renew';
    case 'DID_CHANGE_RENEWAL_STATUS':
      return (renInfo?.autoRenewStatus === 'OFF') ? 'auto_renew_off' : 'auto_renew_on';
    case 'DID_FAIL_TO_RENEW': return 'renew_failed';
    case 'GRACE_PERIOD_EXPIRED': return 'grace_expired';
    case 'EXPIRED': return 'expired';
    case 'REFUND':
    case 'REVOKE': return 'revoked';
    default: return t.toLowerCase() || 'other';
  }
}

// Vercel serverless function
export default async function handler(req, res) {
  if (req.method === 'GET') return res.status(200).send('ok');
  if (req.method !== 'POST') return res.status(405).send('method not allowed');

  try {
    // ✅ Parse raw body (not auto-decoded JSON)
    const rawBody = await new Promise((resolve, reject) => {
      let data = '';
      req.on('data', chunk => (data += chunk));
      req.on('end', () => resolve(data));
      req.on('error', reject);
    });

    let body;
    try {
      body = JSON.parse(rawBody);
    } catch {
      body = {};
    }

    // ✅ Case 1: Subscription notification (ASSN v2 with signedPayload)
    if (body?.signedPayload) {
      const { signedPayload } = body;

      // Verify & decode JWS layers
      const note = await verifyAndDecode(String(signedPayload));

      const txnInfo = note?.data?.signedTransactionInfo
        ? await verifyAndDecode(String(note.data.signedTransactionInfo))
        : null;

      const renInfo = note?.data?.signedRenewalInfo
        ? await verifyAndDecode(String(note.data.signedRenewalInfo))
        : null;

      // Normalize data for Bubble
      const productId = txnInfo?.productId || renInfo?.autoRenewPreference || '';
      const expiresIso = msToIso(txnInfo?.expiresDate);
      const operation = mapOperation(note, renInfo);

      const out = {
        now: new Date().toISOString(),
        source: 'apple-assn',
        operation,
        environment: note?.data?.environment || '',
        notification_uuid: note?.notificationUUID || '',
        type: note?.notificationType || '',
        subtype: note?.subtype || '',
        transaction_id: String(txnInfo?.transactionId || ''),
        transaction_expires_at: expiresIso,
        products: productId ? [productId] : [],
        entitlements: productId ? [{
          product_id: productId,
          original_transaction_id: String(txnInfo?.originalTransactionId || ''),
          expires_at: expiresIso
        }] : [],
        app_account_token: txnInfo?.appAccountToken || renInfo?.appAccountToken || ''
      };

      console.log('✅ Normalized payload ready to forward:', out);

      // Forward to Bubble backend
      const forward = await fetch(process.env.BUBBLE_HOOK_URL, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-hook-secret': process.env.BUBBLE_SECRET ?? ''
        },
        body: JSON.stringify(out)
      });

      return res.status(200).json({ forwardedStatus: forward.status });
    }

    // ✅ Case 2: Ping/basic event (no signedPayload)
    console.log('📡 Webhook ping or basic event:', body);
    return res.status(200).json({ received: true, body });

  } catch (e) {
    console.error('❌ Webhook error:', e);
    return res.status(400).send(String(e));
  }
}
