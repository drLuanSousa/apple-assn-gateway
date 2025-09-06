import { createLocalJWKSet, jwtVerify } from 'jose';
import appleKeys from './apple_keys.json' assert { type: 'json' };

// Load Apple's public JWKS for ASSN v2 locally (cached file)
const APPLE_JWKS = createLocalJWKSet(appleKeys);

async function verifyAndDecode(jws) {
  const { payload } = await jwtVerify(jws, APPLE_JWKS, { algorithms: ['ES256'] });
  return payload;
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
    // ✅ Case 1: Subscription notification (ASSN v2 with signedPayload)
    if (req.body?.signedPayload) {
      const { signedPayload } = req.body;

      // Verify & decode JWS layers
      const note = await verifyAndDecode(signedPayload);

      const txnInfo = note?.data?.signedTransactionInfo
        ? await verifyAndDecode(note.data.signedTransactionInfo)
        : null;

      const renInfo = note?.data?.signedRenewalInfo
        ? await verifyAndDecode(note.data.signedRenewalInfo)
        : null;

      // Normalize data
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
    console.log('Webhook ping or basic event:', req.body);
    return res.status(200).json({ received: true, body: req.body });

  } catch (e) {
    console.error('Webhook error:', e);
    return res.status(400).send(String(e));
  }
}
