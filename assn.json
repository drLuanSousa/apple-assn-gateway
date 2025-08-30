import { createRemoteJWKSet, jwtVerify } from 'jose';

// Apple's public JWKS for ASSN v2
const APPLE_JWKS = createRemoteJWKSet(
  new URL('https://apple-public.keys.storekit.itunes.apple.com/keys')
);

async function verifyAndDecode(jws) {
  // Verifies ES256 and returns the decoded payload
  const { payload } = await jwtVerify(jws, APPLE_JWKS, { algorithms: ['ES256'] });
  return payload;
}

function msToIso(ms) {
  if (!ms) return null;
  const n = Number(ms);
  return new Date(n > 1e12 ? n : n * 1000).toISOString(); // supports seconds or ms
}

function mapOperation(note, renInfo) {
  const t = (note?.notificationType || '').toUpperCase();
  switch (t) {
    case 'SUBSCRIBED':                 return 'purchase';
    case 'DID_RENEW':                  return 'renew';
    case 'DID_CHANGE_RENEWAL_STATUS':  return (renInfo?.autoRenewStatus === 'OFF') ? 'auto_renew_off' : 'auto_renew_on';
    case 'DID_FAIL_TO_RENEW':          return 'renew_failed';
    case 'GRACE_PERIOD_EXPIRED':       return 'grace_expired';
    case 'EXPIRED':                    return 'expired';
    case 'REFUND':
    case 'REVOKE':                     return 'revoked';
    default:                           return t.toLowerCase() || 'other';
  }
}

// Vercel serverless function (Node runtime)
// URL will be: https://<your-vercel-project>.vercel.app/api/assn
export default async function handler(req, res) {
  // Health check
  if (req.method === 'GET') return res.status(200).send('ok');
  if (req.method !== 'POST') return res.status(405).send('method not allowed');

  try {
    const { signedPayload } = req.body || {};
    if (!signedPayload) return res.status(400).send('missing signedPayload');

    // 1) Verify the top-level JWS
    const note = await verifyAndDecode(signedPayload);

    // 2) Decode nested JWS (if present)
    const txnInfo = note?.data?.signedTransactionInfo
      ? await verifyAndDecode(note.data.signedTransactionInfo)
      : null;

    const renInfo = note?.data?.signedRenewalInfo
      ? await verifyAndDecode(note.data.signedRenewalInfo)
      : null;

    // 3) Normalize for Bubble
    const productId = txnInfo?.productId || renInfo?.autoRenewPreference || '';
    const expiresIso = msToIso(txnInfo?.expiresDate);
    const operation = mapOperation(note, renInfo);

    const out = {
      now: new Date().toISOString(),
      source: 'apple-assn',
      operation,                                      // purchase/renew/expired/auto_renew_off/...
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
      // You can include the full raw objects if you want:
      // raw_note: note, raw_txn: txnInfo, raw_ren: renInfo
    };

    // 4) Forward to your Bubble backend workflow
    const forward = await fetch(process.env.BUBBLE_HOOK_URL, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-hook-secret': process.env.BUBBLE_SECRET ?? ''   // optional shared secret check in Bubble
      },
      body: JSON.stringify(out)
    });

    return res.status(200).json({ forwardedStatus: forward.status });
  } catch (e) {
    // Any verification or parsing error means we reject the request
    return res.status(400).send(String(e));
  }
}
