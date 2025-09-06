export default async function handler(req, res) {
  // Health check
  if (req.method === 'GET') return res.status(200).send('ok');
  if (req.method !== 'POST') return res.status(405).send('method not allowed');

  try {
    // ✅ Case 1: Apple ASSN v2 (with signedPayload)
    if (req.body?.signedPayload) {
      const { signedPayload } = req.body;

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

      // Forward to Bubble
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

    // ✅ Case 2: Apple Ping / simple webhook (no signedPayload)
    console.log('Webhook ping or basic event:', req.body);
    return res.status(200).json({ received: true, body: req.body });

  } catch (e) {
    console.error('Webhook error:', e);
    return res.status(400).send(String(e));
  }
}
