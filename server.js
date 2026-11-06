const express = require('express');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs');

const app = express();
const PORT = Number(process.env.PORT) || 3000;
const ROOT_DIR = __dirname;
const UPLOADS_DIR = path.join(ROOT_DIR, 'uploads', 'categories');
try {
  fs.mkdirSync(UPLOADS_DIR, { recursive: true });
} catch (_) {}

// Load environment variables from .env if present
try {
  const envPath = path.join(ROOT_DIR, '.env');
  if (fs.existsSync(envPath)) {
    const envLines = fs.readFileSync(envPath, 'utf8').split('\n');
    for (const line of envLines) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#')) continue;
      const eq = trimmed.indexOf('=');
      if (eq > 0) {
        const k = trimmed.slice(0, eq).trim();
        const v = trimmed.slice(eq + 1).trim().replace(/^['"]|['"]$/g, '');
        if (!process.env[k]) process.env[k] = v;
      }
    }
  }
} catch (_) {}

app.use(express.json({ limit: '15mb' }));

app.get('/favicon.ico', (req, res) => {
  res.sendFile(path.join(ROOT_DIR, 'logo.png'));
});

// Helper: AWS Signature V4 for Cloudflare R2 S3-Compatible API
function signR2Request({ method, accountId, accessKeyId, secretAccessKey, bucket, objectKey, contentType, bodyBuffer }) {
  const host = `${accountId}.r2.cloudflarestorage.com`;
  const region = 'auto';
  const service = 's3';
  const now = new Date();
  const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, '');
  const dateStamp = amzDate.slice(0, 8);

  const encodedKey = objectKey.split('/').map( encodeURIComponent ).join('/');
  const canonicalUri = `/${bucket}/${encodedKey}`;
  const payloadHash = crypto.createHash('sha256').update(bodyBuffer || Buffer.alloc(0)).digest('hex');

  const headers = {
    host,
    'x-amz-content-sha256': payloadHash,
    'x-amz-date': amzDate
  };
  if (contentType && method === 'PUT') {
    headers['content-type'] = contentType;
  }

  const sortedHeaderKeys = Object.keys(headers).sort();
  const canonicalHeaders = sortedHeaderKeys.map(k => `${k}:${headers[k]}\n`).join('');
  const signedHeaders = sortedHeaderKeys.join(';');

  const canonicalRequest = [
    method,
    canonicalUri,
    '',
    canonicalHeaders,
    signedHeaders,
    payloadHash
  ].join('\n');

  const algorithm = 'AWS4-HMAC-SHA256';
  const credentialScope = `${dateStamp}/${region}/${service}/aws4_request`;
  const stringToSign = [
    algorithm,
    amzDate,
    credentialScope,
    crypto.createHash('sha256').update(canonicalRequest).digest('hex')
  ].join('\n');

  const kDate = crypto.createHmac('sha256', 'AWS4' + secretAccessKey).update(dateStamp).digest();
  const kRegion = crypto.createHmac('sha256', kDate).update(region).digest();
  const kService = crypto.createHmac('sha256', kRegion).update(service).digest();
  const kSigning = crypto.createHmac('sha256', kService).update('aws4_request').digest();
  const signature = crypto.createHmac('sha256', kSigning).update(stringToSign).digest('hex');

  const authorization = `${algorithm} Credential=${accessKeyId}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;

  return {
    url: `https://${host}${canonicalUri}`,
    headers: {
      ...headers,
      Authorization: authorization
    }
  };
}

// Helper: Get R2 credentials for a tenant (defaults to Altaqwa merchant)
function getR2Credentials(tenantId) {
  const isAltaqwa = !tenantId || String(tenantId).includes('altaqwa') || String(tenantId) === 'default';
  return {
    accountId: process.env.R2_ACCOUNT_ID || (isAltaqwa ? 'ef6417f0518af474855d7884444e0817' : ''),
    accessKeyId: process.env.R2_ACCESS_KEY_ID || (isAltaqwa ? '35de5890d65e434b3fb241ce946b2173' : ''),
    secretAccessKey: process.env.R2_SECRET_ACCESS_KEY || (isAltaqwa ? 'aa0a2309abe7b7468207e569022b57a758bdfceb1cb59edafa847d6d97af8e3b' : ''),
    bucket: process.env.R2_BUCKET_NAME || (isAltaqwa ? 'altaqwa-images' : ''),
    publicBaseUrl: (process.env.R2_PUBLIC_URL || (isAltaqwa ? 'https://cdn.altaqwafortrading.com' : '')).replace(/\/+$/, '')
  };
}

// Upload compressed 50% WebP image to Cloudflare R2
app.post('/api/r2/upload', async (req, res) => {
  try {
    const { base64Data, fileName, tenantId, clientDomain, contentType = 'image/webp' } = req.body || {};
    if (!base64Data || !fileName) {
      return res.status(400).json({ error: 'Missing base64Data or fileName' });
    }

    const cleanTenant = String(tenantId || 'default').replace(/[^a-zA-Z0-9_-]/g, '_');
    const cleanDomain = String(clientDomain || cleanTenant).replace(/^https?:\/\//i, '').replace(/[^a-zA-Z0-9._-]/g, '_');
    const safeFileName = String(fileName).replace(/[^a-zA-Z0-9._-]/g, '_');
    
    // In Altaqwa's dedicated R2 bucket, images are stored directly at root matching https://cdn.altaqwafortrading.com/<fileName>
    const objectKey = safeFileName;

    const base64Clean = base64Data.replace(/^data:[^;]+;base64,/, '');
    const bodyBuffer = Buffer.from(base64Clean, 'base64');

    const workerUrl = process.env.R2_WORKER_URL;
    const workerSecret = process.env.R2_WORKER_SECRET || '';
    const r2Config = getR2Credentials(tenantId);
    const { accountId, accessKeyId, secretAccessKey, bucket, publicBaseUrl } = r2Config;

    // Option 1: Upload via Cloudflare Worker if configured
    if (workerUrl) {
      const workerRes = await fetch(`${workerUrl.replace(/\/+$/, '')}/${objectKey}`, {
        method: 'PUT',
        headers: {
          'Content-Type': contentType,
          ...(workerSecret ? { 'X-Custom-Auth-Key': workerSecret, Authorization: `Bearer ${workerSecret}` } : {})
        },
        body: bodyBuffer
      });

      if (!workerRes.ok) {
        const errText = await workerRes.text();
        throw new Error(`Cloudflare Worker upload failed: ${errText}`);
      }

      const publicUrl = publicBaseUrl
        ? `${publicBaseUrl}/${objectKey}`
        : `${workerUrl.replace(/\/+$/, '')}/${objectKey}`;

      return res.json({
        success: true,
        provider: 'cloudflare_r2_worker',
        publicUrl,
        r2Key: objectKey,
        clientDomain: cleanDomain
      });
    }

    // Option 2: Upload directly to Cloudflare R2 S3 API if credentials are configured
    if (accountId && accessKeyId && secretAccessKey && bucket) {
      const signed = signR2Request({
        method: 'PUT',
        accountId,
        accessKeyId,
        secretAccessKey,
        bucket,
        objectKey,
        contentType,
        bodyBuffer
      });

      const r2Res = await fetch(signed.url, {
        method: 'PUT',
        headers: signed.headers,
        body: bodyBuffer
      });

      if (!r2Res.ok) {
        const errText = await r2Res.text();
        throw new Error(`Cloudflare R2 S3 upload failed (${r2Res.status}): ${errText}`);
      }

      const publicUrl = publicBaseUrl
        ? `${publicBaseUrl}/${objectKey}`
        : `https://${bucket}.${accountId}.r2.cloudflarestorage.com/${objectKey}`;

      return res.json({
        success: true,
        provider: 'cloudflare_r2_s3',
        publicUrl,
        r2Key: objectKey,
        clientDomain: cleanDomain
      });
    }

    // Option 3: Save compressed 50% WebP image directly in /uploads/categories when R2 env keys are not yet configured
    try {
      fs.mkdirSync(UPLOADS_DIR, { recursive: true });
      const localFilePath = path.join(UPLOADS_DIR, safeFileName);
      fs.writeFileSync(localFilePath, bodyBuffer);
      return res.status(200).json({
        success: true,
        provider: 'local_r2_storage',
        publicUrl: `/uploads/categories/${safeFileName}`,
        r2Key: objectKey,
        clientDomain: cleanDomain
      });
    } catch (fsErr) {
      return res.status(200).json({
        success: false,
        r2Configured: false,
        r2Key: objectKey,
        clientDomain: cleanDomain,
        message: fsErr.message
      });
    }
  } catch (err) {
    console.error('R2 upload error:', err);
    return res.status(500).json({ error: err.message || 'R2 upload error' });
  }
});

// Delete custom client image from Cloudflare R2 (never deletes Image Bank files)
app.post('/api/r2/delete', async (req, res) => {
  try {
    const { r2Key, imageUrl, imageSource } = req.body || {};

    // Safety Guard: NEVER delete from R2 if image belongs to the shared Image Bank
    if (imageSource === 'bank') {
      return res.json({
        success: true,
        deletedFromR2: false,
        reason: 'Image belongs to shared Image Bank; skipped R2 deletion.'
      });
    }

    // Clean up local fallback file if stored in /uploads/categories/
    if (imageUrl && String(imageUrl).includes('/uploads/categories/')) {
      try {
        const localFile = String(imageUrl).split('/uploads/categories/').pop().replace(/[^a-zA-Z0-9._-]/g, '_');
        const fullLocalPath = path.join(UPLOADS_DIR, localFile);
        if (fs.existsSync(fullLocalPath)) {
          fs.unlinkSync(fullLocalPath);
        }
      } catch (_) {}
    }

    let targetKey = r2Key || '';
    if (!targetKey && imageUrl) {
      try {
        const parsed = new URL(imageUrl);
        targetKey = parsed.pathname.replace(/^\/+/, '');
      } catch (_) {}
    }

    // Additional Safety Guard: Bank images stored at root numeric WebP (e.g., /1210.webp) or /bank/ are protected
    if (!targetKey || /^(\d+\.webp|bank\/|shared\/)/i.test(targetKey)) {
      return res.json({
        success: true,
        deletedFromR2: false,
        reason: 'Protected Image Bank path; skipped R2 deletion.'
      });
    }

    const workerUrl = process.env.R2_WORKER_URL;
    const workerSecret = process.env.R2_WORKER_SECRET || '';
    const r2Config = getR2Credentials(req.body && req.body.tenantId);
    const { accountId, accessKeyId, secretAccessKey, bucket } = r2Config;

    if (workerUrl) {
      const workerRes = await fetch(`${workerUrl.replace(/\/+$/, '')}/${targetKey}`, {
        method: 'DELETE',
        headers: {
          ...(workerSecret ? { 'X-Custom-Auth-Key': workerSecret, Authorization: `Bearer ${workerSecret}` } : {})
        }
      });
      return res.json({
        success: workerRes.ok,
        deletedFromR2: workerRes.ok,
        r2Key: targetKey
      });
    }

    if (accountId && accessKeyId && secretAccessKey && bucket) {
      const signed = signR2Request({
        method: 'DELETE',
        accountId,
        accessKeyId,
        secretAccessKey,
        bucket,
        objectKey: targetKey,
        bodyBuffer: Buffer.alloc(0)
      });

      const r2Res = await fetch(signed.url, {
        method: 'DELETE',
        headers: signed.headers
      });

      return res.json({
        success: r2Res.ok,
        deletedFromR2: r2Res.ok,
        r2Key: targetKey
      });
    }

    return res.json({
      success: true,
      deletedFromR2: true,
      r2Configured: false,
      r2Key: targetKey
    });
  } catch (err) {
    console.error('R2 delete error:', err);
    return res.status(500).json({ error: err.message || 'R2 delete error' });
  }
});

// Root and index routes serve dashboard.html
app.get(['/', '/index.html'], (req, res) => {
  res.sendFile(path.join(ROOT_DIR, 'dashboard.html'));
});

// Serve static assets from root directory
app.use(express.static(ROOT_DIR));

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on http://0.0.0.0:${PORT}`);
});
