#!/usr/bin/env node
const crypto = require('crypto');
const fs = require('fs').promises;
const fsSync = require('fs');
const readline = require('readline');
const path = require('path');
const os = require('os');
const https = require('https');
const http = require('http');

// -------------------------
// Bootstrap & Core Config
// -------------------------
// Load or generate MASTER_SECRET (generate-and-persist behavior).
function loadOrCreateMasterSecretSync() {
  const env = process.env.MASTER_SECRET_HEX;
  if (env && /^[0-9a-fA-F]{64}$/.test(env)) {
    return env;
  }

  const defaultPath = path.join(os.homedir(), '.vart_master_secret');
  const secretFile = process.env.MASTER_SECRET_FILE || defaultPath;

  const version = "v. 1.1.0"

  try {
    const content = fsSync.readFileSync(secretFile, 'utf8').trim();
    if (content && /^[0-9a-fA-F]{64}$/.test(content)) {
      return content;
    } else {
      console.warn(`Found secret file ${secretFile} but contents look invalid. Ignoring and regenerating.`);
    }
  } catch (err) {
    // file does not exist
  }

  const newSecret = crypto.randomBytes(32).toString('hex');

  try {
    fsSync.writeFileSync(secretFile, newSecret + '\n', { encoding: 'utf8', mode: 0o600, flag: 'wx' });
    console.warn(`Generated new MASTER_SECRET and saved to ${secretFile}. Keep this file safe and add it to your .gitignore.`);
    return newSecret;
  } catch (err) {
    if (err.code === 'EEXIST') {
      const content = fsSync.readFileSync(secretFile, 'utf8').trim();
      if (content && /^[0-9a-fA-F]{64}$/.test(content)) {
        return content;
      }
    }
    throw err;
  }
}

const MASTER_SECRET_HEX = loadOrCreateMasterSecretSync();
const MASTER_SECRET = Buffer.from(MASTER_SECRET_HEX, 'hex');

// -------------------------
// Helpers
// -------------------------
function normalizeForHashing(text) {
  const s = (typeof text === 'string') ? text : String(text || '');
  return (s.normalize ? s.normalize('NFKC') : s)
    .replace(/\r\n/g, '\n')
    .replace(/[ \t]+/g, ' ')
    .trim();
}

// Stable/canonical JSON: sort object keys recursively to ensure deterministic fingerprinting
function canonicalize(value) {
  if (value === null || typeof value !== 'object') return value;
  if (Array.isArray(value)) return value.map(canonicalize);
  const sortedKeys = Object.keys(value).sort();
  const out = {};
  for (const k of sortedKeys) {
    out[k] = canonicalize(value[k]);
  }
  return out;
}

async function writeVartFile(filename, type, data, publicMeta = {}) {
  const vartContent = {
    type: type,
    data: data,
    version: version,
    public: publicMeta
  };
  const content = JSON.stringify(vartContent, null, 2);
  await fs.writeFile(filename, content, { encoding: 'utf8', mode: 0o600 });
  console.log(`✓ Saved to ${filename}`);
  return filename;
}

async function readVartFile(filename) {
  const content = await fs.readFile(filename, 'utf8');
  try {
    const json = JSON.parse(content);
    if (!json.type || (json.data === undefined) || !json.version) {
      throw new Error('Invalid .vart structure: missing fields');
    }
    return json;
  } catch (e) {
    throw new Error(`Invalid .vart file content: ${e.message}`);
  }
}

async function resolveKeyOrFile(input) {
  if (typeof input === 'string') {
    const looksLikeVart = input.endsWith('.vart');
    const exists = await fileExists(input);
    if (looksLikeVart && !exists) {
      throw new Error(`File not found: ${input}`);
    }
    if (exists) {
      const json = await readVartFile(input);
      return json.data;
    }
  }
  return input;
}

async function fileExists(f) {
  try {
    const st = await fs.stat(f);
    return st.isFile();
  } catch {
    return false;
  }
}

// fetchUrl with timeout and size limit to avoid hangs / DoS
function fetchUrl(url, { timeoutMs = 5000, maxBytes = 5 * 1024 * 1024 } = {}) {
  return new Promise((resolve, reject) => {
    const client = url.startsWith('https') ? https : http;
    const req = client.get(url, (res) => {
      if (res.statusCode < 200 || res.statusCode >= 300) {
        res.resume();
        return reject(new Error(`Status code ${res.statusCode}`));
      }
      let data = '';
      let bytes = 0;
      res.on('data', (chunk) => {
        bytes += chunk.length;
        if (bytes > maxBytes) {
          req.destroy();
          return reject(new Error('Response exceeded max size'));
        }
        data += chunk.toString('utf8');
      });
      res.on('end', () => resolve(data));
    });
    req.on('error', (err) => reject(err));
    req.setTimeout(timeoutMs, () => {
      req.destroy();
      reject(new Error('Request timed out'));
    });
  });
}

// -------------------------
// Crypto Helpers
// -------------------------
function encrypt(data, secret = MASTER_SECRET) {
  const iv = crypto.randomBytes(16);
  const secretBuf = Buffer.isBuffer(secret) ? secret : Buffer.from(secret, 'hex');
  const cipher = crypto.createCipheriv('aes-256-gcm', secretBuf, iv);
  let encrypted = cipher.update(JSON.stringify(data), 'utf8', 'hex');
  encrypted += cipher.final('hex');
  const authTag = cipher.getAuthTag().toString('hex');
  return iv.toString('hex') + encrypted + authTag;
}

function decrypt(encryptedHex, secret = MASTER_SECRET) {
  try {
    const iv = Buffer.from(encryptedHex.slice(0, 32), 'hex');
    const authTag = Buffer.from(encryptedHex.slice(-32), 'hex');
    const encrypted = encryptedHex.slice(32, -32);
    const secretBuf = Buffer.isBuffer(secret) ? secret : Buffer.from(secret, 'hex');
    const decipher = crypto.createDecipheriv('aes-256-gcm', secretBuf, iv);
    decipher.setAuthTag(authTag);
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return JSON.parse(decrypted);
  } catch (e) {
    throw new Error('Decryption failed. Invalid key or secret.');
  }
}

function getKeyFingerprint(writerKey) {
  return crypto.createHash('sha256')
    .update(writerKey)
    .digest('hex')
    .slice(0, 16);
}

// -------------------------
// Core Functions
// -------------------------
async function register(name, options = {}) {
  if (!name || typeof name !== 'string') {
    throw new Error('Name is required for registration');
  }

  const identity = {
    name,
    email: options.email || null,
    website: options.website || null,
    organization: options.organization || false,
    description: options.description || null,
    verifiedOn: options.verifiedOn || [],
    created: new Date().toISOString()
  };

  const writerKey = encrypt(identity);

  // Canonical fingerprint over the canonicalized identity
  const canonical = canonicalize(identity);
  const fingerprint = crypto.createHash('sha256')
    .update(JSON.stringify(canonical))
    .digest('hex');

  let authoritySignature = null;
  if (AUTHORITY_PRIVATE_KEY_PEM) {
    try {
      const signature = crypto.sign(null, Buffer.from(fingerprint, 'utf8'), AUTHORITY_PRIVATE_KEY_PEM);
      authoritySignature = signature.toString('base64');
    } catch (e) {
      console.warn('Failed to sign fingerprint with AUTHORITY_PRIVATE_KEY_PEM:', e.message);
      authoritySignature = null;
    }
  }

  const safeName = name.replace(/[^a-z0-9]/gi, '_').toLowerCase();
  const filename = `${safeName}.vart`;

  const publicMeta = {
    authority: AUTHORITY_NAME,
    authorityPublicKey: AUTHORITY_PUBLIC_KEY_PEM || null,
    fingerprint,
    authoritySignature,
    signedAt: new Date().toISOString()
  };

  await writeVartFile(filename, 'identity', writerKey, publicMeta);

  console.log('\n--- Registration Successful ---');
  console.log(`Name: ${name}`);
  console.log(`Email: ${identity.email}`);
  console.log(`Website: ${identity.website}`);
  console.log(`Fingerprint: ${fingerprint.slice(0, 16)}...`);
  console.log(`Key File: ${filename}`);
  if (identity.verifiedOn && identity.verifiedOn.length > 0) {
    console.log(`Verified On:`);
    identity.verifiedOn.forEach(url => console.log(`  - ${url}`));
  }

  return { writerKey, identity, filename };
}

async function verifyKey(input) {
  const writerKey = await resolveKeyOrFile(input);
  try {
    const identity = decrypt(writerKey);
    console.log('\n--- Key Verification ---');
    console.log('Identity:', identity);
    return identity;
  } catch (error) {
    console.error('Invalid key');
    return null;
  }
}

async function signArticle(articlePath, keyInput) {
  const writerKey = await resolveKeyOrFile(keyInput);
  const articleText = await fs.readFile(articlePath, 'utf8');
  const normalized = normalizeForHashing(articleText);
  const articleKey = crypto.randomBytes(16).toString('hex');
  const hmacKey = crypto.createHash('sha256')
    .update(writerKey)
    .update(articleKey)
    .digest();

  const hmac = crypto.createHmac('sha512', hmacKey);
  hmac.update(normalized);
  const fingerprint = hmac.digest('hex');

  const metadata = {
    writerKey,
    articleKey,
    fingerprint,
    originalText: articleText,
    signed: new Date().toISOString()
  };

  const signedArticle = encrypt(metadata);
  const inputExt = path.extname(articlePath);
  const basename = path.basename(articlePath, inputExt);
  const outputPath = `${basename}.vart`;

  const publicMeta = {
    authority: AUTHORITY_NAME,
    authorityPublicKey: AUTHORITY_PUBLIC_KEY_PEM || null,
    contentFingerprint: crypto.createHash('sha256').update(normalized).digest('hex'),
    contentSignature: null,
    signedAt: new Date().toISOString()
  };

  if (AUTHORITY_PRIVATE_KEY_PEM) {
    try {
      const signature = crypto.sign(
        null,
        Buffer.from(publicMeta.contentFingerprint, 'utf8'),
        AUTHORITY_PRIVATE_KEY_PEM
      );
      publicMeta.contentSignature = signature.toString('base64');
    } catch (e) {
      console.warn('Failed to sign content fingerprint with AUTHORITY_PRIVATE_KEY_PEM:', e.message);
      publicMeta.contentSignature = null;
    }
  }

  await writeVartFile(outputPath, 'signed_article', signedArticle, publicMeta);

  console.log(`\n✓ Signed article saved to: ${outputPath}`);

  return { outputPath };
}

async function verifyArticle(vartPath) {
  try {
    if (!await fileExists(vartPath)) {
      throw new Error(`File not found: ${vartPath}`);
    }

    const parsed = await readVartFile(vartPath);
    const signedData = parsed.data;

    if (!signedData) {
      throw new Error('Invalid .vart file: missing data');
    }
    const metadata = decrypt(signedData);

    const writer = decrypt(metadata.writerKey);

    const normalized = normalizeForHashing(metadata.originalText);

    const hmacKey = crypto.createHash('sha256')
      .update(metadata.writerKey)
      .update(metadata.articleKey)
      .digest();

    const hmac = crypto.createHmac('sha512', hmacKey);
    hmac.update(normalized);
    const calculatedFingerprint = hmac.digest('hex');

    console.log('\n--- Article Verification ---');
    console.log(`File: ${vartPath}`);

    if (calculatedFingerprint === metadata.fingerprint) {
      console.log('✓ VALID');
      console.log(`Signed By: ${writer.name} (${writer.organization ? 'Organization' : 'Individual'})`);
      console.log(`Description: ${writer.description || 'N/A'}`);
      console.log(`Date: ${metadata.signed}`);
      return true;
    } else {
      console.log('✗ INVALID: Content mismatch or alteration detected.');
      return false;
    }
  } catch (error) {
    console.error('❌ Verification Failed:', error.message);

    if (error.message.includes('Decryption failed')) {
      console.log('\nPossible causes:');
      console.log('  - Wrong MASTER_SECRET_HEX (or different persisted secret)');
      console.log('  - Corrupted file');
      console.log('  - File created with different vart version');
    }

    return false;
  }
}

async function verifyPublic(filePath, articlePath) {
  try {
    const raw = await readVartFile(filePath);
    const pub = raw.public || {};
    if (raw.type === 'signed_article') {
      if (!pub.contentFingerprint) {
        console.log('❌ No public content fingerprint present in this .vart file.');
        return false;
      }
      if (!pub.contentSignature) {
        console.log('❌ No authority signature present for the content fingerprint.');
        return false;
      }
      if (!pub.authorityPublicKey && !AUTHORITY_PUBLIC_KEY_PEM) {
        console.log('❌ No authority public key available to verify signature.');
        return false;
      }

      if (!articlePath) {
        console.log('❌ Provide the original article text to verify public content.');
        console.log('Usage: vart verify-public <file.vart> [article.txt]');
        return false;
      }

      const articleText = await fs.readFile(articlePath, 'utf8');
      const normalized = normalizeForHashing(articleText);
      const contentFingerprint = crypto.createHash('sha256').update(normalized).digest('hex');

      if (contentFingerprint !== pub.contentFingerprint) {
        console.log('❌ INVALID: Content hash mismatch.');
        return false;
      }

      const authorityPub = pub.authorityPublicKey || AUTHORITY_PUBLIC_KEY_PEM;
      const ok = crypto.verify(
        null,
        Buffer.from(pub.contentFingerprint, 'utf8'),
        authorityPub,
        Buffer.from(pub.contentSignature, 'base64')
      );

      console.log('\n--- Public Article Verification ---');
      console.log(`File: ${filePath}`);
      if (ok) {
        console.log('✅ VERIFIED content signature by authority');
        console.log(`Authority: ${pub.authority || 'Unknown'}`);
        console.log(`Fingerprint: ${pub.contentFingerprint.slice(0, 32)}...`);
        return true;
      }

      console.log('❌ INVALID authority signature — file may be forged or tampered with.');
      return false;
    }
    if (!pub.fingerprint) {
      console.log('❌ No public fingerprint present in this .vart file.');
      return false;
    }
    if (!pub.authoritySignature) {
      console.log('❌ No authority signature present in this .vart file.');
      return false;
    }
    if (!pub.authorityPublicKey && !AUTHORITY_PUBLIC_KEY_PEM) {
      console.log('❌ No authority public key available to verify signature.');
      return false;
    }

    const authorityPub = pub.authorityPublicKey || AUTHORITY_PUBLIC_KEY_PEM;

    const ok = crypto.verify(
      null,
      Buffer.from(pub.fingerprint, 'utf8'),
      authorityPub,
      Buffer.from(pub.authoritySignature, 'base64')
    );

    console.log('\n--- Public Verification ---');
    console.log(`File: ${filePath}`);
    if (ok) {
      console.log('✅ VERIFIED by authority signature');
      console.log(`Authority: ${pub.authority || 'Unknown'}`);
      console.log(`Fingerprint: ${pub.fingerprint.slice(0, 32)}...`);
      return true;
    } else {
      console.log('❌ INVALID authority signature — file may be forged or tampered with.');
      return false;
    }
  } catch (e) {
    console.error('Public verification failed:', e.message);
    return false;
  }
}

async function joinOrganization(writerInput, orgInput) {
  const writerKey = await resolveKeyOrFile(writerInput);
  const orgKey = await resolveKeyOrFile(orgInput);

  try {
    const writer = decrypt(writerKey);
    const org = decrypt(orgKey);

    const combinedIdentity = {
      ...writer,
      organization: org.name,
      orgKey: orgKey,
      joined: new Date().toISOString()
    };

    const combinedKey = encrypt(combinedIdentity);

    const safeName = writer.name.replace(/[^a-z0-9]/gi, '_').toLowerCase();
    const filename = `${safeName}_at_${org.name.replace(/[^a-z0-9]/gi, '_').toLowerCase()}.vart`;

    const publicMeta = {
      authority: AUTHORITY_NAME,
      authorityPublicKey: AUTHORITY_PUBLIC_KEY_PEM || null,
      signedAt: new Date().toISOString()
    };

    await writeVartFile(filename, 'identity', combinedKey, publicMeta);

    console.log(`\n✓ Joined Organization: ${org.name}`);
    console.log(`New Identity File: ${filename}`);

    return filename;
  } catch (e) {
    console.error('Join Failed:', e.message);
    return null;
  }
}

// Add this function to your code
async function initAuthority() {
    console.log('--- Vart Authority Initialization ---\n');
    
    const configDir = path.join(os.homedir(), '.vart');
    const pubKeyFile = path.join(configDir, 'authority_public.pem');
    const privKeyFile = path.join(configDir, 'authority_private.pem');
    
    // Check if keys already exist
    if (fsSync.existsSync(pubKeyFile) && fsSync.existsSync(privKeyFile)) {
        console.log('⚠️  Authority keys already exist:');
        console.log(`   Public:  ${pubKeyFile}`);
        console.log(`   Private: ${privKeyFile}`);
        
        const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
        const answer = await new Promise(r => rl.question('Regenerate? (yes/no): ', r));
        rl.close();
        
        if (answer.toLowerCase() !== 'yes') {
            console.log('Keeping existing keys.');
            return;
        }
    }
    
    // Generate new keypair
    console.log('Generating ed25519 keypair...');
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519', {
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });
    
    // Create directory if needed
    await fs.mkdir(configDir, { recursive: true });
    
    // Save keys
    await fs.writeFile(pubKeyFile, publicKey, { mode: 0o644 }); // Public can be readable
    await fs.writeFile(privKeyFile, privateKey, { mode: 0o600 }); // Private is restricted
    
    console.log('\n Authority keys generated and saved:');
    console.log(`   Public:  ${pubKeyFile}`);
    console.log(`   Private: ${privKeyFile}`);
    console.log('\n Important:');
    console.log('   - Keep the private key safe!');
    console.log('   - Add to .gitignore: .vart/');
    console.log('   - Backup both keys securely');
    console.log('\n To use these keys automatically, vart will load them from ~/.vart/');
    console.log('   Or set environment variables:');
    console.log(`   export AUTHORITY_PUBLIC_KEY_PEM="$(cat ${pubKeyFile})"`);
    console.log(`   export AUTHORITY_PRIVATE_KEY_PEM="$(cat ${privKeyFile})"`);
}

// Replace the loadAuthorityPublicKey function
function loadAuthorityPublicKey() {
  // 1. Try environment variable first
  const pubEnv = process.env.AUTHORITY_PUBLIC_KEY_PEM;
  if (pubEnv && pubEnv.trim()) {
    return pubEnv.trim();
  }

  // 2. Try loading from ~/.vart/authority_public.pem
  const configDir = path.join(os.homedir(), '.vart');
  const pubKeyFile = path.join(configDir, 'authority_public.pem');
  
  try {
    const content = fsSync.readFileSync(pubKeyFile, 'utf8');
    if (content && content.includes('BEGIN PUBLIC KEY')) {
      return content.trim();
    }
  } catch (e) {
    // File doesn't exist, that's ok
  }

  // 3. Try deriving from private key
  const privEnv = process.env.AUTHORITY_PRIVATE_KEY_PEM;
  if (privEnv && privEnv.trim()) {
    try {
      const privKeyObj = crypto.createPrivateKey({ 
        key: privEnv.trim(), 
        format: 'pem', 
        type: 'pkcs8' 
      });
      const derivedPub = privKeyObj.export({ type: 'spki', format: 'pem' });
      return derivedPub;
    } catch (e) {
      console.warn('Failed to derive public key from private key:', e.message);
    }
  }

  return null;
}

// Add similar function for private key
function loadAuthorityPrivateKey() {
  // 1. Try environment variable first
  const privEnv = process.env.AUTHORITY_PRIVATE_KEY_PEM;
  if (privEnv && privEnv.trim()) {
    return privEnv.trim();
  }

  // 2. Try loading from ~/.vart/authority_private.pem
  const configDir = path.join(os.homedir(), '.vart');
  const privKeyFile = path.join(configDir, 'authority_private.pem');
  
  try {
    const content = fsSync.readFileSync(privKeyFile, 'utf8');
    if (content && content.includes('BEGIN PRIVATE KEY')) {
      return content.trim();
    }
  } catch (e) {
    // File doesn't exist, that's ok
  }

  return null;
}

// Update the global variables
const AUTHORITY_PUBLIC_KEY_PEM = loadAuthorityPublicKey();
const AUTHORITY_PRIVATE_KEY_PEM = loadAuthorityPrivateKey();
const AUTHORITY_NAME = process.env.AUTHORITY_NAME || 'VART-Authority';


async function checkTrust(filePath) {
  try {
    const rawContent = await fs.readFile(filePath, 'utf8');
    const json = JSON.parse(rawContent);

    if (!json.type || !json.data) throw new Error("Invalid .vart file");

    const writerKey = json.data;
    const identity = decrypt(writerKey);

    console.log(`\n--- Trust Verification: ${identity.name} ---`);
    console.log(`File: ${filePath}`);

    if (!identity.verifiedOn || identity.verifiedOn.length === 0) {
      console.log('⚠️  No verification sources found in identity.');
      console.log('Trust Score: LOW (Self-signed only)');
      return;
    }

    console.log(`Checking ${identity.verifiedOn.length} verification source(s)...`);

    let matches = 0;

    for (const url of identity.verifiedOn) {
      try {
        process.stdout.write(`Fetching ${url}... `);
        const content = await fetchUrl(url);

        const keyFingerprint = writerKey.slice(0, 64);

        if (content.includes(writerKey) || content.includes(keyFingerprint)) {
          console.log('✓ MATCH');
          matches++;
        } else {
          console.log('❌ NO MATCH');
        }
      } catch (err) {
        console.log(`❌ ERROR (${err.message})`);
      }
    }

    console.log('\n--- Result ---');
    if (matches === identity.verifiedOn.length) {
      console.log('✅ TRUSTED: All verification sources confirmed.');
    } else if (matches > 0) {
      console.log('⚠️  PARTIALLY TRUSTED: Some sources failed.');
    } else {
      console.log('❌ UNTRUSTED: verification failed.');
    }

  } catch (e) {
    console.error('Trust Check Failed:', e.message);
  }
}

async function exportArticle(vartPath, outputPath) {
  const parsed = await readVartFile(vartPath);
  const metadata = decrypt(parsed.data);

  const output = outputPath || vartPath.replace('.vart', '.txt');
  await fs.writeFile(output, metadata.originalText, 'utf8');

  console.log(`✓ Exported to: ${output}`);
}

async function status() {
    console.log('--- Vart Configuration Status ---\n');
    
    // Master secret
    console.log('Master Secret:');
    if (MASTER_SECRET_HEX) {
        console.log(`  ✅ Loaded (${MASTER_SECRET_HEX.slice(0, 8)}...)`);
        const secretFile = process.env.MASTER_SECRET_FILE || path.join(os.homedir(), '.vart_master_secret');
        if (fsSync.existsSync(secretFile)) {
            console.log(`  📁 File: ${secretFile}`);
        }
    } else {
        console.log('  ❌ Not set');
    }
    
    // Authority keys
    console.log('\nAuthority Keys:');
    const configDir = path.join(os.homedir(), '.vart');
    const pubKeyFile = path.join(configDir, 'authority_public.pem');
    const privKeyFile = path.join(configDir, 'authority_private.pem');
    
    if (AUTHORITY_PUBLIC_KEY_PEM) {
        console.log('  ✅ Public key loaded');
        if (fsSync.existsSync(pubKeyFile)) {
            console.log(`     📁 ${pubKeyFile}`);
        } else {
            console.log('     🔧 From environment variable');
        }
    } else {
        console.log('  ⚠️  Public key not found');
        console.log(`     Expected at: ${pubKeyFile}`);
        console.log('     Run: vart init');
    }
    
    if (AUTHORITY_PRIVATE_KEY_PEM) {
        console.log('  ✅ Private key loaded');
        if (fsSync.existsSync(privKeyFile)) {
            console.log(`     📁 ${privKeyFile}`);
        } else {
            console.log('     🔧 From environment variable');
        }
    } else {
        console.log('  ⚠️  Private key not found');
        console.log(`     Expected at: ${privKeyFile}`);
        console.log('     Run: vart init');
    }
    
    // Capabilities
    console.log('\nCapabilities:');
    console.log(`  Registration: ${MASTER_SECRET_HEX ? '✅' : '❌'}`);
    console.log(`  Signing: ${AUTHORITY_PRIVATE_KEY_PEM ? '✅' : '⚠️  (will work but no authority signature)'}`);
    console.log(`  Public Verification: ${AUTHORITY_PUBLIC_KEY_PEM ? '✅' : '❌'}`);
    console.log(`  Private Verification: ${MASTER_SECRET_HEX ? '✅' : '❌'}`);
}

async function info(filePath) {
  const rawContent = await fs.readFile(filePath, 'utf8');
  const json = JSON.parse(rawContent);

  console.log(`\n--- Vart File Info ---`);
  console.log(`Type: ${json.type}`);
  console.log(`Version: ${json.version}`);

  if (json.type === 'identity') {
    const identity = decrypt(json.data);
    const fingerprint = json.public && json.public.fingerprint ? json.public.fingerprint : getKeyFingerprint(json.data);

    console.log(`Name: ${identity.name}`);
    console.log(`Email: ${identity.email || 'N/A'}`);
    console.log(`Website: ${identity.website || 'N/A'}`);
    console.log(`Organization: ${identity.organization}`);
    console.log(`Created: ${identity.created}`);
    console.log(`Fingerprint: ${fingerprint}`);
    console.log(`Authority: ${json.public && json.public.authority ? json.public.authority : 'N/A'}`);
    if (json.public && json.public.authorityPublicKey) {
      console.log(`Authority Public Key: (present)`);
    } else {
      console.log(`Authority Public Key: (not provided)`);
    }

    if (identity.verifiedOn && identity.verifiedOn.length > 0) {
      console.log(`Verified On:`);
      identity.verifiedOn.forEach(url => console.log(`  - ${url}`));
    }
  } else if (json.type === 'signed_article') {
    const metadata = decrypt(json.data);
    const writer = decrypt(metadata.writerKey);

    console.log(`Article signed by: ${writer.name}`);
    console.log(`Signed: ${metadata.signed}`);
    console.log(`Article Key (preview): ${metadata.articleKey.slice(0, 16)}...`);
    console.log(`Authority: ${json.public && json.public.authority ? json.public.authority : 'N/A'}`);
    console.log(`Authority Public Key: ${json.public && json.public.authorityPublicKey ? '(present)' : '(not provided)'}`);
  }
}

// -------------------------
// CLI Logic
// -------------------------
if (require.main === module) {
  const args = process.argv.slice(2);
  const command = args[0];

  (async () => {
    try {
      if (command === 'reg') {
        const flags = {};
        for (let i = 1; i < args.length; i++) {
          if (args[i].startsWith('--')) {
            const key = args[i].replace(/^--/, '');
            const value = args[i + 1] && !args[i + 1].startsWith('--') ? args[i + 1] : true;

            if (flags[key]) {
              if (Array.isArray(flags[key])) {
                flags[key].push(value);
              } else {
                flags[key] = [flags[key], value];
              }
            } else {
              flags[key] = value;
            }
          }
        }

        let { name, email, website, org, description, verify } = flags;
        const verifiedOn = verify ? (Array.isArray(verify) ? verify : [verify]) : [];

        if (!name && Object.keys(flags).length === 0) {
          const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
          const question = (q) => new Promise((r) => rl.question(q, r));
          try {
            console.log('--- Interactive Registration ---');
            name = await question('Name: ');
            email = await question('Email: ');
            website = await question('Website: ');
            const orgInput = await question('Organization (true/false, default false): ');
            org = (orgInput || '').toLowerCase() === 'true';
            description = await question('Description (optional): ');
          } finally {
            rl.close();
          }
        }
        await register(name, { email, website, organization: org, description, verifiedOn });

      } else if (command === 'verify') {
        const input = args[1];
        if (!input) throw new Error('Usage: verify <file.vart or KEY>');
        await verifyKey(input);

      } else if (command === 'verify-public') {
        const file = args[1];
        const articlePath = args[2];
        if (!file) throw new Error('Usage: verify-public <file.vart> [article.txt]');
        await verifyPublic(file, articlePath);

      } else if (command === 'sign') {
        const filePath = args[1];
        const keyInput = args[2];
        if (!filePath || !keyInput) throw new Error('Usage: sign <file> <key.vart or KEY>');
        await signArticle(filePath, keyInput);

      } else if (command === 'verify-article') {
        const filePath = args[1];
        if (!filePath) throw new Error('Usage: verify-article <file.vart>');
        await verifyArticle(filePath);

      } else if (command === 'join') {
        const writer = args[1];
        const org = args[2];
        if (!writer || !org) throw new Error('Usage: join <writer.vart> <org.vart>');
        await joinOrganization(writer, org);

      } else if (command === 'trust') {
        const file = args[1];
        if (!file) throw new Error('Usage: trust <file.vart>');
        await checkTrust(file);

      } else if (command === 'info') {
        const file = args[1];
        if (!file) throw new Error('Usage: info <file.vart>');
        await info(file);

      } else if (command === 'export') {
        const vartFile = args[1];
        const outputFile = args[2];
        if (!vartFile) throw new Error('Usage: export <article.vart> [output.txt]');
        await exportArticle(vartFile, outputFile);
      } 
    else if 
    (command === 'init') {
        await initAuthority();
    } else if (command === 'status') {
    await status();
}else {
        console.log('Vart - Verification Article Tool ${version}\n');
        console.log('Usage:');
        console.log('  vart reg [--name NAME] [--email EMAIL] [--verify URL]  Register identity (optionally provide verification URL(s))');
        console.log('  vart verify <file.vart>                                Verify identity (requires MASTER_SECRET to decrypt)');
        console.log('  vart verify-public <file.vart> [article.txt]           Public verification (authority signature only)');
        console.log('  vart info <file.vart>                                  Show file info');
        console.log('  vart sign <article.txt> <key.vart>                     Sign article');
        console.log('  vart verify-article <article.vart>                     Verify signed article');
        console.log('  vart export <article.vart> [output.txt]                Export article content');
        console.log('  vart trust <key.vart>                                  Check trust verification');
        console.log('  vart join <writer.vart> <org.vart>                     Join organization');
        console.log('  vart inf                                               Additional information about Vart');
        console.log('\nEnvironment:');
        console.log('  MASTER_SECRET_HEX        - Preferred (64-char hex string)');
        console.log('  or MASTER_SECRET_FILE    - Path to persisted secret file (default: ~/.vart_master_secret)');
        console.log('  AUTHORITY_PUBLIC_KEY_PEM - PEM text for authority public key (optional but recommended)');
        console.log('  AUTHORITY_PRIVATE_KEY_PEM- PEM text for authority private key (optional; used to sign fingerprints)');
        console.log('  AUTHORITY_NAME           - Friendly name for authority (default: VART-Authority)');
      }
    } catch (err) {
      console.error('Error:', err.message);
    }
  })();
}

module.exports = {
  encrypt, decrypt, register, verifyKey, signArticle, verifyArticle, verifyPublic, joinOrganization, checkTrust, exportArticle, info

};
