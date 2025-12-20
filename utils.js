const crypto = require('crypto');

function parseMessages(data) {
  const lines = data.trim().split('\n');
  return lines.map((line) => JSON.parse(line));
}

function verifyCertificate(certificate, caPublicKey) {
  try {
    const now = Date.now();
    const validFrom = new Date(certificate.validFrom).getTime();
    const validTo = new Date(certificate.validTo).getTime();

    if (now < validFrom || now > validTo) {
      return false;
    }

    const certData = JSON.stringify({
      serialNumber: certificate.serialNumber,
      nodeId: certificate.nodeId,
      publicKey: certificate.publicKey,
      validFrom: certificate.validFrom,
      validTo: certificate.validTo,
    });

    const signatureBuffer = Buffer.from(certificate.signature, 'base64');
    const isValid = crypto.verify(
      'sha256',
      Buffer.from(certData),
      {
        key: caPublicKey,
        padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
      },
      signatureBuffer
    );

    return isValid;
  } catch (error) {
    return false;
  }
}

function generateSessionKey(clientRandom, serverRandom, premasterSecret) {
  const material = clientRandom + serverRandom + premasterSecret;
  return crypto.createHash('sha256').update(material).digest('hex');
}

function encryptMessage(message, sessionKey) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv(
    'aes-256-cbc',
    Buffer.from(sessionKey, 'hex'),
    iv
  );
  let encrypted = cipher.update(message, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return iv.toString('hex') + ':' + encrypted;
}

function decryptMessage(encryptedData, sessionKey) {
  const parts = encryptedData.split(':');
  const iv = Buffer.from(parts[0], 'hex');
  const encrypted = parts[1];
  const decipher = crypto.createDecipheriv(
    'aes-256-cbc',
    Buffer.from(sessionKey, 'hex'),
    iv
  );
  let decrypted = decipher.update(encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

function fragmentMessage(message, maxPacketSize) {
  const messageStr = JSON.stringify(message);
  const messageBuffer = Buffer.from(messageStr, 'utf8');
  const messageId = crypto.randomBytes(16).toString('hex');

  const fragments = [];
  const totalFragments = Math.ceil(messageBuffer.length / maxPacketSize);

  for (let i = 0; i < totalFragments; i++) {
    const start = i * maxPacketSize;
    const end = Math.min(start + maxPacketSize, messageBuffer.length);
    const fragmentData = messageBuffer.slice(start, end);

    fragments.push({
      type: 'FRAGMENT',
      messageId: messageId,
      fragmentIndex: i,
      totalFragments: totalFragments,
      data: fragmentData.toString('base64'),
    });
  }

  return fragments;
}

function getFullTopology(topologyMap) {
  const fullTopology = {};
  topologyMap.forEach((neighbors, nodeId) => {
    fullTopology[nodeId] = neighbors;
  });
  return fullTopology;
}

function mergeTopology(localTopology, receivedTopology) {
  if (Array.isArray(receivedTopology)) {
    return;
  }

  Object.keys(receivedTopology).forEach((node) => {
    if (!localTopology.has(node)) {
      localTopology.set(node, []);
    }

    const neighbors = receivedTopology[node];
    neighbors.forEach((neighbor) => {
      if (!localTopology.get(node).includes(neighbor)) {
        localTopology.get(node).push(neighbor);
      }
    });
  });
}

module.exports = {
  parseMessages,
  verifyCertificate,
  generateSessionKey,
  encryptMessage,
  decryptMessage,
  fragmentMessage,
  getFullTopology,
  mergeTopology,
};
