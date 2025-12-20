const crypto = require('crypto');
const net = require('net');

function verifyCertificateWithCA(certificate, caPort = 9000) {
  return new Promise((resolve, reject) => {
    const socket = new net.Socket();

    socket.connect(caPort, 'localhost', () => {
      socket.write(
        JSON.stringify({
          type: 'VERIFY_CERTIFICATE',
          nodeId: certificate.nodeId,
          certificate: certificate,
        })
      );
    });

    socket.on('data', (data) => {
      try {
        const response = JSON.parse(data.toString());

        if (response.type === 'VERIFICATION_RESULT') {
          socket.end();
          resolve(response.valid);
        }
      } catch (error) {
        socket.end();
        reject(error);
      }
    });

    socket.on('error', (error) => {
      reject(error);
    });

    socket.setTimeout(5000);
    socket.on('timeout', () => {
      socket.destroy();
      reject(new Error('CA verification timeout'));
    });
  });
}

function parseMessages(data) {
  const lines = data.trim().split('\n');
  return lines.map((line) => JSON.parse(line));
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
  verifyCertificateWithCA,
  generateSessionKey,
  encryptMessage,
  decryptMessage,
  fragmentMessage,
  getFullTopology,
  mergeTopology,
};
