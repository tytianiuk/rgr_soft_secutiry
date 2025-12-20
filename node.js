const net = require('net');
const crypto = require('crypto');
const readline = require('readline');
const {
  parseMessages,
  verifyCertificate,
  generateSessionKey,
  encryptMessage,
  decryptMessage,
  fragmentMessage,
  getFullTopology,
  mergeTopology,
} = require('./utils');

class DistributedNode {
  constructor(nodeId, port, caPort = 9000) {
    this.nodeId = nodeId;
    this.port = port;
    this.caPort = caPort;
    this.server = null;
    this.peers = new Map();
    this.routingTable = new Map();
    this.topology = new Map();

    this.MAX_PACKET_SIZE = 128;

    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });

    this.publicKey = publicKey;
    this.privateKey = privateKey;
    this.certificate = null;
    this.caPublicKey = null;

    this.fragmentBuffer = new Map();

    console.log(
      `=== Вузол ${this.nodeId} ініціалізований на порту ${this.port} ===`
    );
  }

  async initialize() {
    await this.obtainCertificate();
    this.startServer();
  }

  obtainCertificate() {
    return new Promise((resolve, reject) => {
      const socket = new net.Socket();

      socket.connect(this.caPort, 'localhost', () => {
        console.log(
          `[${this.nodeId}] Підключення до CA для отримання сертифіката...`
        );

        socket.write(
          JSON.stringify({
            type: 'SIGN_CERTIFICATE',
            nodeId: this.nodeId,
            publicKey: this.publicKey,
            nodeInfo: {
              port: this.port,
              timestamp: Date.now(),
            },
          })
        );
      });

      socket.on('data', (data) => {
        const response = JSON.parse(data.toString());

        if (response.type === 'SIGNED_CERTIFICATE') {
          this.certificate = response.certificate;
          this.caPublicKey = response.caPublicKey;
          socket.end();
          resolve();
        }
      });

      socket.on('error', (error) => {
        console.error(`[${this.nodeId}] Помилка CA з'єднання:`, error.message);
        reject(error);
      });
    });
  }

  startServer() {
    this.server = net.createServer((socket) => {
      this.handleIncomingConnection(socket);
    });

    this.server.listen(this.port, () => {
      console.log(`[${this.nodeId}] Сервер запущено на порту ${this.port}`);
    });
  }

  handleIncomingConnection(socket) {
    let peerNodeId = null;
    let sessionKey = null;
    let serverRandom = null;
    let clientRandom = null;

    socket.on('data', (data) => {
      try {
        const messages = parseMessages(data.toString());

        messages.forEach((message) => {
          switch (message.type) {
            case 'NODE_HELLO':
              peerNodeId = message.nodeId;
              clientRandom = message.clientRandom;

              if (verifyCertificate(message.certificate, this.caPublicKey)) {
                serverRandom = crypto.randomBytes(32).toString('hex');

                socket.write(
                  JSON.stringify({
                    type: 'NODE_SERVER_HELLO',
                    nodeId: this.nodeId,
                    serverRandom: serverRandom,
                    certificate: this.certificate,
                    publicKey: this.publicKey,
                    topology: getFullTopology(this.topology),
                  }) + '\n'
                );
              } else {
                console.log(
                  `[${this.nodeId}] УВАГА: Невалідний сертифікат ${peerNodeId}`
                );
                socket.end();
              }
              break;

            case 'NODE_KEY_EXCHANGE':
              const encryptedPremaster = Buffer.from(
                message.encryptedPremaster,
                'base64'
              );
              const premasterSecret = crypto
                .privateDecrypt(
                  {
                    key: this.privateKey,
                    padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                  },
                  encryptedPremaster
                )
                .toString('hex');

              sessionKey = generateSessionKey(
                clientRandom,
                serverRandom,
                premasterSecret
              );
              const finishedMsg = encryptMessage('NODE_FINISHED', sessionKey);
              socket.write(
                JSON.stringify({
                  type: 'NODE_FINISHED',
                  encrypted: finishedMsg,
                }) + '\n'
              );
              console.log(
                `[${this.nodeId}] ✓ Handshake завершено з ${peerNodeId}`
              );

              this.peers.set(peerNodeId, {
                socket: socket,
                sessionKey: sessionKey,
                nodeId: peerNodeId,
              });

              if (!this.topology.has(this.nodeId)) {
                this.topology.set(this.nodeId, []);
              }
              if (!this.topology.get(this.nodeId).includes(peerNodeId)) {
                this.topology.get(this.nodeId).push(peerNodeId);
              }

              if (message.topology) {
                mergeTopology(this.topology, message.topology, this.nodeId);
              }

              this.buildRoutingTable();
              this.broadcastTopologyUpdate();
              break;

            case 'ENCRYPTED_DATA':
              const decryptedData = decryptMessage(message.data, sessionKey);
              const payload = JSON.parse(decryptedData);
              this.handleEncryptedMessage(payload, peerNodeId, sessionKey);
              break;

            case 'FRAGMENT':
              this.handleFragment(message, peerNodeId);
              break;
          }
        });
      } catch (error) {
        console.error(`[${this.nodeId}] Помилка обробки:`, error.message);
      }
    });

    socket.on('end', () => {
      if (peerNodeId) {
        console.log(`[${this.nodeId}] З'єднання з ${peerNodeId} закрито`);
        this.peers.delete(peerNodeId);
      }
    });

    socket.on('error', (error) => {
      console.error(`[${this.nodeId}] Помилка сокету:`, error.message);
    });
  }

  connectToPeer(peerNodeId, host, port) {
    return new Promise((resolve, reject) => {
      const socket = new net.Socket();
      let serverRandom = null;
      const clientRandom = crypto.randomBytes(32).toString('hex');
      const premasterSecret = crypto.randomBytes(48).toString('hex');
      let peerPublicKey = null;

      socket.connect(port, host, () => {
        socket.write(
          JSON.stringify({
            type: 'NODE_HELLO',
            nodeId: this.nodeId,
            clientRandom: clientRandom,
            certificate: this.certificate,
            topology: getFullTopology(this.topology),
          }) + '\n'
        );
      });

      socket.on('data', (data) => {
        try {
          const messages = parseMessages(data.toString());

          messages.forEach((message) => {
            switch (message.type) {
              case 'NODE_SERVER_HELLO':
                serverRandom = message.serverRandom;
                peerPublicKey = message.publicKey;

                if (message.topology) {
                  mergeTopology(this.topology, message.topology, this.nodeId);
                }

                const encryptedPremaster = crypto.publicEncrypt(
                  {
                    key: peerPublicKey,
                    padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                  },
                  Buffer.from(premasterSecret, 'hex')
                );

                socket.write(
                  JSON.stringify({
                    type: 'NODE_KEY_EXCHANGE',
                    encryptedPremaster: encryptedPremaster.toString('base64'),
                    topology: getFullTopology(this.topology),
                  }) + '\n'
                );
                break;

              case 'NODE_FINISHED':
                const sessionKey = generateSessionKey(
                  clientRandom,
                  serverRandom,
                  premasterSecret
                );
                console.log(
                  `[${this.nodeId}] ✓ Handshake завершено з ${peerNodeId}`
                );

                this.peers.set(peerNodeId, {
                  socket: socket,
                  sessionKey: sessionKey,
                  nodeId: peerNodeId,
                  host: host,
                  port: port,
                });

                if (!this.topology.has(this.nodeId)) {
                  this.topology.set(this.nodeId, []);
                }
                if (!this.topology.get(this.nodeId).includes(peerNodeId)) {
                  this.topology.get(this.nodeId).push(peerNodeId);
                }

                this.buildRoutingTable();
                this.broadcastTopologyUpdate();

                resolve();
                break;

              case 'ENCRYPTED_DATA':
                const peer = this.peers.get(peerNodeId);
                if (peer) {
                  const decryptedData = decryptMessage(
                    message.data,
                    peer.sessionKey
                  );
                  const payload = JSON.parse(decryptedData);
                  this.handleEncryptedMessage(
                    payload,
                    peerNodeId,
                    peer.sessionKey
                  );
                }
                break;

              case 'FRAGMENT':
                const peerData = this.peers.get(peerNodeId);
                if (peerData) {
                  this.handleFragment(message, peerNodeId);
                }
                break;
            }
          });
        } catch (error) {
          console.error(`[${this.nodeId}] Помилка обробки:`, error.message);
        }
      });

      socket.on('error', (error) => {
        console.error(
          `[${this.nodeId}] Помилка підключення до ${peerNodeId}:`,
          error.message
        );
        reject(error);
      });
    });
  }

  handleFragment(fragment, peerNodeId) {
    const { messageId, fragmentIndex, totalFragments, data } = fragment;

    if (!this.fragmentBuffer.has(messageId)) {
      this.fragmentBuffer.set(messageId, {
        fragments: new Array(totalFragments),
        received: 0,
        totalFragments: totalFragments,
      });
    }

    const buffer = this.fragmentBuffer.get(messageId);
    buffer.fragments[fragmentIndex] = Buffer.from(data, 'base64');
    buffer.received++;

    if (buffer.received === buffer.totalFragments) {
      const completeMessage = Buffer.concat(buffer.fragments).toString('utf8');
      const message = JSON.parse(completeMessage);

      this.fragmentBuffer.delete(messageId);

      this.handleEncryptedMessage(message, peerNodeId);
    }
  }

  handleEncryptedMessage(payload, fromNodeId) {
    switch (payload.messageType) {
      case 'CHAT':
        console.log(
          `\n[${this.nodeId}] Повідомлення від ${fromNodeId}: ${payload.content}\n`
        );
        break;

      case 'BROADCAST':
        console.log(
          `\n[${this.nodeId}] Broadcast від ${payload.sourceNode}: ${payload.content}`
        );
        console.log(`   Шлях: ${payload.path.join(' -> ')}`);

        if (!payload.visited) payload.visited = [];
        payload.visited.push(this.nodeId);
        payload.path.push(this.nodeId);

        this.forwardBroadcast(payload, fromNodeId);
        break;

      case 'ROUTED':
        if (payload.destination === this.nodeId) {
          console.log(
            `\n[${this.nodeId}] Маршрутизоване повідомлення від ${payload.source}:`
          );
          console.log(`   Вміст: ${payload.content}`);
          console.log(`   Шлях: ${payload.path.join(' -> ')}\n`);
        } else {
          payload.path.push(this.nodeId);
          this.routeMessage(payload);
        }
        break;

      case 'TOPOLOGY_UPDATE':
        if (payload.topology) {
          mergeTopology(this.topology, payload.topology, this.nodeId);
          this.buildRoutingTable();
        }
        break;
    }
  }

  forwardBroadcast(payload, excludeNodeId) {
    this.peers.forEach((peer, nodeId) => {
      if (nodeId !== excludeNodeId && !payload.visited.includes(nodeId)) {
        this.sendEncryptedMessage(peer.socket, payload, peer.sessionKey);
      }
    });
  }

  routeMessage(payload) {
    const nextHop = this.routingTable.get(payload.destination);

    if (nextHop && this.peers.has(nextHop)) {
      const peer = this.peers.get(nextHop);
      this.sendEncryptedMessage(peer.socket, payload, peer.sessionKey);
    } else {
      console.log(
        `[${this.nodeId}] ❌ Маршрут до ${payload.destination} не знайдено`
      );
    }
  }

  sendEncryptedMessage(socket, payload, sessionKey) {
    const encrypted = encryptMessage(JSON.stringify(payload), sessionKey);
    const message = { type: 'ENCRYPTED_DATA', data: encrypted };
    const messageStr = JSON.stringify(message);

    if (Buffer.byteLength(messageStr) > this.MAX_PACKET_SIZE) {
      const fragments = fragmentMessage(
        payload,
        this.MAX_PACKET_SIZE,
        this.nodeId
      );
      fragments.forEach((fragment) => {
        socket.write(JSON.stringify(fragment) + '\n');
      });
    } else {
      socket.write(messageStr + '\n');
    }
  }

  sendChatMessage(targetNodeId, content) {
    const peer = this.peers.get(targetNodeId);

    if (!peer) {
      console.log(`[${this.nodeId}] ❌ Нема з'єднання з ${targetNodeId}`);
      return;
    }

    const payload = {
      messageType: 'CHAT',
      content: content,
      timestamp: Date.now(),
    };

    console.log(`[${this.nodeId}] Відправка до ${targetNodeId}: ${content}`);
    this.sendEncryptedMessage(peer.socket, payload, peer.sessionKey);
  }

  broadcast(content) {
    const payload = {
      messageType: 'BROADCAST',
      sourceNode: this.nodeId,
      content: content,
      timestamp: Date.now(),
      visited: [this.nodeId],
      path: [this.nodeId],
    };

    console.log(`\n[${this.nodeId}] Відправка broadcast: ${content}`);

    this.peers.forEach((peer, nodeId) => {
      console.log(`[${this.nodeId}]    -> до ${nodeId}`);
      this.sendEncryptedMessage(peer.socket, payload, peer.sessionKey);
    });
  }

  sendRoutedMessage(destinationNodeId, content) {
    if (this.peers.has(destinationNodeId)) {
      this.sendChatMessage(destinationNodeId, content);
    } else {
      const payload = {
        messageType: 'ROUTED',
        source: this.nodeId,
        destination: destinationNodeId,
        content: content,
        timestamp: Date.now(),
        path: [this.nodeId],
      };

      console.log(
        `\n[${this.nodeId}] Маршрутизація до ${destinationNodeId}: ${content}`
      );
      this.routeMessage(payload);
    }
  }

  updateTopology(peerNodeId, peerTopology) {
    if (!this.topology.has(this.nodeId)) {
      this.topology.set(this.nodeId, []);
    }

    if (!this.topology.get(this.nodeId).includes(peerNodeId)) {
      this.topology.get(this.nodeId).push(peerNodeId);
    }

    if (peerTopology) {
      mergeTopology(this.topology, peerTopology, this.nodeId);
    }

    this.buildRoutingTable();
  }

  buildRoutingTable() {
    this.routingTable.clear();

    const distances = new Map();
    const previous = new Map();
    const unvisited = new Set();

    this.topology.forEach((_, nodeId) => {
      distances.set(nodeId, Number.POSITIVE_INFINITY);
      previous.set(nodeId, null);
      unvisited.add(nodeId);
    });

    distances.set(this.nodeId, 0);

    while (unvisited.size > 0) {
      let current = null;
      let minDistance = Number.POSITIVE_INFINITY;

      unvisited.forEach((nodeId) => {
        const dist = distances.get(nodeId);
        if (dist < minDistance) {
          minDistance = dist;
          current = nodeId;
        }
      });

      if (current === null || minDistance === Number.POSITIVE_INFINITY) break;

      unvisited.delete(current);

      const neighbors = this.topology.get(current) || [];
      neighbors.forEach((neighbor) => {
        if (unvisited.has(neighbor)) {
          const alt = distances.get(current) + 1;
          if (alt < distances.get(neighbor)) {
            distances.set(neighbor, alt);
            previous.set(neighbor, current);
          }
        }
      });
    }

    this.topology.forEach((_, destination) => {
      if (destination !== this.nodeId) {
        let current = destination;
        const path = [];

        while (previous.get(current) !== null) {
          path.unshift(current);
          current = previous.get(current);
        }

        if (path.length > 0 && current === this.nodeId) {
          const nextHop = path[0];
          this.routingTable.set(destination, nextHop);
        }
      }
    });
  }

  broadcastTopologyUpdate() {
    const topology = getFullTopology(this.topology);

    this.peers.forEach((peer) => {
      const message = {
        messageType: 'TOPOLOGY_UPDATE',
        topology: topology,
        source: this.nodeId,
      };

      this.sendEncryptedMessage(peer.socket, message, peer.sessionKey);
    });
  }
}

module.exports = DistributedNode;
