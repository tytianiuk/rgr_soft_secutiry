const net = require('net');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

class CertificateAuthority {
  constructor(port = 9000) {
    this.port = port;
    this.server = null;
    this.certDirectory = path.join(__dirname, 'certificates');

    if (!fs.existsSync(this.certDirectory)) {
      fs.mkdirSync(this.certDirectory);
    }

    // Генерація пари ключів RSA для CA
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
      modulusLength: 4096,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });

    this.caPublicKey = publicKey;
    this.caPrivateKey = privateKey;

    fs.writeFileSync(
      path.join(this.certDirectory, 'ca-public.pem'),
      this.caPublicKey
    );

    this.certificates = new Map();

    console.log('=== Certificate Authority Server ===');
    console.log('Root CA ініціалізовано');
    console.log('Public ключ CA збережено в certificates/ca-public.pem\n');
  }

  start() {
    this.server = net.createServer((socket) => {
      this.handleConnection(socket);
    });

    this.server.listen(this.port, () => {
      console.log(`CA сервер запущено на порту ${this.port}`);
    });
  }

  handleConnection(socket) {
    socket.on('data', (data) => {
      try {
        const request = JSON.parse(data.toString());

        switch (request.type) {
          // Запит на підпис сертифіката
          case 'SIGN_CERTIFICATE':
            console.log(`Запит на підпис сертифіката від: ${request.nodeId}`);
            const signedCert = this.signCertificate(
              request.nodeId,
              request.publicKey,
              request.nodeInfo
            );

            this.certificates.set(request.nodeId, signedCert);

            socket.write(
              JSON.stringify({
                type: 'SIGNED_CERTIFICATE',
                certificate: signedCert,
                caPublicKey: this.caPublicKey,
              })
            );
            console.log(`Сертифікат підписано для: ${request.nodeId}\n`);
            break;

          // Запит на перевірку сертифіката
          case 'VERIFY_CERTIFICATE':
            console.log(`Запит на перевірку сертифіката: ${request.nodeId}`);
            const isValid = this.verifyCertificate(request.certificate);

            socket.write(
              JSON.stringify({
                type: 'VERIFICATION_RESULT',
                valid: isValid,
                nodeId: request.nodeId,
              })
            );
            break;

          // Запит на отримання публічного ключа CA
          case 'GET_CA_PUBLIC_KEY':
            socket.write(
              JSON.stringify({
                type: 'CA_PUBLIC_KEY',
                publicKey: this.caPublicKey,
              })
            );
            console.log('Відправлено публічний ключ CA\n');
            break;
        }
      } catch (error) {
        console.error('Помилка CA:', error.message);
        socket.write(
          JSON.stringify({
            type: 'ERROR',
            message: error.message,
          })
        );
      }
    });

    socket.on('error', (error) => {
      console.error('Помилка сокету CA:', error.message);
    });
  }

  signCertificate(nodeId, publicKey, nodeInfo) {
    const certificate = {
      version: '1.0',
      serialNumber: crypto.randomBytes(16).toString('hex'),
      nodeId: nodeId,
      publicKey: publicKey,
      nodeInfo: nodeInfo,
      issuer: 'RootCA',
      validFrom: new Date().toISOString(),
      validTo: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString(),
      issuedAt: Date.now(),
    };

    const certData = JSON.stringify({
      serialNumber: certificate.serialNumber,
      nodeId: certificate.nodeId,
      publicKey: certificate.publicKey,
      validFrom: certificate.validFrom,
      validTo: certificate.validTo,
    });

    const signature = crypto.sign('sha256', Buffer.from(certData), {
      key: this.caPrivateKey,
      padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
    });

    certificate.signature = signature.toString('base64');

    const certPath = path.join(this.certDirectory, `${nodeId}-cert.json`);
    fs.writeFileSync(certPath, JSON.stringify(certificate, null, 2));
    console.log(`  Сертифікат збережено: ${certPath}`);

    return certificate;
  }

  verifyCertificate(certificate) {
    try {
      const now = Date.now();
      const validFrom = new Date(certificate.validFrom).getTime();
      const validTo = new Date(certificate.validTo).getTime();

      if (now < validFrom || now > validTo) {
        console.log('  Сертифікат прострочений');
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
          key: this.caPublicKey,
          padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
        },
        signatureBuffer
      );

      return isValid;
    } catch (error) {
      return false;
    }
  }
}

const ca = new CertificateAuthority();
ca.start();
