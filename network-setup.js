const DistributedNode = require('./node');

async function setupNetwork() {
  console.log('  === STARTING TLS AND MESH SIMULATION ===');

  const nodeA = new DistributedNode('NodeA', 5000);
  const nodeB = new DistributedNode('NodeB', 5001);
  const nodeC = new DistributedNode('NodeC', 5002);
  const nodeD = new DistributedNode('NodeD', 5003);
  const nodeE = new DistributedNode('NodeE', 5004);

  const nodes = [nodeA, nodeB, nodeC, nodeD, nodeE];

  console.log('Ініціалізація всіх нод (отримання сертифікатів від CA)...\n');

  for (const node of nodes) {
    await node.initialize();
  }

  await new Promise((resolve) => setTimeout(resolve, 1000));

  await nodeA.connectToPeer('NodeB', 'localhost', 5001); // A -> B
  await nodeA.connectToPeer('NodeE', 'localhost', 5004); // A -> E
  await nodeB.connectToPeer('NodeC', 'localhost', 5002); // B -> C
  await nodeC.connectToPeer('NodeD', 'localhost', 5003); // C -> D
  await nodeD.connectToPeer('NodeE', 'localhost', 5004); // D -> E

  await new Promise((resolve) => setTimeout(resolve, 2000));

  return { nodeA };
}

async function demonstrateNetwork() {
  const { nodeA } = await setupNetwork();

  await new Promise((resolve) => setTimeout(resolve, 1000));
  console.log('\n=== SCENARIO 1: Direct TLS connection A -> B ===');
  nodeA.sendChatMessage('NodeB', 'Hello, this is a secret message for B!');

  await new Promise((resolve) => setTimeout(resolve, 1000));
  console.log('\n=== SCENARIO 2: Direct TLS connection A -> C ===');
  nodeA.sendRoutedMessage('NodeC', 'Hello NodeC, this is NodeA!');

  await new Promise((resolve) => setTimeout(resolve, 1000));
  console.log('\n=== SCENARIO 3: Broadcast with routing ===');
  nodeA.broadcast('NodeA sends greetings to everyone! This is a broadcast!');

  await new Promise((resolve) => setTimeout(resolve, 3000));
  console.log('\n=== FINISHED ===');
}

demonstrateNetwork().catch((error) => {
  console.error('Помилка:', error);
  process.exit(1);
});
