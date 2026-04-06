const DistributedNode = require('./node');

async function setupNetwork() {
  console.log('  === STARTING TLS AND MESH SIMULATION ===');

  const hubA = new DistributedNode('HubA', 5000);
  const node1 = new DistributedNode('Node1', 5001);
  const node2 = new DistributedNode('Node2', 5002);
  const node3 = new DistributedNode('Node3', 5003);

  const bridge = new DistributedNode('Bridge', 5004);

  const hubB = new DistributedNode('HubB', 5005);
  const node4 = new DistributedNode('Node4', 5006);
  const node5 = new DistributedNode('Node5', 5007);
  const node6 = new DistributedNode('Node6', 5008);

  const nodes = [hubA, node1, node2, node3, bridge, hubB, node4, node5, node6];

  console.log('Ініціалізація всіх нод (отримання сертифікатів від CA)...\n');

  for (const node of nodes) {
    await node.initialize();
  }

  await new Promise((resolve) => setTimeout(resolve, 1000));

  await node1.connectToPeer('HubA', 'localhost', 5000); // Node1 -> HubA
  await node2.connectToPeer('HubA', 'localhost', 5000); // Node2 -> HubA
  await node3.connectToPeer('HubA', 'localhost', 5000); // Node3 -> HubA

  await hubA.connectToPeer('Bridge', 'localhost', 5004); // HubA -> Bridge
  await bridge.connectToPeer('HubB', 'localhost', 5005); // Bridge -> HubB

  await node4.connectToPeer('HubB', 'localhost', 5005); // Node4 -> HubB
  await node5.connectToPeer('HubB', 'localhost', 5005); // Node5 -> HubB
  await node6.connectToPeer('HubB', 'localhost', 5005); // Node6 -> HubB

  await new Promise((resolve) => setTimeout(resolve, 2000));

  return { bridge, node1, node2, node4 };
}

async function demonstrateNetwork() {
  const { bridge, node1, node2, node4 } = await setupNetwork();

  await new Promise((resolve) => setTimeout(resolve, 1000));
  console.log('СЦЕНАРІЙ 1: Пряме повідомлення Node1 -> HubA');
  node1.sendChatMessage('HubA', 'Привіт HubA! Це Node1 з першої зірки!');

  await new Promise((resolve) => setTimeout(resolve, 1000));
  console.log(
    'СЦЕНАРІЙ 2: Маршрутизоване повідомлення Node1 -> Node3 (через HubA)'
  );
  node1.sendRoutedMessage('Node3', 'Привіт Node3! Маршрут через HubA.');

  await new Promise((resolve) => setTimeout(resolve, 1000));
  console.log('СЦЕНАРІЙ 3: Маршрутизація між зірками Node1 -> Node6');
  console.log('(Node1 -> HubA -> Bridge -> HubB -> Node6)');
  node1.sendRoutedMessage(
    'Node6',
    'Привіт Node6! Повідомлення через дві зірки!'
  );

  await new Promise((resolve) => setTimeout(resolve, 1000));
  console.log('СЦЕНАРІЙ 4: Broadcast від Node2 по всій мережі');
  node2.broadcast('Широкомовне повідомлення від Node2 всім нодам мережі!');

  await new Promise((resolve) => setTimeout(resolve, 1000));
  console.log('СЦЕНАРІЙ 5: Велике повідомлення з фрагментацією');
  const largeMessage =
    'Це велике повідомлення, яке буде фрагментоване на частини через обмеження розміру пакету в 16 байт!';
  node4.sendRoutedMessage('Node1', largeMessage);

  await new Promise((resolve) => setTimeout(resolve, 1000));
  console.log('СЦЕНАРІЙ 6: Повідомлення від Bridge до обох зірок');
  bridge.broadcast('Повідомлення від Bridge!');

  await new Promise((resolve) => setTimeout(resolve, 3000));
  console.log('\n=== FINISHED ===');
}

demonstrateNetwork().catch((error) => {
  console.error('Помилка:', error);
  process.exit(1);
});
