// Official Bradbury ABIs: github.com/genlayerlabs/genlayer-networks/tree/main/bradbury/abi
const managerAddress = '0x8aCE036C8C3C5D603dB546b031302FCf149648E8';
const managerAbi = [{type:'function',name:'getAllContractAddresses',stateMutability:'view',inputs:[],
  outputs:[{name:'result',type:'tuple[]',components:[{name:'key',type:'string'},{name:'addr',type:'address'}]}]}];
const queueAbi = ['maxPendingTxsPerRecipient','getPendingTxCount'].map(name => ({type:'function',name,
  stateMutability:'view',inputs:name === 'getPendingTxCount' ? [{name:'recipient',type:'address'}] : [],
  outputs:[{name:'',type:'uint256'}]}));

export async function readPendingQueue({publicClient,recipient}) {
  const block = await publicClient.getBlock();
  const entries = await publicClient.readContract({address:managerAddress,abi:managerAbi,
    functionName:'getAllContractAddresses',blockNumber:block.number});
  const queues = entries.filter(entry => entry.key === 'Queues');
  if (queues.length !== 1 || !/^0x[0-9a-f]{40}$/i.test(queues[0].addr)) throw new Error('cannot resolve authoritative Bradbury Queues address');
  const address = queues[0].addr;
  const [maximum,pending] = await Promise.all([
    publicClient.readContract({address,abi:queueAbi,functionName:'maxPendingTxsPerRecipient',blockNumber:block.number}),
    publicClient.readContract({address,abi:queueAbi,functionName:'getPendingTxCount',args:[recipient],blockNumber:block.number}),
  ]);
  if (maximum <= 0n || pending < 0n || pending > maximum) throw new Error('invalid authoritative queue capacity');
  return {source:'AddressManager→Queues',address,recipient,block:block.number,
    maximum:Number(maximum),pending:Number(pending)};
}
