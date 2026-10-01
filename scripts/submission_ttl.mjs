// V6 addTransaction's public protocol deadline. SDK 1.1.8 exposes no TTL option.
export const submissionV6Abi=[{type:'function',name:'addTransaction',stateMutability:'nonpayable',
  inputs:[{name:'sender',type:'address'},{name:'recipient',type:'address'},
    {name:'validators',type:'uint256'},{name:'rotations',type:'uint256'},
    {name:'data',type:'bytes'},{name:'validUntil',type:'uint256'}],outputs:[]}];

export function createSubmissionTTL({seconds,decodeFunctionData,encodeFunctionData,now=()=>Math.floor(Date.now()/1000)}) {
  if(!Number.isSafeInteger(seconds)||seconds<3600||seconds>21600)throw Error('submission TTL must be 3600–21600 seconds');
  let original,encoded,deadline;
  return {
    rewrite(data) {
      if(encoded){if(data!==original&&data!==encoded)throw Error('TTL submission calldata changed after estimation');return encoded;}
      let decoded;
      try{decoded=decodeFunctionData({abi:submissionV6Abi,data});}catch{throw Error('custom TTL requires the standard V6 addTransaction ABI');}
      if(decoded.functionName!=='addTransaction'||decoded.args.length!==6)throw Error('custom TTL requires V6 addTransaction');
      original=data;deadline=BigInt(now()+seconds);
      encoded=encodeFunctionData({abi:submissionV6Abi,functionName:'addTransaction',args:[...decoded.args.slice(0,5),deadline]});
      return encoded;
    },
    metadata(){if(!encoded)throw Error('TTL was not encoded');return{seconds,valid_until:deadline.toString(),abi:'addTransaction(address,address,uint256,uint256,bytes,uint256)'};},
  };
}
