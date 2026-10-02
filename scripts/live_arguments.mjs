// Validate the complete command line before resolving CLI dependencies, loading
// credentials, creating journals, or contacting either chain endpoint.
const commands = new Set(['deploy','write','settle','recover','cancel-expired',
  'read','code','receipt','evm-receipt','poll','gates','canceled-proof',
  'finalized-failure-proof','pending-head','expired-head']);
const switches = new Set(['--wait','--finalize-nonagreement','--retry-signed-intent']);
const values = new Set(['--out','--submission-ttl','--account','--expected-sender',
  '--rpc','--gas-limit','--max-cleanup-fee','--address','--args-file','--value',
  '--file','--method','--hash','--sender','--result','--variant',
  '--canceled-retry-anchor','--finalized-retry-anchor','--retry-sender','--timeout']);

export function validateLiveArguments(command, options) {
  if(!commands.has(command)) throw Error('Unknown or missing live command.');
  if(!Array.isArray(options)) throw Error('Invalid live arguments.');
  const seen=new Set();
  for(let i=0;i<options.length;i++) {
    const name=options[i];
    if(typeof name!=='string' || !name.startsWith('--')) throw Error('Unexpected positional argument; use named options only.');
    if(!switches.has(name) && !values.has(name)) {
      const hint=name==='--args'?' Use --args-file with a JSON array file.':'';
      throw Error(`Unknown option ${name}.${hint}`);
    }
    if(seen.has(name)) throw Error(`Duplicate option ${name}.`);
    seen.add(name);
    if(values.has(name)) {
      const value=options[++i];
      if(typeof value!=='string' || value.length===0 || value.startsWith('--')) throw Error(`Missing value for ${name}.`);
    }
  }
}
