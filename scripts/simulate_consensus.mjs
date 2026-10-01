#!/usr/bin/env node
// Immediate GenVM diagnostic only: no account key, signature or transaction.
import {readFileSync,writeFileSync,mkdirSync} from 'node:fs';
import {resolve} from 'node:path';
import {execFileSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {abi} from 'genlayer-js';

let argsFile='runs/first-attestation-args.json';
let outputDirectory='runs/diagnostics/consensus-simulation';
const options=process.argv.slice(2);
for(let i=0;i<options.length;i++) {
  if(options[i]==='--args-file') {
    if(!options[i+1]||options[i+1].startsWith('--')) throw new Error('missing --args-file value');
    argsFile=options[++i];
  } else if(options[i].startsWith('--')) throw new Error('unknown option '+options[i]);
  else outputDirectory=options[i];
}
const output = resolve(outputDirectory);
mkdirSync(output,{recursive:true});
const original = readFileSync('contracts/attaint.bradbury.py','utf8');
const code = execFileSync('python3',['-c',`
import ast,json,pathlib,sys
source=pathlib.Path('contracts/attaint.bradbury.py').read_text()
tree=ast.parse(source)
contract=next(n for n in tree.body if isinstance(n,ast.ClassDef) and n.name=='Attaint')
constructor=next(n for n in contract.body if isinstance(n,ast.FunctionDef) and n.name=='__init__')
policy=json.loads(pathlib.Path('runs/policy-args.json').read_text())
attestation=json.loads(pathlib.Path(sys.argv[1]).read_text())
constructor.body.extend(ast.parse('diagnostic_policy_id=self.register_policy(*'+repr(policy)+')').body)
attestation[0]=0
constructor.body.extend(ast.parse('diagnostic_att_id=self.request_attestation(*'+repr(attestation)+')').body)
constructor.body.extend(ast.parse('print("ATTAINT_SIMULATION_GATE="+json.dumps(self.gate(diagnostic_att_id),sort_keys=True))').body)
ast.fix_missing_locations(tree)
sys.stdout.write(source.splitlines()[0]+'\\n'+ast.unparse(tree)+'\\n')
`,argsFile],{encoding:'utf8'});
writeFileSync(resolve(output,'diagnostic-code.py'),code);
const sender='0x771388495F34d21C5574FeFc04cd1D5811E00aDa';
const rpc='https://rpc-bradbury.genlayer.com';
const sha256 = text=>createHash('sha256').update(text).digest('hex');
const request = {type:'deploy',from:sender,to:'0x0000000000000000000000000000000000000000',
  data:abi.transactions.serialize([code,abi.calldata.encode({args:[]}),false])};
const manifest = {kind:'read-only GenVM simulation; not a receipt',rpc,sender,
  production_source_sha256:sha256(original),diagnostic_source_sha256:sha256(code),
  policy_args:JSON.parse(readFileSync('runs/policy-args.json')),
  args_file:resolve(argsFile),envelope_hash:JSON.parse(readFileSync(argsFile))[5]};
const save=(name,value)=>writeFileSync(resolve(output,name+'.json'),JSON.stringify(value,null,2)+'\n');
save('manifest',manifest);
const rpcCall = async (name,params)=>{
  const body={jsonrpc:'2.0',id:1,method:'gen_call',params:[params]};
  save(name+'-request',body);
  const response=await fetch(rpc,{method:'POST',headers:{'Content-Type':'application/json','User-Agent':'genlayer-js/1.1.8'},
    body:JSON.stringify(body),signal:AbortSignal.timeout(240000)});
  const result=await response.json();save(name+'-response',result);
  if(result.error) throw new Error(name+': '+JSON.stringify(result.error));
  if(result.result?.status?.code!==0) throw new Error(name+': '+JSON.stringify(result.result?.status));
  const gateLine=(result.result.stdout||'').split('\n').find(line=>line.startsWith('ATTAINT_SIMULATION_GATE='));
  const gate=gateLine?JSON.parse(gateLine.slice('ATTAINT_SIMULATION_GATE='.length)):null;
  const summary={name,status:result.result.status,gate,eq_output_count:result.result.eqOutputs?.length,
    nondetDisagreementCallNo:result.result.nondetDisagreementCallNo};
  save(name+'-summary',summary);console.log(JSON.stringify(summary));
  return result.result;
};

try {
  const leader=await rpcCall('leader',request);
  if(!Array.isArray(leader.eqOutputs)||leader.eqOutputs.length!==7) throw new Error('expected registry verification plus six class equivalence outputs');
  const validators=[];
  for(let n=1;n<=2;n++) validators.push(await rpcCall('validator-'+n,{...request,leader_results:leader.eqOutputs}));
  const report={kind:manifest.kind,production_source_sha256:manifest.production_source_sha256,
    validator_disagreements:validators.map(v=>v.nondetDisagreementCallNo),
    passed:validators.every(v=>v.nondetDisagreementCallNo===null)};
  save('report',report);
  if(!report.passed) throw new Error('one or more validator simulations rejected the leader outputs; inspect saved comparator logs');
} catch(error) {save('failure',{kind:manifest.kind,error:error.message});console.error(error.message);process.exitCode=2;}
