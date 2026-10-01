#!/usr/bin/env python3
"""Cancel only a fixed list of expired own queue heads; no attestation requests."""
import argparse,fcntl,json,pathlib,subprocess,sys
ROOT=pathlib.Path(__file__).resolve().parents[1]
def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--plan',type=pathlib.Path,required=True)
    parser.add_argument('--account',default='recuse-deployer')
    parser.add_argument('--out-dir',type=pathlib.Path,default=ROOT/'runs/expired-cleanup')
    args=parser.parse_args()
    plan=json.loads(args.plan.read_text()); hashes=plan['hashes']
    if not 1<=len(hashes)<=18 or len(set(hashes))!=len(hashes):raise ValueError('cleanup requires 1–18 unique pinned hashes')
    budget=int(plan['max_fee_wei'])
    if budget<=0:raise ValueError('cleanup requires a positive fixed fee ceiling')
    args.out_dir.mkdir(parents=True,exist_ok=True)
    # Shares the scanner's process lock, so it cannot restart between cancels.
    with (ROOT/'.attaint-scan.lock').open('a+') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        for index in range(len(hashes)):
            observed=subprocess.run(['node',str(ROOT/'scripts/live.mjs'),'pending-head','--address',plan['recipient']],cwd=ROOT,capture_output=True,text=True,timeout=120)
            if observed.returncode:raise ValueError(observed.stderr.strip())
            hash=json.loads(observed.stdout)['head']
            if hash not in hashes:
                print(json.dumps({'stop':'current head is outside fixed cleanup list','head':hash}),flush=True)
                return 0
            path=args.out_dir/(hash+'.json')
            spent=0
            for journal in args.out_dir.glob('*.json'):
                record=json.loads(journal.read_text())
                if record.get('hash') not in hashes:continue
                receipt=record.get('cleanup_receipt')
                if receipt:spent+=int(receipt['gasUsed'])*int(receipt['effectiveGasPrice'])
                elif record.get('cleanup_intent'):raise ValueError('unresolved cleanup intent; resume its exact hash before proceeding')
            if spent>=budget:raise ValueError('approved cleanup fee budget exhausted')
            command=['node',str(ROOT/'scripts/live.mjs'),'cancel-expired','--address',plan['recipient'],
                '--hash',hash,'--account',args.account,'--out',str(path),'--max-cleanup-fee',str(budget-spent)]
            process=subprocess.run(command,cwd=ROOT,capture_output=True,text=True,timeout=120)
            if process.returncode:
                print('STOP bounded cleanup at '+hash+': '+process.stderr.strip(),file=sys.stderr)
                return 2
            record=json.loads(process.stdout)
            print(json.dumps({'index':index,'consensus_hash':hash,'cleanup_evm_hash':record['cleanup_hash'],
                'pending_after':record['queue_after']['pending']}),flush=True)
    return 0
if __name__=='__main__':raise SystemExit(main())
