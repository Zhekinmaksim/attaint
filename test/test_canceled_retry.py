import copy,json,pathlib,sys,tempfile,unittest
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'cli'))
import canceled_retry as cr

class CanceledRetryTests(unittest.TestCase):
    def setUp(self):
        self.h='0x'+'11'*32;self.sender='0x'+'22'*20;self.contract='0x'+'33'*20
        self.row={'transaction_hash':self.h,'envelope_hash':'e','status':'AWAITING_FINAL_CONSENSUS'}
        self.journal={'chainId':4221,'hash':self.h,'address':self.contract,'args':[0,'pkg','1','2',1,'e','canonical'],'method':'request_attestation'}
        self.entry={'index':13,'expected_old_hash':self.h,'envelope_hash':'e','requester':self.sender}
        self.raw={'chainId':4221,'hash':self.h,'raw_status':8,'recipient':self.contract,'sender':self.sender,'calldata_matches':True,'value_wei':'0','outside_pending_queue':True,'queue':{'pending_hashes':[]}}
        self.gates=lambda v:{'chainId':4221,'address':self.contract,'variant':v,'count':0,'gates':[]}
    def prove(self,raw=None,gates=None):return cr.prove_canceled(self.journal,self.entry,lambda *a:raw or self.raw,gates or self.gates)
    def test_requires_raw_cancel_and_both_complete_absent_views(self):
        self.prove()
        for change in [{'raw_status':1},{'outside_pending_queue':False},{'calldata_matches':False},{'sender':'wrong'},{'queue':{'pending_hashes':[self.h]}}]:
            with self.assertRaises(ValueError):self.prove({**self.raw,**change})
        matching={'att_id':0,'policy_id':0,'package':'pkg','from_version':'1','to_version':'2','requester':self.sender,'envelope_hash':'other'}
        for which in ['latest-final','latest-nonfinal']:
            def gates(v):return {**self.gates(v),'count':1,'gates':[matching]}if v==which else self.gates(v)
            with self.assertRaises(ValueError):self.prove(gates=gates)
    def test_archive_reference_durable_before_unlink_and_one_anchor(self):
        with tempfile.TemporaryDirectory()as directory:
            path=pathlib.Path(directory)/'13.transaction.json';path.write_text(json.dumps(self.journal))
            save=lambda p,d:p.write_text(json.dumps(d))
            def fail(row):raise OSError('checkpoint save failed')
            with self.assertRaises(OSError):cr.archive_canceled(path,self.row,self.entry,lambda *a:self.raw,self.gates,save,fail)
            self.assertTrue(path.exists())
            cr.archive_canceled(path,self.row,self.entry,lambda *a:self.raw,self.gates,save,lambda row:None)
            self.assertFalse(path.exists());self.assertEqual(len(self.row['canceled_consensus_attempts']),1)
            self.assertTrue(cr.is_anchored_original(self.row,self.entry,self.journal))
            self.assertFalse(cr.is_anchored_original(self.row,self.entry,{**self.journal,'hash':'replacement-even-if-failed'}))
            with self.assertRaises(ValueError):cr.require_fresh_manifest(self.row,None)
            cr.require_fresh_manifest(self.row,self.entry)
            for state in ['SIGNED','REVERTED','CONFIRMED']:
                with self.assertRaisesRegex(ValueError,'one canceled replacement'):
                    cr.forbid_replacement_intent_archive(self.row,{'submission_intent':{'state':state}})
    def test_manifest_pins_policy_old_hash_and_envelope(self):
        report={'contract':self.contract,'code_sha256':'c','policy_id':0,'policy_hash':'p','controls':[copy.deepcopy(self.row)for _ in range(45)]}
        doc={'version':1,'chainId':4221,**{k:report[k]for k in ['contract','code_sha256','policy_id','policy_hash']},'requester':self.sender,'maximum_fresh_requests':1,'rows':[{k:v for k,v in self.entry.items()if k!='requester'}]}
        self.assertEqual(list(cr.load_manifest(doc,report)),[13])
        for change in [{'policy_hash':'other'},{'maximum_fresh_requests':2},{'rows':[doc['rows'][0],doc['rows'][0]]}]:
            with self.assertRaises(ValueError):cr.load_manifest({**doc,**change},report)
        report['controls'][13]['transaction_hash']='different-new-hash'
        with self.assertRaises(ValueError):cr.load_manifest(doc,report)
