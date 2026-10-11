"""Reproduce external sample eligibility and explicitly proxy-labeled holdouts."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from evaluate_rba import evaluate, read_events, partitions

ROOT=Path(__file__).resolve().parents[1]


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--csv',type=Path,default=ROOT/'experiments/datasets/rba-prefix.csv')
    parser.add_argument('--manifest',type=Path,default=ROOT/'experiments/external-data.json')
    parser.add_argument('--max-rows',type=int,default=200000)
    parser.add_argument('--reuse',action='store_true',help='Reuse matching reports; never trust a different digest, label, split or row limit')
    args=parser.parse_args()
    if args.max_rows<100:
        parser.error('--max-rows must be at least 100')
    manifest=json.loads(args.manifest.read_text(encoding='utf-8'))
    digest=hashlib.sha256(args.csv.read_bytes()).hexdigest()
    if digest!=manifest['sample_sha256']:
        parser.error('Sample bytes do not match the provenance manifest; no cached report can be reused')
    studies=[]
    for label in ('Is Account Takeover','Is Attack IP'):
        x,y,times,users=read_events(args.csv,args.max_rows,label,include_users=True)
        for split in ('chronological','user-disjoint'):
            parts=partitions(users,split)
            names=('train','calibration','selection','test')
            counts={name:{'events':len(part),'positives':int(y[part].sum())} for name,part in zip(names,parts)}
            row={'label':label,'split':split,'partitions':counts}
            if any(not len(part) or len(set(y[part]))!=2 for part in parts):
                row.update(status='ineligible',reason='All four partitions require both classes; no training or metrics fabricated.')
            else:
                filename='external-ip-'+split+'.json' if label=='Is Attack IP' else 'external-takeover-'+split+'.json'
                path=ROOT/'experiments'/filename
                report=json.loads(path.read_text(encoding='utf-8')) if args.reuse and path.exists() else None
                if not report or report['dataset']['sha256']!=manifest['sample_sha256'] or report['dataset']['label']!=label or report['dataset']['row_limit']!=args.max_rows or not report['method']['split'].startswith(split+' '):
                    report=evaluate(args.csv,args.max_rows,split,label)
                    path.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
                row.update(status='evaluated',report=filename,baseline=report['baseline'],candidate=report['improved'],user_overlap_train_test=report['method']['user_overlap_train_test'])
            studies.append(row)
    report={'provenance_manifest':'external-data.json','source':manifest['source'],'sample_sha256':manifest['sample_sha256'],'rows':min(args.max_rows,manifest['rows']),'synthetic':True,'independent_of_project_generator':True,'raw_production_data':False,'runtime_model_replaced':False,'studies':studies,'limitations':['Prefix convenience sample is not a representative population.','Attack IP is a proxy; these scores cannot be presented as takeover detection.','Candidate thresholds are validation-selected; all test regressions remain reported.','Unchanged 0.3/0.7 policy is an ablation, not the deployed policy: calibration can cause every event to be allowed.','Chronological split permits repeated users; user-disjoint split has overlapping time periods.','Independent human language annotations and real organizational outcomes remain pending.']}
    path=ROOT/'experiments/external-study.json'
    path.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'report':str(path),'studies':[{'label':r['label'],'split':r['split'],'status':r['status']} for r in studies]}))


if __name__=='__main__':
    main()
