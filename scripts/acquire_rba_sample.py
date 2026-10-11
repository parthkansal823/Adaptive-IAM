"""Acquire a bounded prefix from the authors' published SYNTHESIZED RBA archive.

Uses checked HTTP byte ranges, not a full 1.1GB archive download. The prefix is
not representative of all users/time periods. No data is automatically deployed.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import re
import urllib.request
import zipfile
from collections import OrderedDict
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
SOURCE = 'https://zenodo.org/records/6782156/files/rba-dataset.zip?download=1'
FIELDS = ['User ID','Login Timestamp','User Agent String','Country','Login Successful','Is Account Takeover','Is Attack IP']


def timestamp(value):
    """Parse source timestamps without loading model/native dependencies."""
    try:
        number=float(value)
        if number>1e12:
            number/=1000
        return datetime.fromtimestamp(number,tz=timezone.utc)
    except (ValueError,OverflowError,OSError):
        parsed=datetime.fromisoformat(value.replace('Z','+00:00'))
        return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)


class RangeReader(io.RawIOBase):
    def __init__(self, max_bytes):
        self.position=0
        self.downloaded=0
        self.maximum=max_bytes
        self.cache=OrderedDict()
        self.block=1024*1024
        first,total=self.request(0,0)
        self.size=total
        if len(first)!=1:
            raise ValueError('Archive range probe did not return exactly one byte')

    def request(self,start,end):
        request=urllib.request.Request(SOURCE,headers={'Range':f'bytes={start}-{end}','Accept-Encoding':'identity','User-Agent':'AdaptiveIAM-research-sampler/1.0'})
        with urllib.request.urlopen(request,timeout=30) as response:
            target=urlsplit(response.url)
            if target.scheme!='https' or target.hostname!='zenodo.org' or response.status!=206:
                raise ValueError('Official archive must provide HTTPS byte ranges; full-download fallback is disabled')
            match=re.fullmatch(r'bytes (\d+)-(\d+)/(\d+)',response.headers.get('Content-Range',''))
            if not match or (int(match[1]),int(match[2]))!=(start,end):
                raise ValueError('Archive returned an unexpected byte range')
            expected=end-start+1
            if self.downloaded+expected>self.maximum:
                raise ValueError('Bounded acquisition byte budget reached; no representative-data claim is possible')
            payload=response.read(expected+1)
            if len(payload)!=expected:
                raise ValueError('Archive returned a truncated or oversized byte range')
            self.downloaded+=len(payload)
            return payload,int(match[3])

    def seekable(self):
        return True

    def readable(self):
        return True

    def tell(self):
        return self.position

    def seek(self,offset,whence=io.SEEK_SET):
        position=offset if whence==io.SEEK_SET else self.position+offset if whence==io.SEEK_CUR else self.size+offset if whence==io.SEEK_END else -1
        if not 0<=position<=self.size:
            raise ValueError('Archive seek is outside the verified file length')
        self.position=position
        return position

    def read(self,size=-1):
        size=self.size-self.position if size<0 else min(size,self.size-self.position)
        if size>self.maximum:
            raise ValueError('Unbounded archive read rejected')
        pieces=[]
        while size:
            index=self.position//self.block
            start=index*self.block
            if index not in self.cache:
                payload,total=self.request(start,min(self.size-1,start+self.block-1))
                if total!=self.size:
                    raise ValueError('Archive size changed during acquisition')
                self.cache[index]=payload
                while len(self.cache)>4:
                    self.cache.popitem(last=False)
            self.cache.move_to_end(index)
            payload=self.cache[index]
            offset=self.position-start
            amount=min(size,len(payload)-offset)
            pieces.append(payload[offset:offset+amount])
            self.position+=amount
            size-=amount
        return b''.join(pieces)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rows',type=int,default=100000)
    parser.add_argument('--max-download-mib',type=int,default=64)
    parser.add_argument('--output',type=Path,default=ROOT/'experiments/datasets/rba-prefix.csv')
    parser.add_argument('--manifest',type=Path,default=ROOT/'experiments/external-data.json')
    args=parser.parse_args()
    if not 100<=args.rows<=500000 or not 4<=args.max_download_mib<=256:
        parser.error('Use 100..500000 rows and 4..256 MiB acquisition budget')
    stream=RangeReader(args.max_download_mib*1024*1024)
    csv.field_size_limit(8192)
    with zipfile.ZipFile(stream) as archive:
        members=[member for member in archive.infolist() if member.filename.endswith('.csv') and not member.is_dir()]
        if len(members)!=1:
            raise ValueError('Expected exactly one CSV in the authors archive')
        with archive.open(members[0]) as compressed:
            reader=csv.DictReader(io.TextIOWrapper(compressed,encoding='utf-8-sig',newline=''))
            if not set(FIELDS)<=set(reader.fieldnames or []):
                raise ValueError('Source schema does not match the documented RBA columns')
            records=[]
            for row in reader:
                records.append({field:row[field] for field in FIELDS})
                if len(records)>=args.rows:
                    break
        records.sort(key=lambda row:timestamp(row['Login Timestamp']))
        args.output.parent.mkdir(parents=True,exist_ok=True)
        with args.output.open('w',encoding='utf-8',newline='') as handle:
            writer=csv.DictWriter(handle,fieldnames=FIELDS)
            writer.writeheader()
            writer.writerows(records)
    labels={field:sum(row[field].lower()=='true' for row in records) for field in ['Is Account Takeover','Is Attack IP']}
    manifest={'source':SOURCE,'authors_repository':'https://github.com/das-group/rba-dataset','doi':'10.5281/zenodo.6782156','license':'CC BY 4.0','synthetic':True,'independent_of_project_generator':True,'raw_production_data':False,'sampling':'First archive CSV rows, then sorted by login timestamp. Prefix convenience sample; not a representative population.','rows':len(records),'row_limit':args.rows,'label_counts':labels,'sample_sha256':hashlib.sha256(args.output.read_bytes()).hexdigest(),'downloaded_bytes':stream.downloaded,'archive_bytes':stream.size,'full_archive_checksum_verified':False,'member_crc_fully_verified':False,'limitations':['Entire archive and member were not downloaded, so published full checksum and final CRC were not verified.','HTTPS ranges and bounded schema were checked; sample SHA-256 is reproducible for the obtained bytes.','Authors describe all values as artificial; this is an external synthesized-data study.','Is Attack IP is a threat-intelligence proxy, not a confirmed takeover label.','A prefix may contain insufficient positives for a valid study; the evaluator rejects such partitions.']}
    manifest.update(license_url='https://github.com/das-group/rba-dataset/blob/main/LICENSE',citation_doi='10.1145/3546069',authors=['Stephan Wiefling','Paul René Jørgensen','Sigurd Thunem','Luigi Lo Iacono'])
    args.manifest.parent.mkdir(parents=True,exist_ok=True)
    args.manifest.write_text(json.dumps(manifest,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'manifest':str(args.manifest),'rows':len(records),'labels':labels,'downloaded_mib':round(stream.downloaded/1024/1024,2)}))


if __name__=='__main__':
    main()
