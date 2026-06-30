#!/usr/bin/env python3

import argparse
import csv
import re
from collections import defaultdict
from pathlib import Path

GROUPS = {
    'Loss of observability': [
        r'\bobservability\b', r'osbervability', r'\bvisibility\b', r'\btelemetry\b', r'\bmonitoring\b',
        r'cannot assess', r'inability to assess', r'loss of view', r'grid[- ]state', r'manipulated',
        r'current state', r'loss of communication', r'PDC isolation', r'SCADA control isolation', r'modification', r'modified'
    ],
    'Incorrect operational assessment': [
        r'state estimation', r'incorrect result', r'wrong result', r'wrong analysis',
        r'incorrect data', r'compromised service', r'algorithm', r'analysis result',
        r'analytics', r'statistic', r'measurement', r'false alarm', r'false positive',
        r'incorrect operation', r'wrong operational', r'misleading', r'contingency analysis', r'bogus'
    ],
    'Operational service compromise/degradation': [
        r'compromised service', r'compromise SCADA', r'compromise.*PDC', r'compromise.*EMS',
        r'workload', r'malicious code', r'backdoor', r'service disruption', r'denial of service',
        r'unavailable', r'not working', r'disruption of.*system', r'control.*system',
        r'critical services', r'service is delayed', r'services do not', r'controlled by the attacker',
        r'full control', r'deactivate', r'block of.*services', r'dirsrupted', 
    ],
    'Delayed response/recovery': [
        r'\bdelay(?:ed|s|ing)?\b', r'dealy', r'\bslower\b', r'increased time', r'recovery', r'recover',
        r'reboot', r'scheduling', r'patch', r'updates?', r'failover', r'incident response', r'reconfiguration',
        r'root-cause', r'alignment', r'reconfiguration', r'reconciliation', r'delayed response', r'delayed'
    ],
    'Coordination/regional inconsistency': [
        r'coordination', r'consistency', r'inconsistency', r'regional', r'\bregion\b',
        r'federation', r'federated', r'\bmembers\b', r'other high-level PDC',
        r'high-level PDC and EMS', r'alignment', r'disalignment'
    ],
    'Operational knowledge exposure': [
        r'disclosure', r'exposure', r'exposed', r'intelligence', r'topology', r'configuration',
        r'credentials?', r'secrets?', r'architecture', r'weakness', r'reverse engineering',
        r'proprietary', r'privacy', r'compliance', r'snapshot', r'audit logs?', r'\blogs\b', r'audit',
        r'algorithm', r'dependency', r'network', r'current state', r'history', r'sensitive data', r'logic'
    ],
    'Forensic/accountability degradation': [
        r'accountability', r'audit', r'audit logs?', r'\blogs\b', r'root-cause', r'cannot be reconducted',
        r'not traced', r'trustworthy', r'correspondance', r'attribut*',
        r'understand who', r'what device or user', r'compliance', r'who', r'linking', r'mismatch'
    ],
}

def norm(s):
    return (s or '').replace('\n',' ').strip()

def level(n):
    if n == 0: return '-'
    if n == 1: return 'L'
    if n <= 3: return 'M'
    return 'H'

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--input', required=True)
    parser.add_argument('--output-counts', required=True)
    parser.add_argument('--output-evidence', required=True)
    parser.add_argument('--asset-area', default='CLOUD')
    args = parser.parse_args()

    rows = list(csv.DictReader(Path(args.input).open(newline='', encoding='utf-8-sig')))
    cloud_rows = [r for r in rows if r.get('Asset Area','').strip().upper() == args.asset_area.upper()]

    counts = defaultdict(lambda: defaultdict(int))
    evidence_rows = []
    for r in cloud_rows:
        print(r)
        asset = norm(r['Asset'])
        stride = norm(r['STRIDE'])
        impact = norm(r['Impact'])
        if not impact:
            continue
        for group, patterns in GROUPS.items():
            hits = [p for p in patterns if re.search(p, impact, flags=re.I)]
            print("HITS:", hits)
            if hits:
                counts[asset][group] += 1
                evidence_rows.append({
                    'Asset': asset,
                    'STRIDE': stride,
                    'Impact group': group,
                    'Matched terms': '; '.join(hits[:10]),
                    'Impact excerpt': impact[:450] + ('...' if len(impact) > 450 else '')
                })
               

    assets = []
    for r in cloud_rows:
        a = norm(r['Asset'])
        if a and a not in assets:
            assets.append(a)

    with Path(args.output_counts).open('w', newline='', encoding='utf-8') as f:
        fieldnames = ['Asset']
        for g in GROUPS:
            fieldnames += [g + ' count', g + ' recurrence']
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for a in assets:
            row = {'Asset': a}
            for g in GROUPS:
                c = counts[a].get(g, 0)
                row[g + ' count'] = c
                row[g + ' recurrence'] = level(c)
            w.writerow(row)

    with Path(args.output_evidence).open('w', newline='', encoding='utf-8') as f:
        fieldnames = ['Asset','STRIDE','Impact group','Matched terms','Impact excerpt']
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(evidence_rows)

    # print('Wrote', args.output_counts)
    # print('Wrote', args.output_evidence)
    # print('Assets', len(assets), 'evidence rows', len(evidence_rows))
    # print('\nRECURRENCE TABLE')
    # print('Asset,' + ','.join(GROUPS.keys()))
    # for a in assets:
    #     print(a + ' & '  + ' & '.join(level(counts[a].get(g,0)) for g in GROUPS) +  '  \\\\' + "\n \hline")

if __name__ == '__main__':
    main()
