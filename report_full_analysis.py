import csv
import re
from collections import defaultdict, Counter
from pathlib import Path

INPUT_CSV = 'DumpFile.csv'
OUTPUT_MD = 'Rapport_Complet.md'

length_re = re.compile(r"length\s+(\d+)")
flags_re = re.compile(r"Flags\s*\[([^\]]+)\]")
seq_re = re.compile(r"seq\s+([\d:]+)")
ack_re = re.compile(r"ack\s+(\d+)")


def split_host_port(token):
    if not token:
        return ('', '')
    if '.' in token:
        head, tail = token.rsplit('.', 1)
        if tail.isdigit():
            return (head, tail)
    return (token, '')


def analyze():
    path = Path(INPUT_CSV)
    if not path.exists():
        print(f"Fichier d'entrée introuvable: {INPUT_CSV}")
        return

    total_packets = 0
    total_bytes = 0

    src_volume = defaultdict(int)
    src_targets = defaultdict(lambda: defaultdict(int))
    src_targets_set = defaultdict(set)
    dst_port_counter = Counter()
    protocol_counter = Counter()
    packets = []

    with path.open('r', encoding='utf-8') as f:
        reader = csv.DictReader(f, delimiter=';')
        for row in reader:
            total_packets += 1
            ts = row.get('Timestamp','')
            src = row.get('Source','')
            dst = row.get('Destination','')
            pkt = row.get('Packet_Info','') or row.get('HeaderRest','') or ''

            
            m = length_re.search(pkt)
            length = int(m.group(1)) if m else 0
            total_bytes += length
            src_volume[src] += length
            src_targets[src][dst] += length
            src_targets_set[src].add(dst)

            
            _, dst_port = split_host_port(dst)
            if dst_port:
                dst_port_counter[dst_port] += 1

            
            if 'HTTP' in pkt or 'http' in dst:
                protocol_counter['HTTP'] += 1
            elif 'PTR' in pkt or 'NXDomain' in pkt or 'domain' in dst:
                protocol_counter['DNS'] += 1
            else:
                protocol_counter['OTHER'] += 1

            
            flags_m = flags_re.search(pkt)
            seq_m = seq_re.search(pkt)
            ack_m = ack_re.search(pkt)
            flags = flags_m.group(1) if flags_m else ''
            seq = seq_m.group(1) if seq_m else ''
            ack = ack_m.group(1) if ack_m else ''

            packets.append({
                'Timestamp': ts,
                'Source': src,
                'Destination': dst,
                'Length': length,
                'Flags': flags,
                'Seq': seq,
                'Ack': ack,
                'Packet_Info': pkt
            })

    
    top_sources = sorted(src_volume.items(), key=lambda x: x[1], reverse=True)[:10]
    
    top_scanners = sorted(src_targets_set.items(), key=lambda x: len(x[1]), reverse=True)[:10]

    
    with open(OUTPUT_MD, 'w', encoding='utf-8') as md:
        md.write('# Rapport Complet - Analyse des Menaces\n\n')
        md.write(f'Total paquets analysés: **{total_packets}**\n\n')
        md.write(f'Total octets (approx): **{total_bytes}**\n\n')

        md.write('## Top sources par volume (top 10)\n')
        md.write('| Rang | Source | Volume (octets) | Nombre cibles uniques |\n')
        md.write('| --- | --- | ---: | ---: |\n')
        for i, (src, vol) in enumerate(top_sources, 1):
            md.write(f'| {i} | {src} | {vol} | {len(src_targets_set[src])} |\n')

        md.write('\n')

        md.write('## Top sources par nombre de cibles uniques (scan)\n')
        md.write('| Rang | Source | Cibles uniques |\n')
        md.write('| --- | --- | ---: |\n')
        for i, (src, targets) in enumerate(top_scanners, 1):
            md.write(f'| {i} | {src} | {len(targets)} |\n')

        md.write('\n')

        
        md.write('## Détails pour les principales sources suspectes\n')
        suspects = [s for s, _ in top_sources[:5]]
        for s in suspects:
            md.write(f'### Source: {s}\n')
            dests = sorted(src_targets[s].items(), key=lambda x: x[1], reverse=True)[:10]
            md.write('| Destination | Octets transférés | Comptes de paquets approximatif |\n')
            md.write('| --- | ---: | ---: |\n')
            for d, vol in dests:
                md.write(f'| {d} | {vol} | (approx) |\n')
            md.write('\n')

        
        md.write('## Ports de destination les plus visés\n')
        md.write('| Port | Nombre d\'apparitions |\n')
        md.write('| --- | ---: |\n')
        for port, cnt in dst_port_counter.most_common(20):
            md.write(f'| {port} | {cnt} |\n')

        md.write('\n')

        md.write('## Répartition par protocole (heuristique)\n')
        md.write('| Protocole | Comptes |\n')
        md.write('| --- | ---: |\n')
        for proto, cnt in protocol_counter.items():
            md.write(f'| {proto} | {cnt} |\n')

        md.write('\n')

        
        if top_scanners:
            top_scanner = top_scanners[0][0]
            md.write(f'## Cibles visées par le principal scanneur: {top_scanner}\n')
            md.write('| Destination | Octets transférés |\n')
            md.write('| --- | ---: |\n')
            dests = sorted(src_targets[top_scanner].items(), key=lambda x: x[1], reverse=True)
            for d, vol in dests:
                md.write(f'| {d} | {vol} |\n')
            md.write('\n')

        
        md.write('## Exemples de paquets (échantillon)\n')
        md.write('| Timestamp | Source | Destination | Length | Flags | Seq | Ack | Info |\n')
        md.write('| --- | --- | --- | ---: | --- | --- | --- | --- |\n')
        sample = []
        for s, _ in top_sources[:5]:
            for p in packets:
                if p['Source'] == s:
                    sample.append(p)
                    if len(sample) >= 20:
                        break
            if len(sample) >= 20:
                break
        for p in sample:
            info = (p['Packet_Info'] or '').replace('|', '/')[:80]
            md.write(f"| {p['Timestamp']} | {p['Source']} | {p['Destination']} | {p['Length']} | {p['Flags']} | {p['Seq']} | {p['Ack']} | {info} |\n")

    print(f"Rapport généré: {OUTPUT_MD}")


if __name__ == '__main__':
    analyze()
