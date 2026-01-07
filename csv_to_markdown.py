import csv

def generate_report(csv_file, output_md):
    try:
        # Initialisation des variables pour l'analyse
        data = []
        ip_stats = {} # Pour stocker volumes et cibles
        
        # 1. Lecture du fichier CSV
        with open(csv_file, mode='r', encoding='utf-8') as f:
            reader = csv.DictReader(f, delimiter=';')
            for row in reader:
                src = row.get('Source', '')
                dst = row.get('Destination', '')
                # Longueur : essayer plusieurs sources (colonne 'Length' directe ou extraire depuis 'Packet_Info')
                length_val = None
                if 'Length' in row and row.get('Length') is not None and row.get('Length') != '':
                    try:
                        length_val = int(row.get('Length'))
                    except ValueError:
                        length_val = None
                if length_val is None:
                    # Chercher "length <num>" dans la colonne Packet_Info si présente
                    pkt = row.get('Packet_Info', '') or row.get('HeaderRest', '')
                    m = None
                    try:
                        import re
                        m = re.search(r"length\s+(\d+)", pkt)
                    except Exception:
                        m = None
                    if m:
                        length_val = int(m.group(1))
                    else:
                        # valeur par défaut si non trouvée
                        length_val = 0
                length = length_val
                
                # On stocke les données pour le tableau global
                data.append(row)
                
                # Analyse par IP (pour identifier les 2 menaces)
                if src not in ip_stats:
                    ip_stats[src] = {'volume': 0, 'targets': set()}
                
                ip_stats[src]['volume'] += length
                ip_stats[src]['targets'].add(dst)

        # 2. Préparation des statistiques (Tri manuel)
        # Menace 1 : Plus gros volumes (Exfiltration)
        top_volumes = sorted(ip_stats.items(), key=lambda x: x[1]['volume'], reverse=True)[:5]
        
        # Menace 2 : Plus grand nombre de cibles (Scan)
        top_scanners = sorted(ip_stats.items(), key=lambda x: len(x[1]['targets']), reverse=True)[:5]

        # 3. Écriture du fichier Markdown
        with open(output_md, 'w', encoding='utf-8') as md:
            md.write("# 🛡️ Rapport de Sécurité Réseau - Site Inde\n\n")
            md.write(f"Ce rapport analyse les flux suspects détectés le **07 Janvier 2026**.\n\n")

            # Section Menace 1 : Exfiltration
            md.write("## 📤 Activité 1 : Volume de données sortant\n")
            md.write("| Adresse IP Source | Volume Total (Octets) | État |\n")
            md.write("| :--- | :--- | :--- |\n")
            for ip, stats in top_volumes:
                status = "⚠️ SUSPECT" if stats['volume'] > 1000000 else "✅ OK"
                md.write(f"| {ip} | {stats['volume']} | {status} |\n")
            
            md.write("\n")

            # Section Menace 2 : Balayage (Scan)
            md.write("## 🔍 Activité 2 : Analyse du Balayage Réseau\n")
            md.write("| Adresse IP Source | Nombre de cibles uniques | État |\n")
            md.write("| :--- | :--- | :--- |\n")
            for ip, stats in top_scanners:
                count = len(stats['targets'])
                status = "🚨 SCANNER" if count > 10 else "✅ OK"
                md.write(f"| {ip} | {count} | {status} |\n")

            # Section Détails (Tableau complet des 10 premières lignes)
            md.write("\n## 📋 Extrait des flux analysés\n")
            md.write("| Horodatage | Source | Destination | Taille |\n")
            md.write("| :--- | :--- | :--- | :--- |\n")
            for row in data[:10]:
                # Utiliser la même logique pour afficher la taille si la colonne Length est absente
                disp_len = row.get('Length')
                if not disp_len:
                    pkt = row.get('Packet_Info', '') or row.get('HeaderRest', '')
                    import re
                    m = re.search(r"length\s+(\d+)", pkt) if pkt else None
                    disp_len = m.group(1) if m else ''
                md.write(f"| {row.get('Timestamp','')} | {row.get('Source','')} | {row.get('Destination','')} | {disp_len} |\n")

        print(f"✅ Analyse terminée. Rapport généré dans : {output_md}")

    except FileNotFoundError:
        print("❌ Erreur : Le fichier CSV est introuvable.")
    except Exception as e:
        print(f"❌ Une erreur est survenue : {e}")

if __name__ == "__main__":
    generate_report('DumpFile.csv', 'Rapport_Final.md')