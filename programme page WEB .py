import csv
import re
import datetime
import os

# --- CONFIGURATION ---
FICHIER_SOURCE = 'DumpFile.csv'
PAGE_SORTIE_HTML = 'Rapport_Final.html'
OUT_VOL = 'top_sources_volume.png'
OUT_SCAN = 'top_scanners_count.png'

# Seuils de détection
SEUIL_VOLUME_EXFIL = 1000000  # 1 Mo
SEUIL_SCAN_CIBLES = 10        # 10 IPs cibles uniques

def identifier_attaque(ip, volume, cibles):
    """Analyse le comportement pour définir le type d'attaque"""
    if cibles > SEUIL_SCAN_CIBLES and volume < 200000:
        return "Balayage de Ports (Scanning)", "warning"
    elif volume > SEUIL_VOLUME_EXFIL and cibles <= 2:
        return "Exfiltration de Données", "danger"
    elif volume > 500000 and cibles > 5:
        return "Tentative de DDoS", "danger"
    else:
        return "Activité Suspecte", "warning"

def generer_page_web():
    stats = {}
    print(f"⏳ Analyse de {FICHIER_SOURCE} en cours...")

    try:
        # 1. Extraction des données
        with open(FICHIER_SOURCE, mode='r', encoding='utf-8') as f:
            reader = csv.DictReader(f, delimiter=';')
            for row in reader:
                src = row.get('Source')
                dst = row.get('Destination')
                
                length = 0
                if row.get('Length'):
                    try: length = int(row.get('Length'))
                    except: length = 0
                else:
                    info = row.get('Packet_Info', '') or row.get('HeaderRest', '')
                    m = re.search(r"length\s+(\d+)", info)
                    length = int(m.group(1)) if m else 0

                if src:
                    if src not in stats:
                        stats[src] = {'volume': 0, 'cibles': set()}
                    stats[src]['volume'] += length
                    stats[src]['cibles'].add(dst)

        # 2. Construction du HTML
        now = datetime.datetime.now().strftime("%d/%m/%Y à %H:%M")
        
        html_template = f"""
        <!DOCTYPE html>
        <html lang="fr">
        <head>
            <meta charset="UTF-8">
            <title>Rapport de Sécurité Réseau</title>
            <style>
                body {{ font-family: 'Helvetica Neue', Arial, sans-serif; background-color: #f0f2f5; padding: 40px; color: #333; }}
                .container {{ max-width: 1000px; background: white; padding: 30px; border-radius: 15px; box-shadow: 0 10px 25px rgba(0,0,0,0.1); margin: auto; }}
                h1 {{ color: #1a365d; border-bottom: 3px solid #3182ce; padding-bottom: 15px; }}
                .meta {{ color: #718096; margin-bottom: 30px; font-style: italic; }}
                table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
                th {{ background-color: #3182ce; color: white; padding: 12px; text-align: left; }}
                td {{ padding: 12px; border-bottom: 1px solid #e2e8f0; }}
                tr:hover {{ background-color: #f7fafc; }}
                .badge {{ padding: 6px 12px; border-radius: 20px; font-size: 0.85em; font-weight: bold; text-transform: uppercase; }}
                .danger {{ background-color: #fed7d7; color: #c53030; }}
                .warning {{ background-color: #feebc8; color: #c05621; }}
                .success {{ background-color: #c6f6d5; color: #2f855a; }}
                code {{ background: #edf2f7; padding: 2px 5px; border-radius: 4px; font-family: monospace; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>🛡️ Rapport d'Analyse des Menaces</h1>
                <p class="meta">Généré le {now} | Analyse des flux IP</p>
                
                <table>
                    <thead>
                        <tr>
                            <th>IP Source</th>
                            <th>Type d'Attaque</th>
                            <th>Gravité</th>
                            <th>Détails (Volume / Cibles)</th>
                        </tr>
                    </thead>
                    <tbody>
        """

        compteur = 0
        for ip, data in stats.items():
            vol = data['volume']
            nb_cibles = len(data['cibles'])

            if vol > SEUIL_VOLUME_EXFIL or nb_cibles > SEUIL_SCAN_CIBLES:
                nom_attaque, classe_css = identifier_attaque(ip, vol, nb_cibles)
                html_template += f"""
                <tr>
                    <td><code>{ip}</code></td>
                    <td>{nom_attaque}</td>
                    <td><span class="badge {classe_css}">{classe_css}</span></td>
                    <td>{vol} octets / {nb_cibles} cible(s)</td>
                </tr>
                """
                compteur += 1

        if compteur == 0:
            html_template += "<tr><td colspan='4' style='text-align:center;'>✅ Aucune menace détectée.</td></tr>"

        # Générer les graphiques (si matplotlib est installé)
        def generate_graphs(local_stats):
            try:
                import matplotlib.pyplot as plt
            except Exception:
                return False

            top_sources = sorted(((s, d['volume']) for s, d in local_stats.items()), key=lambda x: x[1], reverse=True)[:10]
            top_scanners = sorted(((s, len(d['cibles'])) for s, d in local_stats.items()), key=lambda x: x[1], reverse=True)[:10]

            if top_sources:
                names = [s for s, _ in top_sources]
                vols = [v for _, v in top_sources]
                plt.figure(figsize=(10,5))
                plt.bar(range(len(names)), vols, color='tab:blue')
                plt.xticks(range(len(names)), names, rotation=45, ha='right')
                plt.ylabel('Volume (octets)')
                plt.title('Top sources par volume')
                plt.tight_layout()
                plt.savefig(OUT_VOL)
                plt.close()

            if top_scanners:
                names = [s for s, _ in top_scanners]
                counts = [c for _, c in top_scanners]
                plt.figure(figsize=(10,5))
                plt.bar(range(len(names)), counts, color='tab:orange')
                plt.xticks(range(len(names)), names, rotation=45, ha='right')
                plt.ylabel('Nombre de cibles uniques')
                plt.title('Top scanneurs par cibles uniques')
                plt.tight_layout()
                plt.savefig(OUT_SCAN)
                plt.close()
            return True

        graphs_generated = generate_graphs(stats)

        # Préparer le HTML pour les graphiques (si disponibles)
        graph_html = ''
        if graphs_generated or os.path.exists(OUT_VOL) or os.path.exists(OUT_SCAN):
            if os.path.exists(OUT_VOL):
                graph_html += f"<div style='margin-top:20px;'><h3>Top sources par volume</h3><img src='{OUT_VOL}' alt='Top volumes' style='max-width:100%'></div>"
            if os.path.exists(OUT_SCAN):
                graph_html += f"<div style='margin-top:12px;'><h3>Top scanneurs par cibles uniques</h3><img src='{OUT_SCAN}' alt='Top scanneurs' style='max-width:100%'></div>"
        else:
            graph_html = "<p style='color:#718096;'>(Graphiques indisponibles — installez matplotlib ou générez les images séparément.)</p>"

        html_template += f"""
                    </tbody>
                </table>
                {graph_html}
                <p style="margin-top: 30px; font-size: 0.8em; color: #a0aec0; text-align: center;">
                    Fin du rapport de sécurité réseau automatisé.
                </p>
            </div>
        </body>
        </html>
        """

        with open(PAGE_SORTIE_HTML, 'w', encoding='utf-8') as f:
            f.write(html_template)

        print(f"✅ Terminé ! {compteur} menaces trouvées.")
        print(f"🌍 Double-cliquez sur '{PAGE_SORTIE_HTML}' pour l'ouvrir dans Safari.")

    except FileNotFoundError:
        print(f"❌ Erreur : '{FICHIER_SOURCE}' est introuvable.")

if __name__ == "__main__":
    generer_page_web()