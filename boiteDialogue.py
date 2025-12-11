import tkinter as tk
from tkinter import filedialog, scrolledtext, messagebox

# --- FONCTION PRINCIPALE : lit le fichier ICS et renvoie le tableau de chaînes pseudo-CSV ---
def lire_ics(chemin_fichier):
    """
    Lit un fichier ICS et retourne un tableau (liste) de chaînes pseudo-CSV,
    une chaîne par événement.
    Format : "DateDébut;DateFin;Résumé;Lieu;Description"
    """
    try:
        pseudo_csv = []
        with open(chemin_fichier, "r", encoding="utf-8") as f:
            contenu = f.read()

        # Séparer les événements (ignorer l'en-tête du fichier)
        evenements = contenu.split("BEGIN:VEVENT")[1:]

        for evt in evenements:
            if "END:VEVENT" not in evt:
                continue  # Ignorer les événements incomplets
                
            lignes = evt.strip().splitlines()
            info = {
                "debut": "", "fin": "", "resume": "", "lieu": "", "desc": ""
            }
            
            # Extraire les informations de chaque ligne
            for ligne in lignes:
                if ligne.startswith("DTSTART"):
                    info["debut"] = ligne.split(":", 1)[1].strip()
                elif ligne.startswith("DTEND"):
                    info["fin"] = ligne.split(":", 1)[1].strip()
                elif ligne.startswith("SUMMARY"):
                    info["resume"] = ligne.split(":", 1)[1].strip().replace(";", " ")  # Échapper les ;
                elif ligne.startswith("LOCATION"):
                    info["lieu"] = ligne.split(":", 1)[1].strip().replace(";", " ")
                elif ligne.startswith("DESCRIPTION"):
                    info["desc"] = ligne.split(":", 1)[1].strip().replace(";", " ")

            # Construire la ligne pseudo-CSV
            ligne_csv = f"{info['debut']};{info['fin']};{info['resume']};{info['lieu']};{info['desc']}"
            pseudo_csv.append(ligne_csv)

        return pseudo_csv
        
    except Exception as e:
        messagebox.showerror("Erreur", f"Erreur lecture fichier : {str(e)}")
        return []


# --- FONCTIONS INTERFACE ---
def choisir_fichier():
    chemin_fichier = filedialog.askopenfilename(
        title="Sélectionner un fichier ICS",
        filetypes=[("Fichiers ICS", "*.ics"), ("Tous les fichiers", "*.*")]
    )

    if chemin_fichier:
        label_chemin.config(text=f"Fichier : {chemin_fichier.split('/')[-1]}")
        
        # Traitement du fichier ICS
        tableau = lire_ics(chemin_fichier)
        
        if tableau:
            # Afficher dans la zone de texte
            zone_resultat.delete(1.0, tk.END)
            zone_resultat.insert(tk.END, f"Nombre d'événements trouvés : {len(tableau)}\n\n")
            zone_resultat.insert(tk.END, "DateDébut;DateFin;Résumé;Lieu;Description\n")
            zone_resultat.insert(tk.END, "-" * 80 + "\n")
            
            for i, ligne in enumerate(tableau, 1):
                zone_resultat.insert(tk.END, f"{i:2d}. {ligne}\n")
            
            status_label.config(text=f"{len(tableau)} événements chargés")
        else:
            zone_resultat.delete(1.0, tk.END)
            zone_resultat.insert(tk.END, "Aucun événement trouvé.")
            status_label.config(text="Erreur de lecture")
    else:
        label_chemin.config(text="Aucun fichier sélectionné")


def quitter():
    fenetre.destroy()


def effacer_resultats():
    zone_resultat.delete(1.0, tk.END)
    label_chemin.config(text="Aucun fichier sélectionné")
    status_label.config(text="Prêt")


# --- INTERFACE GRAPHIQUE ---
fenetre = tk.Tk()
fenetre.title("Programme2.py - Lecteur ICS vers Pseudo-CSV")
fenetre.geometry("800x600")

# Boutons
frame_boutons = tk.Frame(fenetre)
frame_boutons.pack(pady=10)

btn_choisir = tk.Button(frame_boutons, text="Choisir fichier ICS", command=choisir_fichier, bg="#4CAF50", fg="white")
btn_choisir.pack(side=tk.LEFT, padx=10)

btn_effacer = tk.Button(frame_boutons, text="Effacer", command=effacer_resultats)
btn_effacer.pack(side=tk.LEFT, padx=10)

btn_quitter = tk.Button(frame_boutons, text="Quitter", command=quitter, bg="#f44336", fg="white")
btn_quitter.pack(side=tk.LEFT, padx=10)

# Info fichier
label_chemin = tk.Label(fenetre, text="Aucun fichier sélectionné", fg="blue")
label_chemin.pack(pady=5)

# Zone de résultats
tk.Label(fenetre, text="Tableau pseudo-CSV des événements :", font=("Arial", 10, "bold")).pack(anchor="w", padx=10)
zone_resultat = scrolledtext.ScrolledText(fenetre, width=90, height=25, wrap=tk.WORD)
zone_resultat.pack(padx=10, pady=5, fill=tk.BOTH, expand=True)

# Status
status_label = tk.Label(fenetre, text="Prêt", fg="green")
status_label.pack(pady=5)

# Lancer l'application
if __name__ == "__main__":
    fenetre.mainloop()
