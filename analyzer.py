import collections

def executer_analyse():
    logs = []
    try:
        with open("network_log.txt", "r") as f:
            for ligne in f:
                champs = ligne.strip().split(";")
                if len(champs) == 6:
                    logs.append({"ip": champs[2], "port": champs[3], "statut": champs[5]})
    except FileNotFoundError:
        print("Fichier network_log.txt introuvable.")
        return

    total = len(logs)
    succes = sum(1 for l in logs if l['statut'] == "SUCCES")
    echecs = total - succes
    
    ports = [l['port'] for l in logs]
    top_ports = collections.Counter(ports).most_common(3)
    ip_active = collections.Counter([l['ip'] for l in logs]).most_common(1)[0]

    # Detection IP suspecte (> 5 echecs sur un port)
    echecs_par_cle = collections.Counter()
    suspects = set()
    for l in logs:
        if l['statut'] == "ECHEC":
            cle = (l['ip'], l['port'])
            echecs_par_cle[cle] += 1
            if echecs_par_cle[cle] > 5:
                suspects.add(l['ip'])

    with open("rapport_analyse.txt", "w") as r:
        r.write("=== RAPPORT D'ANALYSE NOC ===\n")
        r.write(f"Connexions totales : {total}\nSucces : {succes} | Echecs : {echecs}\n")
        r.write(f"IP la plus active : {ip_active[0]}\n")
        r.write("\nTOP 3 PORTS :\n")
        for p, c in top_ports: r.write(f"- Port {p} : {c} fois\n")
        r.write("\nIP SUSPECTES (ALERTE SECURITE) :\n")
        for s in suspects: r.write(f"- {s}\n")
    
    print(f"Analyse Python terminee. {total} lignes traitees.")

if __name__ == "__main__":
    executer_analyse()
Version Python
