import tkinter as tk
from tkinter import ttk
import subprocess
import scapy.all as scapy
import requests
import numpy as np
import pandas as pd

# Configurer le bot Telegram
TELEGRAM_API_URL = "https://api.telegram.org/bot7787535602:AAENiaZPT8nz70EsrVbxBO-ti8BTBVHIEtk/sendMessage"
CHAT_ID = "6386909236"  # Remplacez par votre chat_id

# Classe principale de l'application
class SecurityApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Application de Sécurité Réseau")
        self.create_dashboard()
        
        # Stockage des données de trafic
        self.network_data = []
        self.moving_avg_window = 5  # Fenêtre pour la moyenne mobile
        self.threshold = 1.5  # Seuil pour détecter une anomalie (à ajuster)
        
    def create_dashboard(self):
        # Créer les onglets
        tab_control = ttk.Notebook(self.root)
        traffic_tab = ttk.Frame(tab_control)
        scan_tab = ttk.Frame(tab_control)
        
        tab_control.add(traffic_tab, text='Analyse du Trafic')
        tab_control.add(scan_tab, text='Scan de Réseau')
        tab_control.pack(expand=1, fill='both')

        # Onglet Analyse du Trafic
        start_capture_btn = tk.Button(traffic_tab, text="Démarrer Capture", command=self.start_capture)
        start_capture_btn.pack(pady=10)

        self.interface_var = tk.StringVar(value=scapy.get_if_list()[0])
        interface_label = tk.Label(traffic_tab, text="Choisir l'interface:")
        interface_label.pack(pady=5)
        interface_dropdown = ttk.Combobox(traffic_tab, textvariable=self.interface_var, values=scapy.get_if_list())
        interface_dropdown.pack(pady=5)

        # Onglet Scan de Réseau
        scan_button = tk.Button(scan_tab, text="Scanner le Réseau", command=self.scan_network)
        scan_button.pack(pady=10)
        
    def start_capture(self):
        iface = self.interface_var.get()
        scapy.sniff(iface=iface, prn=self.capture_traffic)
        
    def capture_traffic(self, packet):
        # Ajout de données de trafic pour analyse
        self.network_data.append(packet.summary())
        print(packet.summary())
        self.analyze_threats()
        
    def analyze_threats(self):
        # Convertir les données en DataFrame pour l'analyse
        df = pd.DataFrame(self.network_data, columns=["Traffic"])
        
        # Générer des données aléatoires pour simuler le volume de trafic
        df['TrafficVolume'] = np.random.rand(len(df)) * 100  # Simuler des volumes de trafic (à ajuster selon les données réelles)

        # Calculer la moyenne mobile
        df['MovingAvg'] = df['TrafficVolume'].rolling(window=self.moving_avg_window).mean()
        
        # Calculer les écarts entre le volume de trafic et la moyenne mobile
        df['Deviation'] = df['TrafficVolume'] - df['MovingAvg']
        
        # Identifier les anomalies en comparant l'écart avec le seuil
        df['Anomaly'] = df['Deviation'].apply(lambda x: 1 if abs(x) > self.threshold else 0)
        
        # Vérifier s'il y a des anomalies
        if df['Anomaly'].any() == 1:  # S'il y a au moins une anomalie détectée
            self.send_telegram_alert("Anomalie détectée dans le trafic réseau!")
        
    def scan_network(self):
        command = ["nmap", "-sP", "192.168.1.0/24"]  # Remplacez par votre plage IP
        result = subprocess.run(command, capture_output=True, text=True)
        self.display_scan_results(result.stdout)
        
    def display_scan_results(self, results):
        print("Résultats du scan :")
        print(results)
        
    def send_telegram_alert(self, message):
        payload = {
            'chat_id': CHAT_ID,
            'text': message
        }
        requests.post(TELEGRAM_API_URL, data=payload)

# Exécution de l'application
if __name__ == "__main__":
    root = tk.Tk()
    app = SecurityApp(root)
    root.mainloop()
