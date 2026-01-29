# 🕵️‍♂️ Telegram ReconOps Bot

**ReconOps Bot** adalah asisten keamanan siber otomatis berbasis Telegram yang dirancang untuk melakukan pengintaian (reconnaissance) pada target domain atau IP. Bot ini dibangun menggunakan Python dengan arsitektur OOP (Object-Oriented Programming) yang rapi, *asynchronous*, dan menggunakan database SQLite untuk manajemen riwayat.

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![Telegram](https://img.shields.io/badge/Telegram-Bot-blue)
![License](https://img.shields.io/badge/License-MIT-green)

## ✨ Fitur Utama

Bot ini mengintegrasikan berbagai *security tools* populer ke dalam satu antarmuka chat:

* **🔍 Nmap Scan**: Port scanning dan deteksi layanan (`-sV -sC`).
* **🌐 Subfinder**: Penemuan subdomain pasif.
* **📂 Dirsearch**: Enumerasi direktori dan file tersembunyi (Bruteforce).
* **📡 DNS Recon**: Analisis DNS record (A, MX, NS, TXT) menggunakan `dnspython`.
* **👤 Whois Intelligence**: Informasi registrasi domain (menggunakan CLI system).
* **🚀 All-in-One Mode**: Menjalankan seluruh tools di atas secara berurutan dalam satu perintah.
* **📄 Report Generation**: Hasil scan dikirimkan sebagai pesan preview dan file `.txt` yang dapat diunduh.

---

## ⚙️ Prasyarat (Requirements)

Sebelum menjalankan bot, pastikan sistem Anda (Linux/VPS) memiliki dependensi berikut:

### 1. System Tools
Bot ini memanggil tools eksternal melalui command line. Install tools berikut:

```bash
# Update repository
sudo apt update

# Install Nmap dan Whois
sudo apt install nmap whois -y

# Install Python Pip & Venv (jika belum ada)
sudo apt install python3-pip python3-venv -y
