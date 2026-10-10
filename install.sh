#!/bin/bash

# Warna untuk output cantik
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}=================================================${NC}"
echo -e "${BLUE}   EKA DASHBOARD - INSTALLER OTOMATIS            ${NC}"
echo -e "${BLUE}=================================================${NC}"
echo ""

# Cek apakah dijalankan sebagai root (Sudo)
if [ "$EUID" -ne 0 ]; then 
  echo -e "${RED}[ERROR] Mohon jalankan script ini dengan sudo!${NC}"
  echo "Usage: sudo bash install.sh"
  exit 1
fi

# --- CONFIGURATION ---
INSTALL_DIR="/root/eka_dashboard"
CURRENT_DIR=$(pwd)

# --- STEP 0: Cek Mode Update ---
# Jika kita tidak berada di INSTALL_DIR, asumsikan ini adalah folder update hasil ekstraksi ZIP
if [ "$CURRENT_DIR" != "$INSTALL_DIR" ]; then
    echo -e "${BLUE}[INFO] Mendeteksi Mode Update/Instalasi Baru...${NC}"
    echo -e "Sumber: $CURRENT_DIR"
    echo -e "Tujuan: $INSTALL_DIR"
    
    # Konfirmasi (Auto-yes jika ada flag -y, tapi sementara manual dulu atau langsung gas)
    echo -e "${YELLOW}Akan mengupdate file sistem di $INSTALL_DIR...${NC}"
    
    # 1. Buat folder tujuan jika belum ada
    if [ ! -d "$INSTALL_DIR" ]; then
        echo -e "Membuat folder instalasi baru..."
        mkdir -p "$INSTALL_DIR"
    fi
    
    # 2. Copy file (kecuali data/ config user)
    echo -e "Menyalin file update..."
    # Copy semua file dari current dir ke install dir
    # Kita pakai rsync atau cp -r. Hati-hati jangan overwrite data jika ada di source (tapi source dari zip update biasanya bersih dari data)
    
    # Exclude data folder dari copy agar tidak menimpa data user (meskipun di zip kosong)
    # Gunakan cp -rf untuk overwrite code
    find "$CURRENT_DIR" -mindepth 1 -maxdepth 1 ! -name 'data' ! -name '.env' ! -name '.git' -exec cp -rf {} "$INSTALL_DIR/" \;
    
    # 3. Pindah ke folder instalasi
    echo -e "Pindah ke $INSTALL_DIR untuk melanjutkan instalasi..."
    cd "$INSTALL_DIR"
    
    # Pastikan executables
    chmod +x install.sh
fi

# --- STEP 1: Port configuration (non-destructive) ---
# Never rewrite CasaOS configuration or stop arbitrary host processes automatically.
ENV_DASHBOARD_PORT=""
if [ -f ".env" ]; then
    ENV_DASHBOARD_PORT="$(sed -n 's/^DASHBOARD_PORT=//p' .env | tail -n 1)"
fi
DASHBOARD_PORT="${DASHBOARD_PORT:-${ENV_DASHBOARD_PORT:-80}}"
if ! [[ "$DASHBOARD_PORT" =~ ^[0-9]+$ ]] || [ "$DASHBOARD_PORT" -lt 1 ] || [ "$DASHBOARD_PORT" -gt 65535 ]; then
    echo -e "${RED}[ERROR] DASHBOARD_PORT harus berupa angka 1-65535.${NC}"
    exit 1
fi

if [ -f "/etc/casaos/gateway.ini" ]; then
    echo -e "${YELLOW}[INFO] CasaOS terdeteksi. Installer tidak akan mengubah port CasaOS otomatis.${NC}"
fi

# Detect conflicts but never kill or disable the process that owns the port.
if command -v lsof >/dev/null 2>&1; then
    PORT_PIDS="$(lsof -nP -iTCP:"$DASHBOARD_PORT" -sTCP:LISTEN -t 2>/dev/null || true)"
    if [ -n "$PORT_PIDS" ]; then
        if docker ps --format '{{.Names}}' 2>/dev/null | grep -Fxq 'eka_dashboard'; then
            echo -e "${BLUE}[INFO] Container eka_dashboard sudah berjalan; melanjutkan update tanpa menghentikan proses host.${NC}"
        else
            echo -e "${RED}[ERROR] Port $DASHBOARD_PORT sedang dipakai proses lain.${NC}"
            echo -e "Atur port yang kosong pada file .env, misalnya DASHBOARD_PORT=8080."
            echo -e "Installer berhenti tanpa menghentikan proses atau mengubah konfigurasi host."
            exit 1
        fi
    fi
fi

# --- STEP 3: Persiapan Docker & Deployment ---
echo -e "${BLUE}[INFO] Memeriksa instalasi Docker...${NC}"

# Cek Docker, Install otomatis jika belum ada
if ! command -v docker &> /dev/null; then
    echo -e "${YELLOW}[WARNING] Docker belum terinstall. Memulai instalasi otomatis Docker...${NC}"
    curl -fsSL https://get.docker.com | sh
    if [ $? -ne 0 ]; then
        echo -e "${RED}[CRITICAL ERROR] Gagal menginstall Docker secara otomatis. Silakan cek koneksi internet atau install manual.${NC}"
        exit 1
    fi
    echo -e "${GREEN}[OK] Docker berhasil diinstall.${NC}"
else
    echo -e "${GREEN}[OK] Docker sudah terinstall.${NC}"
fi

# Determine Docker Compose command, Install jika belum ada
if command -v docker-compose &> /dev/null; then
    COMPOSE_CMD="docker-compose"
elif docker compose version &> /dev/null; then
    COMPOSE_CMD="docker compose"
else
    echo -e "${YELLOW}[WARNING] Docker Compose tidak ditemukan. Menginstall Docker Compose Plugin...${NC}"
    apt-get update && apt-get install -y docker-compose-plugin
    if docker compose version &> /dev/null; then
        COMPOSE_CMD="docker compose"
        echo -e "${GREEN}[OK] Docker Compose berhasil diinstall.${NC}"
    else
        echo -e "${RED}[ERROR] Gagal menginstall Docker Compose otomatis. Mohon install manual.${NC}"
        exit 1
    fi
fi

echo -e "\${BLUE}[INFO] Membangun dan Menjalankan Dashboard...\${NC}"

# Create a persistent session-signing secret once; preserve it on future updates.
# .env is excluded from Git and made readable only by root.
umask 077
touch .env
if ! grep -Eq '^SECRET_KEY=.+$' .env; then
    if ! command -v openssl >/dev/null 2>&1; then
        echo -e "\${RED}[ERROR] openssl diperlukan untuk membuat SECRET_KEY yang aman.\${NC}"
        exit 1
    fi
    sed -i '/^SECRET_KEY=/d' .env
    printf 'SECRET_KEY=%s\n' "$(openssl rand -hex 32)" >> .env
fi
chmod 600 .env

# Rebuild in place; preserve active services and security configuration.
if $COMPOSE_CMD up --build -d; then
    echo ""
    echo -e "\${GREEN}=================================================\${NC}"
    echo -e "\${GREEN}      INSTALASI SUKSES!             \${NC}"
    echo -e "\${GREEN}=================================================\${NC}"
    echo ""

    IP_ADDR=$(hostname -I | awk '{print $1}')

    echo -e "Silakan akses Dashboard Admin di:"
    echo -e "\${BLUE}   http://$IP_ADDR:$DASHBOARD_PORT \${NC}"
    echo -e "Jika memakai port 80, URL juga dapat dibuka tanpa menulis :80."
    echo -e "Untuk mengubah port, atur DASHBOARD_PORT di file .env."
    echo ""
    echo -e "Terima kasih telah menggunakan produk ini."
else
    echo -e "\${RED}[ERROR] Gagal menjalankan Docker Container.\${NC}"
    exit 1
fi
