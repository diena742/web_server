# Panduan Instalasi Eka Dashboard

Panduan ini menjelaskan instalasi dan konfigurasi dasar Eka Dashboard pada Linux (Ubuntu, Debian, Armbian, STB, Mini PC, VPS, atau server lokal).

> Jalankan installer hanya setelah meninjau perubahan sistem yang akan dilakukan. Installer versi branch ini tidak lagi memindahkan port CasaOS, mematikan layanan host, menghapus container secara paksa, atau menghapus konfigurasi keamanan secara otomatis.

## 1. Persiapan

Siapkan akses shell/SSH, koneksi internet, dan Docker. Installer dapat menawarkan instalasi Docker jika belum tersedia. Pastikan Anda mempunyai backup sebelum memperbarui instalasi yang sudah dipakai.

## 2. Instalasi

### Pilihan A — Git clone

\`\`\`bash
sudo apt-get update
sudo apt-get install -y git
git clone https://github.com/recode-project/web_server.git eka_dashboard
cd eka_dashboard
sudo bash install.sh
\`\`\`

### Pilihan B — ZIP

Ekstrak arsip ke direktori kerja, masuk ke direktori tersebut, lalu jalankan:

\`\`\`bash
sudo bash install.sh
\`\`\`

Installer menyalin file aplikasi ke \`/root/eka_dashboard\` tanpa menyalin folder \`data/\` atau file \`.env\` dari direktori sumber. Di direktori instalasi, \`data/\` dan \`.env\` dipertahankan selama pembaruan.

## 3. Port dan CasaOS

Secara default dashboard memakai port host \`80\` dan port container \`5000\`. Installer tidak mengubah port CasaOS atau menghentikan layanan lain. Jika port 80 sedang dipakai, pilih port kosong di file \`.env\` **sebelum** instalasi:

\`\`\`bash
cd eka_dashboard
printf 'DASHBOARD_PORT=8080\n' >> .env
sudo bash install.sh
\`\`\`

Akses dashboard dengan \`http://IP-SERVER:8080\`. Jika sudah terpasang, ubah \`DASHBOARD_PORT\` di \`/root/eka_dashboard/.env\`, lalu jalankan:

\`\`\`bash
cd /root/eka_dashboard
sudo docker compose up -d
\`\`\`

Jika port tetap bentrok, pilih port yang tidak digunakan. Jangan menghentikan proses host yang tidak dikenal hanya untuk membebaskan port.

## 4. Login awal dan token setup satu kali

Installer membuat token setup acak dan menyimpannya di `/root/eka_dashboard/.env`. Sebelum membuka wizard, ambil token melalui shell server tepercaya:

```bash
sudo sed -n 's/^SETUP_TOKEN=//p' /root/eka_dashboard/.env
```

Masukkan token tersebut pada halaman Setup Admin, lalu buat akun owner dengan password sekurang-kurangnya 12 karakter. Jangan mengirim token melalui issue/PR atau membiarkan terminal/server setup dapat diakses orang yang tidak dipercaya.

Jika melakukan instalasi manual tanpa `install.sh`, buat token sebelum menyalakan Compose:

```bash
umask 077
touch .env
printf 'SETUP_TOKEN=%s\\n' "$(openssl rand -hex 32)" >> .env
printf 'SECRET_KEY=%s\\n' "$(openssl rand -hex 32)" >> .env
chmod 600 .env
sudo docker compose up --build -d
```

Pastikan nilai tersebut diteruskan ke container melalui `docker-compose.yml`. Tanpa `SETUP_TOKEN` yang dikonfigurasi, endpoint setup menolak pembuatan akun pertama.

## 5. Secret, token mobile, dan origin browser

### Secret sesi

Installer membuat \`SECRET_KEY\` acak dan menyimpannya di file \`.env\` agar sesi tetap valid setelah container diperbarui. Jangan menghapus, mengunggah, atau memasukkan \`.env\` ke commit. File tersebut dicakup oleh \`.gitignore\`.

Jika menjalankan Compose secara manual tanpa installer, buat secret yang persisten satu kali:

\`\`\`bash
cd /root/eka_dashboard
umask 077
touch .env
if ! grep -Eq '^SECRET_KEY=.+$' .env; then
    sed -i '/^SECRET_KEY=/d' .env
    printf 'SECRET_KEY=%s\n' "$(openssl rand -hex 32)" >> .env
fi
chmod 600 .env
\`\`\`

### Aplikasi Android Mobile Backup (opsional)

API Mobile Backup menerima sesi dashboard atau token khusus dari environment \`MOBILE_ACCESS_TOKEN\`. Token ini hanya berlaku untuk rute \`/api/mobile-backup/*\`; tidak ada lagi header rahasia yang melewati autentikasi global.

Untuk membuat token, jalankan di server dan simpan nilainya hanya di konfigurasi privat aplikasi Android:

\`\`\`bash
cd /root/eka_dashboard
umask 077
touch .env
if ! grep -Eq '^SECRET_KEY=.+
sed -i '/^MOBILE_ACCESS_TOKEN=/d' .env
TOKEN="$(openssl rand -hex 32)"
printf 'MOBILE_ACCESS_TOKEN=%s\n' "$TOKEN" >> .env
chmod 600 .env
printf 'Atur header X-Mobile-Key aplikasi Android menjadi: %s\n' "$TOKEN"
sudo docker compose up -d --build
\`\`\`

Perintah ini mengganti secret sesi, sehingga semua sesi browser yang sudah aktif akan diminta login kembali. Jika Anda hanya perlu membuat token mobile dan telah memiliki \`SECRET_KEY\` yang benar, jangan menghapus atau menggantinya; hapus hanya baris \`MOBILE_ACCESS_TOKEN\` lama sebelum membuat token baru.

Jangan masukkan nilai secret atau token ke source code, commit Git, screenshot, issue, atau Pull Request.

 .env; then
    sed -i '/^SECRET_KEY=/d' .env
    printf 'SECRET_KEY=%s\n' "$(openssl rand -hex 32)" >> .env
fi
sed -i '/^MOBILE_ACCESS_TOKEN=/d' .env
TOKEN="$(openssl rand -hex 32)"
printf 'MOBILE_ACCESS_TOKEN=%s\n' "$TOKEN" >> .env
chmod 600 .env
printf 'Atur header X-Mobile-Key aplikasi Android menjadi: %s\n' "$TOKEN"
sudo docker compose up -d --build
\`\`\`

Perintah ini mengganti secret sesi, sehingga semua sesi browser yang sudah aktif akan diminta login kembali. Jika Anda hanya perlu membuat token mobile dan telah memiliki \`SECRET_KEY\` yang benar, jangan menghapus atau menggantinya; hapus hanya baris \`MOBILE_ACCESS_TOKEN\` lama sebelum membuat token baru.

Jangan masukkan nilai secret atau token ke source code, commit Git, screenshot, issue, atau Pull Request.

### Akses file untuk role operator dan read-only

Karena dashboard memiliki akses host-level untuk file manager, role `operator` dan `readonly` tidak boleh otomatis membaca seluruh filesystem (termasuk `.env` dan konfigurasi sistem). Secara default akses file untuk role tersebut belum diaktifkan. Jika mereka memang perlu melihat folder bersama, buat direktori yang memang aman untuk dibagikan dan set path container di `.env`:

```bash
sudo mkdir -p /mnt/data/DashboardShared
sudo chmod 755 /mnt/data/DashboardShared
printf 'FILES_READONLY_ROOTS=/host/root/mnt/data/DashboardShared\\n' >> /root/eka_dashboard/.env
sudo docker compose up -d
```

Anda dapat mencantumkan beberapa direktori yang dipercaya dengan memisahkannya memakai koma. Path harus berupa path di dalam container, biasanya diawali `/host/root/`. Owner/admin tetap memiliki akses file manager penuh.

### CORS dan cookie sesi

Secara default UI dan Socket.IO hanya menerima origin yang sama dengan dashboard. Jika memang memakai frontend browser dari origin lain, set \`DASHBOARD_ALLOWED_ORIGINS\` di \`.env\` sebagai daftar origin lengkap dipisahkan koma, misalnya \`https://dashboard.example.com\`. Jangan memakai wildcard untuk origin yang membawa cookie sesi. Jika dashboard diakses melalui HTTPS, set \`SESSION_COOKIE_SECURE=1\`; nilai default \`0\` dipakai saat akses langsung melalui HTTP di LAN.

## 6. FAQ dan pemecahan masalah

**Port sudah digunakan.** Atur \`DASHBOARD_PORT=8080\` (atau port kosong lain) di file \`.env\`; installer tidak akan menghentikan proses yang memakai port tersebut.

**Dashboard tidak dapat dibuka.** Pastikan container aktif dengan \`sudo docker compose ps\`, periksa log dengan \`sudo docker compose logs --tail=200\`, lalu pastikan firewall mengizinkan port yang dipilih.

**Bagaimana memperbarui aplikasi?** Masuk ke direktori instalasi dan jalankan \`sudo bash install.sh\` dari salinan source yang akan dipakai. Installer mempertahankan folder \`data/\`, file \`.env\`, dan konfigurasi keamanan. Buat backup sebelum upgrade.

**Bagaimana mengganti password owner yang terlupa?** Jangan menghapus \`data/security_config.json\` pada server yang dapat dijangkau jaringan; tindakan itu mengaktifkan wizard setup kembali dan berisiko memberi orang lain kesempatan mengambil alih akun. Gunakan console tepercaya di server untuk memperbarui hash password utama saat container berjalan:

\`\`\`bash
cd /root/eka_dashboard
sudo docker exec -it eka_dashboard python -c 'import getpass, app; cfg=app.load_security_config(); pw=getpass.getpass("Password baru (min. 12 karakter): "); assert len(pw) >= 12, "Password terlalu pendek"; cfg["password_hash"]=app.create_password_hash(pw); app.save_security_config(cfg); print("Password owner diperbarui.")'
\`\`\`

Perintah itu mengubah hash password utama dan mempertahankan konfigurasi pengguna lain. Jalankan hanya dari shell tepercaya.

**Bagaimana memeriksa log?** Gunakan \`sudo docker compose logs -f\`; tekan \`Ctrl+C\` untuk keluar tanpa menghentikan container.

**Bagaimana menghentikan dashboard?** Gunakan \`sudo docker compose stop\`. Gunakan \`sudo docker compose up -d\` untuk menyalakannya kembali. Perintah \`down\` menghapus container dan network Compose, tetapi tidak menghapus bind-mounted \`data/\` atau \`.env\`.

---

Dokumen ini menjelaskan perilaku branch pengembangan \`fix/critical-bugs\`; tetap periksa hasil CI dan konfigurasi host sebelum menerapkan perubahan di server produksi.
