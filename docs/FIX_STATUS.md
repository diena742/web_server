# Status Perbaikan dan Kriteria PR

Tanggal pembaruan: 2026-10-10  
Repositori kerja: [diena742/web_server](https://github.com/diena742/web_server)  
Branch: `fix/critical-bugs`  
Sumber upstream: [recode-project/web_server](https://github.com/recode-project/web_server)

## Status saat ini

Branch ini sudah mempunyai patch hardening pertama dan tes regresi otomatis. Ini belum berarti semua bug proyek sudah selesai, dan belum dianggap siap untuk PR final sampai blocker residual di bawah ditangani atau dibatasi secara eksplisit.

### Perbaikan yang sudah diterapkan

- Menghapus header `X-Mobile-Key` hard-coded sebagai bypass autentikasi global. Token mobile sekarang hanya diterima oleh endpoint `/api/mobile-backup/*`, melalui environment `MOBILE_ACCESS_TOKEN`.
- Memberikan pemeriksaan sesi dan role pada event Socket.IO terminal, memisahkan PTY per socket, mengirim output hanya ke socket pemilik, membatasi ukuran input/resize, dan membersihkan terminal saat disconnect.
- Memasang autentikasi/RBAC pada sejumlah API sistem, Docker, LXD, konfigurasi keamanan, log container, dan aksi host yang sebelumnya tidak konsisten dilindungi.
- Membatasi read-only file browser ke direktori yang secara eksplisit dikonfigurasi melalui `FILES_READONLY_ROOTS`. Owner/admin tetap mempunyai akses file host penuh sesuai rancangan aplikasi.
- Menambahkan pemeriksaan batas path dan memakai path kanonis pada operasi Mobile Backup; membatasi upload agar nama file aman dan file yang ada tidak tertimpa tanpa sengaja.
- Mengganti hash password baru menjadi Werkzeug PBKDF2, dengan verifikasi dan migrasi saat login sukses untuk hash SHA-256 lama.
- Menaikkan persyaratan panjang password baru menjadi minimum 12 karakter pada backend dan form terkait.
- Membatasi CORS/Socket.IO pada same-origin secara default, menambahkan konfigurasi allowlist origin, dan mengatur cookie sesi.
- Mengubah installer agar tidak otomatis mematikan proses host, memindahkan port CasaOS, menghapus container secara paksa, atau menghapus konfigurasi keamanan saat update. Port dashboard dapat dipilih melalui `DASHBOARD_PORT`; secret sesi disimpan di `.env`.
- Memperbarui panduan instalasi serta menambah workflow CI.

## Validasi otomatis

Workflow `.github/workflows/source-validation.yml` menjalankan kompilasi Python, instalasi dependensi, unit/regression tests, pengecekan sintaks JavaScript dan pengecekan sintaks shell. Run terakhir yang sudah selesai dan diverifikasi sebelum pembaruan dokumentasi ini melaporkan sukses. Cek halaman Actions untuk hasil dari commit paling baru sebelum membuat PR.

Saat ini terdapat 14 tes regresi yang meliputi hash password, first-run login, autentikasi endpoint file/LXD/mobile, terminal anonim, CORS, batas direktori read-only, redaksi secret, hak akses log Docker, dan perubahan password milik pengguna.

## Blocker / risiko yang belum selesai

### P0 — Arsitektur container mempunyai akses host yang sangat luas

`docker-compose.yml` masih menggunakan `privileged: true`, `pid: host`, Docker socket host, D-Bus system bus socket, mount root filesystem host ke `/host/root`, dan akses konfigurasi WireGuard. RBAC aplikasi mengurangi paparan endpoint, tetapi tidak menghilangkan dampak kompromi proses web. Menghapus akses tersebut tanpa pengganti kemungkinan merusak fitur terminal, manajemen Docker/LXD, file manager, jaringan, dan layanan host.

**Sebelum PR final:** buat matriks fitur host yang benar-benar dibutuhkan, tentukan model threat, lalu pecah operasi privileged ke helper host dengan API sempit jika memungkinkan. Jika refactor penuh di luar cakupan, PR harus menyatakan risiko ini secara eksplisit dan tidak boleh mengklaim dashboard sudah aman untuk dipaparkan ke internet.

### P1 — Backend duplikat belum diaudit penuh

`Dockerfile` menjalankan `app:app` dari `app.py`. `app_server.py` masih ada sebagai backend duplikat dan belum menerima patch fungsional yang sama. Verifikasi apakah file tersebut masih didukung; jika tidak, dokumentasikan/depresiasikan. Jika didukung, terapkan hardening setara dan tambahkan tes untuk kedua backend.

### P1 — Route duplikat dalam `app.py`

Audit menemukan definisi berulang untuk `/files`, `/terminal`, dan `/api/store/manage`. Walau beberapa decorator telah diperketat, definisi ganda membuat handler pertama dapat membayangi handler berikutnya dan berisiko menyebabkan perilaku UI/API yang membingungkan. Periksa seluruh pemanggil/template dan tetapkan satu handler per route sebelum PR.

### P1 — Setup awal dan endpoint monitoring publik perlu keputusan eksplisit

`/api/setup-admin` harus tetap tersedia untuk setup pertama, tetapi proses pembuatan owner pertama masih bisa dimenangkan oleh klien lain jika dashboard baru dapat diakses bersama sebelum pemilik menyelesaikan wizard. Tambahkan prosedur bootstrap yang aman atau dokumentasikan bahwa setup pertama wajib dilakukan pada jaringan tepercaya sebelum service dipublikasikan.

`/` dan `/api/stats` tetap publik untuk mendukung halaman monitoring/wallboard. Putuskan apakah perilaku publik ini memang diinginkan; bila tidak, tambahkan kebijakan akses/konfigurasi dan uji dampaknya pada halaman monitoring.

### P2 — Validasi runtime dan regresi fungsional belum lengkap

- CI memvalidasi sintaks dan unit/regression tests, tetapi belum menjalankan browser E2E, menjalankan Docker Compose di lingkungan terisolasi, atau menguji operasi nyata pada Armbian/STB.
- File manager owner/admin sengaja masih dapat menjangkau filesystem host. Mount root-host membuat kemampuan itu sangat kuat; UI path validation saja bukan boundary keamanan.
- Installer belum diuji melalui instalasi bersih dan upgrade pada mesin uji. Jangan jalankan pada server produksi sebelum uji tersebut dilakukan.
- UI/responsivitas editor file, clipboard terminal Android, dan bug fungsional yang ditemukan saat penggunaan masih perlu daftar reproduksi dan pengujian terpisah.

## Kriteria sebelum membuat PR upstream

1. Periksa semua temuan di atas dan tentukan blocker yang harus diselesaikan versus keterbatasan yang diterima secara sadar.
2. Pastikan CI hijau pada commit terbaru, bukan sekadar pada commit sebelumnya.
3. Jalankan tes runtime terisolasi untuk autentikasi, file manager, terminal, Docker/LXD, installer, serta pengalaman UI utama.
4. Tulis PR dengan langkah reproduksi bug, dampak, patch, hasil tes, perubahan perilaku, dan risiko residual.
5. Jangan menulis langsung ke upstream. Ajukan Pull Request dari `diena742/web_server:fix/critical-bugs` ke branch utama upstream setelah perubahan siap ditinjau.

Dokumen ini membedakan perbaikan yang sudah ada dari risiko yang belum dituntaskan; jangan menggunakan status “semua bug selesai” sebelum blocker di atas diperiksa dan tes runtime dilakukan.
