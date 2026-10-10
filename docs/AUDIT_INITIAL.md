# Audit Awal — Eka Dashboard

Tanggal audit: 2026-10-10  
Fork kerja: [diena742/web_server](https://github.com/diena742/web_server)  
Branch: `fix/critical-bugs`  
Sumber: [recode-project/web_server](https://github.com/recode-project/web_server)

> Dokumen ini mencatat temuan awal dari inspeksi source statis, belum merupakan audit runtime. Severity adalah penilaian awal dan perlu dikonfirmasi melalui pengujian terisolasi. Jangan jalankan `install.sh` pada host produksi selama audit.

## Status awal repositori

- Fork diverifikasi berasal dari repositori sumber.
- Branch `fix/critical-bugs` dibuat dari `main`.
- Pada saat mulai, `main` dan `fix/critical-bugs` identik (0 commit di depan; 0 file berubah).
- Ada dua backend besar (`app.py` dan `app_server.py`) yang memiliki banyak kode serupa tetapi beberapa perilaku berbeda. Harus dipastikan mana entrypoint produksi sebelum memperbaiki kedua file.

## Temuan awal

### AUD-001 — Header rahasia hard-coded melewati autentikasi
**Severity: Kritis (perlu verifikasi konteks pemakaian).**  
File: `app.py`, fungsi `login_required`.

Decorator memercayai nilai header `X-Mobile-Key: EkaBackupSync_2024_Secret` dan mengembalikan akses tanpa memverifikasi sesi atau role. Nilai rahasia statis disimpan langsung dalam source. Jika endpoint sensitif menggunakan decorator ini, siapa pun yang mengetahui/menemukan nilai tersebut berpotensi melewati login.

**Perbaikan yang disarankan:** hapus bypass hard-coded; gunakan autentikasi token per perangkat yang dapat dicabut, disimpan sebagai secret konfigurasi/ENV, dibandingkan secara aman, diberi cakupan endpoint dan role, serta diuji terhadap semua route sensitif.

### AUD-002 — Handler Socket.IO terminal tidak memeriksa autentikasi/otorisasi sendiri
**Severity: Kritis (bergantung konfigurasi server/socket).**  
File: `app.py` dan `app_server.py`: `start_terminal`, `terminal_input`, `terminal_resize`, `stop_terminal`.

Event membuat PTY dan menjalankan `nsenter ... bash` terhadap namespace host. Handler yang ditinjau tidak melakukan pemeriksaan `session`, role, atau kepemilikan session ID sebelum membuat/mengirim input ke terminal. Pembatasan route `/terminal` saja tidak cukup untuk mengamankan event Socket.IO jika endpoint/event dapat dipanggil langsung.

**Perbaikan yang disarankan:** autentikasi saat koneksi Socket.IO; tolak event sebelum terautentikasi; verifikasi role terminal pada setiap event; ikat terminal ke ID user/socket; cegah pemakaian ID terminal milik pengguna lain; bersihkan PTY ketika disconnect; uji event tanpa cookie dan lintas pengguna.

### AUD-003 — API file content tidak memiliki decorator autentikasi
**Severity: Kritis/Tinggi.**  
File: `app.py` dan `app_server.py`, route `/api/files/content` (GET dan POST).

Route membaca dan menulis path yang diberikan klien langsung dengan `open(path, ...)`, tanpa decorator `login_required` atau `requires_permission`. Pada container yang memiliki akses file host luas, ini berpotensi menjadi pembacaan/penulisan arbitrary file.

**Perbaikan yang disarankan:** wajibkan autentikasi dan izin file; validasi serta normalisasi path; gunakan allowlist/root path yang eksplisit; tolak traversal, symlink escape, path sensitif, dan operasi di luar root yang diizinkan.

### AUD-004 — Download file tidak menerapkan izin file secara eksplisit
**Severity: Tinggi.**  
File: `app.py` dan `app_server.py`, route `/api/files/download`.

Endpoint memakai `login_required`, tetapi menerima path arbitrary dan mengirim file apa pun yang dapat dibaca proses. Role/operator/read-only juga tampaknya tidak diverifikasi pada endpoint tersebut.

**Perbaikan yang disarankan:** tambahkan `requires_permission('files', 'read')`, pembatasan root/path, dan pemeriksaan file regular/symlink sebelum `send_file`.

### AUD-005 — Operasi file memiliki kemampuan destructive dengan validasi path minim
**Severity: Tinggi.**  
File: `app.py` dan `app_server.py`, route `/api/files/action`.

Route menerima path dan action yang dikirim klien; action `delete` memanggil `shutil.rmtree` atau `os.remove`, sementara rename/copy/move juga memakai path tersebut langsung. Route didekorasi dengan izin fitur, tetapi path berada di bawah akses host luas dan tidak terlihat validasi boundary root pada potongan yang diperiksa.

**Perbaikan yang disarankan:** implementasikan path policy terpusat; tolak root filesystem, direktori penting, symlink escape, operasi sumber/tujuan di luar ruang lingkup, serta gunakan konfirmasi untuk operasi rekursif.

### AUD-006 — Endpoint monitoring dan Docker tidak konsisten dilindungi
**Severity: Tinggi.**  
File: `app.py` (juga pola serupa di `app_server.py`).

Route seperti `/api/stats`, `/api/docker/containers`, dan `/api/docker/<container_id>/stats` tidak terlihat memiliki decorator auth pada definisi yang ditinjau. Selain mengungkap metadata host/container, endpoint Docker membuka akses data tanpa mengikuti RBAC halaman dashboard.

**Perbaikan yang disarankan:** tetapkan matriks route-permission dan lindungi semua endpoint sensitif secara konsisten; tes unauthenticated/role matrix secara otomatis.

### AUD-007 — Endpoint LXD hanya menggunakan login, belum role admin
**Severity: Tinggi.**  
File: `app.py`, route `/api/lxd/action`, `/api/lxd/create`, `/api/lxd/config`.

Operasi start/stop/restart/delete/create dan konfigurasi container memanggil `nsenter` ke host dengan hanya `login_required` terlihat pada route. Role operator/read-only berpotensi menjalankan perubahan sistem jika dapat mengakses endpoint.

**Perbaikan yang disarankan:** gunakan `admin_required` atau permission capability khusus; validasi nama/image/resource-limit, periksa exit code untuk tiap tindakan, dan tambahkan audit log.

### AUD-008 — Container mendapat akses host yang sangat luas
**Severity: Kritis (arsitektur/deployment).**  
File: `docker-compose.yml`.

Compose menggunakan `privileged: true`, `pid: host`, Docker socket host, D-Bus system bus socket, mount `/` menjadi `/host/root`, serta konfigurasi host WireGuard. Ini memberi dashboard kemampuan administratif hampir setara host. Bila aplikasi web dieksploitasi, dampak bisa mencakup kompromi host penuh.

**Perbaikan yang disarankan:** evaluasi apakah seluruh kemampuan dibutuhkan; pisahkan privileged host-helper dengan API sempit; hapus `privileged`, host PID, Docker socket dan mount root bila tidak mutlak diperlukan. Jika fitur memerlukan akses sistem, dokumentasikan threat model dan batasi akses dengan jaringan tepercaya, autentikasi kuat, serta privilege minimum yang realistis.

### AUD-009 — Installer dapat mengganggu layanan host dan menghapus konfigurasi keamanan
**Severity: Tinggi (operasional).**  
File: `install.sh`.

Installer otomatis dapat mengubah port CasaOS 80 menjadi 9999, menghentikan/menonaktifkan web server di port 80, mengirim `kill -9` ke proses yang memakai port tersebut, menghapus container `eka_dashboard`, menjalankan `compose down`, dan menghapus `data/security_config.json`. Ini berpotensi memutus layanan yang ada dan mereset konfigurasi keamanan tanpa backup pemulihan yang memadai.

**Perbaikan yang disarankan:** mode dry-run, konfirmasi eksplisit setiap perubahan host, jangan matikan proses tak dikenal, jangan hapus konfigurasi keamanan saat update normal, backup terverifikasi sebelum perubahan, dan rollback otomatis.

### AUD-010 — Debug server aktif pada entrypoint manual
**Severity: Tinggi jika dipakai di jaringan/produksi; konteks terbatas.**  
File: `app.py` dan `app_server.py`.

Blok `__main__` menjalankan Socket.IO dengan `debug=True` dan host `0.0.0.0`. Dockerfile memakai Gunicorn, jadi dampaknya tergantung bagaimana aplikasi diluncurkan; tetap berbahaya jika dijalankan langsung.

**Perbaikan yang disarankan:** debug nonaktif secara default dan hanya dapat diaktifkan pada lingkungan development secara eksplisit.

### AUD-011 — Password menggunakan SHA-256 tanpa password hashing khusus
**Severity: Tinggi.**  
File: `app.py` dan `app_server.py`, `load_security_config`/login.

Password utama dan user tambahan dibandingkan dengan SHA-256 biasa. Hash cepat ini tidak dirancang untuk penyimpanan password dan kurang tahan terhadap brute-force offline jika konfigurasi bocor.

**Perbaikan yang disarankan:** migrasikan ke Argon2id/scrypt/PBKDF2 melalui Werkzeug; lakukan migrasi kompatibel saat login sukses, lalu hapus dukungan hash lama setelah transisi.

## Prioritas fase patch

1. P0: audit dan tutup bypass autentikasi; amankan API file dan event Socket.IO terminal; proteksi semua route sensitif.
2. P1: terapkan RBAC server-side yang konsisten dan validasi path/aksi destructive.
3. P1: perbaiki installer agar aman dan mempunyai backup/rollback.
4. P2: hardening deployment Docker serta penanganan password/session.
5. P3: audit bug fungsional/UI/responsivitas, clipboard dan editor file; tambah pengujian regresi.

## Catatan validasi

- Temuan ini berasal dari inspeksi source statis terhadap branch fork saat audit awal.
- Belum ada runtime integration test; beberapa temuan perlu dikonfirmasi terhadap route registry, konfigurasi deployment, dan jalur aplikasi yang benar-benar dipakai.
- `app.py` dan `app_server.py` berbeda. Jangan menambal keduanya secara membabi buta; tentukan entrypoint produksi dan buat tes memastikan kedua backend tidak mengalami regression.
