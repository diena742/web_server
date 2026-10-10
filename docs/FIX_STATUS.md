# Status Audit, Perbaikan, dan Kesiapan Pull Request

Tanggal pembaruan: 2026-10-10  
Repositori pengembangan: [diena742/web_server](https://github.com/diena742/web_server)  
Branch pengembangan: `fix/critical-bugs`  
Sumber upstream: [recode-project/web_server](https://github.com/recode-project/web_server)

## Ringkasan

Branch pengembangan memiliki patch keamanan dan perbaikan fungsional, serta tes regresi otomatis. CI terakhir yang telah diverifikasi berhasil pada commit `dec10014c9e72a5602c9cf12c2889606e1b631ac`.

**Status: belum siap untuk klaim bahwa semua bug terselesaikan atau untuk menyatakan aman dipaparkan ke internet.** CI memvalidasi sintaks dan unit/regression tests, tetapi belum menggantikan uji runtime Docker, browser E2E, dan pengujian pada target Armbian/STB. Risiko arsitektur container berprivilege luas dan backend duplikat juga masih perlu ditangani atau secara eksplisit dibatasi sebelum PR final.

## Perbaikan yang diterapkan pada branch

### Autentikasi dan otorisasi

- Menghapus penggunaan header `X-Mobile-Key` yang tertanam di source sebagai bypass autentikasi global. Token `MOBILE_ACCESS_TOKEN` hanya berlaku pada endpoint `/api/mobile-backup/*`.
- Ketika autentikasi global dinonaktifkan, sesi monitoring tidak lagi otomatis memperoleh role admin; role fallback menjadi `readonly`.
- Memperketat RBAC pada API jaringan, storage, SMB, VPN/WireGuard, ZeroTier, app store, LXD, Docker overview, website monitor, database monitor, backup, serta aksi administrasi host.
- Endpoint konfigurasi client VPN yang dapat mengembalikan konfigurasi WireGuard hanya dapat diakses admin.
- Halaman Mobile Backup dan API monitoring sensitif dibatasi untuk admin. API mobile backup yang memakai token tetap menerima token hanya dalam ruang lingkup endpoint tersebut.
- Memperbaiki hierarki izin: role `limited` memiliki akses `view` yang sesuai, tetapi tidak mendapatkan hak `full`.
- Endpoint kontrol systemd menolak layanan yang tidak terdaftar dalam allowlist; operator hanya boleh melakukan `restart` pada layanan yang dikonfigurasi. Kegagalan `systemctl` tidak lagi dilaporkan sebagai sukses.
- First-run setup membutuhkan `SETUP_TOKEN`. Hash password baru menggunakan Werkzeug PBKDF2, dengan migrasi saat login sukses untuk hash SHA-256 lama; form/backend memberlakukan password minimum 12 karakter.
- CORS/Socket.IO same-origin secara default, dengan origin allowlist dan pengaturan cookie sesi.

### File manager, terminal, dan operasi host

- Menambahkan pengecekan sesi/role pada event Socket.IO terminal, pemisahan sesi PTY, pengiriman output ke socket pemilik, pembatasan ukuran event input/resize, dan pembersihan terminal saat disconnect.
- File browser read-only dibatasi ke root eksplisit dari `FILES_READONLY_ROOTS`; akses penuh owner/admin tetap sangat kuat karena aplikasi memang memasang filesystem host.
- Operasi Mobile Backup memeriksa batas path kanonis. Rename, move, dan copy menolak konflik tujuan yang sudah ada, serta menolak operasi menyalin/memindahkan direktori ke dalam dirinya sendiri.
- Endpoint daftar Mobile Backup tidak lagi membuat subdirektori sembarang saat GET, dan mengabaikan entry symlink.
- Upload Mobile Backup menolak nama yang tidak valid serta menolak file tujuan yang sudah ada.
- Upload Mobile Backup membuat file tujuan dengan operasi eksklusif atomik; entri symlink yang sudah ada, termasuk dangling symlink, ditolak agar upload tidak mengikuti link ke luar direktori backup.
- Deteksi IP LAN/Tailscale tidak menggunakan alamat contoh yang tertanam di source; alamat dideteksi dari network namespace host atau diberikan melalui environment/config yang tervalidasi.
- Operasi rename/move/copy tidak menimpa tujuan yang sudah ada dan tidak dapat memindahkan/menyalin direktori ke dalam dirinya sendiri.
- Deteksi IP LAN/Tailscale tidak menggunakan alamat contoh yang tertanam di source; alamat dideteksi dari network namespace host atau diberikan melalui environment/config yang tervalidasi.
- Endpoint kontrol service dan pembacaan analisis disk memakai validasi input/allowlist serta argumen subprocess terpisah. Endpoint analisis disk/storage dibatasi untuk admin.
- Endpoint update menggunakan direktori kerja absolut yang tervalidasi, quoting untuk perintah di shell bagian dalam, dan argv luar dengan `shell=False`. Pembacaan model CPU tidak lagi memanggil shell.
- Endpoint `/api/network-details` dibatasi untuk admin.

### Backup, restore, dan website monitor

- Pembuatan backup memakai lokasi canonical `APP_SETTINGS_FILE` dan `SECURITY_CONFIG_FILE`, bukan nama/lokasi lama.
- Restore hanya memproses file regular yang namanya masuk allowlist, menulis ke lokasi canonical lewat file sementara dan penggantian atomik, dan tidak mengekstrak entri symlink/hardlink.
- Download arsip backup dibatasi untuk admin.
- Unduh/restore/hapus arsip hanya menerima ID nama file `.tar.gz` sederhana di dalam direktori backup; symlink arsip dan path yang keluar dari direktori ditolak. Daftar backup mengabaikan symlink dan file khusus.
- Restore menolak body JSON yang bukan objek dan hanya memproses file regular dalam allowlist.
- Domain website dinormalisasi dan divalidasi sebagai hostname sebelum disimpan.
- ZIP backup website dibatasi agar tetap di bawah web root, melewati symlink, menggunakan nama file sementara unik, dan menghapus arsip sementara sesudah respons ditutup.
- API web monitor yang membaca log/keadaan host dibatasi untuk admin.

### Installer dan UI

- Installer pada branch ini telah diubah agar tidak secara otomatis membunuh proses host di port 80, menghapus paksa container, mengalihkan port CasaOS, atau menghapus konfigurasi keamanan sebagaimana perilaku awalnya.
- Port dashboard dapat ditetapkan lewat `DASHBOARD_PORT`; secret seharusnya ditempatkan dalam `.env` yang tidak di-commit.
- Perubahan UI terdahulu menambahkan perilaku long-press touch pada file manager, perbaikan lifecycle ResizeObserver tab terminal, serta fallback clipboard Android. Sintaks JavaScript divalidasi oleh CI, tetapi interaksi browser sebenarnya belum diuji melalui E2E pada perangkat.

## Validasi otomatis

Workflow: [Source Validation](https://github.com/diena742/web_server/actions/runs/38049077495)

Hasil commit `8992f668ff03e41a452ef83a19167631b7e281bb`:

- Kompilasi sumber Python: sukses.
- Instalasi dependensi: sukses.
- Unit/regression tests: **48 tes lulus**.
- Validasi sintaks `static/script.js` dan `static/files.js`: sukses.
- Validasi sintaks `install.sh` dan `setup_wg.sh`: sukses.

CI ini tidak menjalankan install/upgrade Docker Compose secara nyata, browser end-to-end, atau uji perangkat STB. Hasil CI hijau adalah bukti untuk tes yang dijalankan—bukan bukti bahwa seluruh fungsi aplikasi bebas bug.

## Risiko dan blocker yang belum terselesaikan

### P0 — Container memiliki akses host yang sangat luas

`docker-compose.yml` masih menggunakan `privileged: true`, `pid: host`, Docker socket host, D-Bus system bus socket, bind mount root host ke `/host/root`, serta mount konfigurasi WireGuard. Bila proses web berhasil dikompromikan, RBAC aplikasi tidak mencegah dampak luas dari akses ini.

**Sebelum merekomendasikan deployment terbuka ke internet:** buat matriks fitur yang benar-benar membutuhkan akses host, lakukan threat modeling, dan evaluasi helper host dengan API terbatas / least privilege. Menghapus semua mount/privilege tanpa desain pengganti berpotensi merusak terminal, file manager, Docker/LXD, jaringan, dan pengelolaan layanan. Sampai masalah ini diselesaikan, jangan mengklaim aplikasi aman untuk dipaparkan ke internet.

### P1 — Backend duplikat belum diselaraskan

Dockerfile saat ini menjalankan `app:app` dari `app.py`. `app_server.py` masih merupakan backend duplikat yang belum menerima hardening fungsional yang sama. Konfirmasikan apakah file itu masih didukung. Jika masih dipakai, terapkan patch sepadan dan tes terhadap kedua entry point; jika tidak, dokumentasikan status/depresiasinya sebelum PR final.

### P2 — Pengujian runtime dan daftar bug fungsional

- Jalankan instalasi bersih dan upgrade pada mesin uji terisolasi, bukan server produksi.
- Jalankan browser E2E untuk login/setup, editor file, upload/download/rename/copy/paste, terminal multi-tab dan clipboard Android, file manager touch, backup/restore, serta Docker/LXD/layanan host.
- Uji pada lingkungan target yang benar-benar akan dipakai, termasuk Armbian/STB. Belum ada bukti dari CI saat ini bahwa seluruh operasi host berhasil pada perangkat tersebut.
- Review ulang API publik `/` dan `/api/stats`; keduanya masih publik untuk kebutuhan monitoring/wallboard. Pastikan ini merupakan keputusan yang disengaja.
- Tinjau kembali visibility tombol di UI berdasarkan role. Walau backend menolak permintaan yang tidak berizin, tombol operasi yang masih tampil bagi role read-only dapat membingungkan pengguna.
- Periksa konfigurasi upload dengan race/symlink test dan uji error handling pada file system read-only/penuh.
- Branch saat ini mempunyai 83 commit di atas branch `main` fork, sehingga riwayat pengembangan cukup panjang. Sebelum PR upstream, tinjau daftar file/diff lengkap dan pertimbangkan squash pada sisi PR agar review lebih terarah.

## Gerbang sebelum Pull Request upstream

1. Tuntaskan atau dokumentasikan dengan jelas blocker residual di atas.
2. Pastikan Actions hijau untuk commit terbaru setelah setiap patch baru.
3. Jalankan tes runtime/E2E terisolasi dan regresi perangkat yang relevan.
4. Isi PR dengan langkah reproduksi setiap bug, dampak, file yang diperbaiki, hasil tes, perubahan perilaku, dan risiko yang belum ditangani.
5. Ajukan PR dari `diena742/web_server:fix/critical-bugs` ke branch utama upstream. Jangan melakukan push langsung ke upstream; maintainer yang memutuskan apakah perubahan diterima/digabungkan.

Dokumen ini sengaja membedakan perbaikan yang telah diterapkan dari risiko yang masih ada. Jangan menyatakan “semua bug selesai” hanya berdasarkan hasil CI hijau.
