# RSA-OAEP Implementation w/o Crypto Lib

## Justification
Projek ini adalah implementasi algoritma kriptografi RSA dengan padding OAEP (Optimal Asymmetric Encryption Padding) yang dibangun tanpa menggunakan library kriptografi standar. Alasan utama pengembangan ini adalah:

1. **Pemahaman Mendalam**: Mengimplementasikan algoritma kriptografi dari awal memungkinkan kita untuk memahami setiap langkah dalam proses enkripsi dan dekripsi RSA-OAEP.

2. **Kontrol Penuh**: Dengan implementasi manual, kita memiliki kontrol penuh atas algoritma, memungkinkan modifikasi dan penyesuaian sesuai kebutuhan.

3. **Nilai Edukasi**: Projek ini berfungsi sebagai alat pembelajaran untuk memahami konsep kriptografi asimetris dan teknik padding yang aman.

4. **Transparansi**: Setiap langkah algoritma dapat diperiksa dan diuji, memberikan transparansi penuh tentang cara kerja sistem.

5. **Penggunaan OAEP**: Padding OAEP memberikan keamanan tambahan dibandingkan dengan implementasi RSA sederhana, melindungi dari berbagai serangan seperti serangan Bleichenbacher.

## User Manual

### 1. Operating GUI

### 2. Project Structure

**SESUAIN LAGI**
Projek ini terdiri dari beberapa file penting:

- `rsa.py`: Berisi implementasi inti algoritma RSA dan OAEP
- `key_pair_generation.py`: Program CLI untuk menghasilkan kunci
- `keygen_cli.py`: Alternatif CLI untuk menghasilkan kunci
- `keygen_gui.py`: Antarmuka grafis untuk menghasilkan kunci
- `gui.py`: Antarmuka grafis untuk enkripsi pesan
- `encrypt_file.py`: Program CLI untuk enkripsi file
- `decrypt_file.py`: Program CLI untuk dekripsi file

### 3. Technical Notes

- Implementasi menggunakan kunci RSA 2048-bit
- Padding OAEP diterapkan menggunakan fungsi hash SHA-256
- Format kunci disimpan dalam representasi hexadecimal dengan format `e:n` atau `d:n`
- Implementasi primality testing menggunakan algoritma Miller-Rabin
- Proses pembuatan kunci bisa memakan waktu beberapa saat karena harus mencari bilangan prima besar

### 5. Security

- Simpan kunci privat dengan aman dan jangan bagikan kepada pihak lain
- Untuk komunikasi yang aman, hanya bagikan kunci publik kepada pihak yang ingin mengirimkan file terenkripsi
- Implementasi ini untuk tujuan edukasi, untuk penggunaan produksi disarankan menggunakan library kriptografi yang sudah teruji dan diaudit

### 6. Constraints

- Ukuran file yang dapat dienkripsi dibatasi oleh ukuran kunci RSA
- GUI enkripsi saat ini mendukung **APA, APA, APA**

## System Requirements

- Python 3.6 atau lebih baru
- Tkinter untuk antarmuka grafis
- Tidak memerlukan library kriptografi eksternal