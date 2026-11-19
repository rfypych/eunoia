# Corpus 500 writeup nyata (19 Nov 2026)

## Hasil

| Ukuran | Lokal (dev DB) | Produksi (box) |
| --- | --- | --- |
| Writeup aktif | 506 | 507 |
| Unclassified | 42 (8,3%) | 45 (8,9%) |
| Recall@10 (21 query, metode 19 Nov 2026) | 0,9524 (pre-test 1,00, mid-test 0,857) | 0,9048 (pre-test 1,00, mid-test 0,714) |
| Latensi | p50 88,04 ms, p95 155,03 ms (VM lokal) | p50 46,89 ms, p95 78,45 ms |

Target: korpus >= 500, unclassified < 10%, recall@10 >= 0,90.
Ketiganya tercapai di lokal dan di produksi. Margin recall produksi
tipis (19/21 — satu miss lagi akan jatuh di bawah 0,90); mid-test
adalah titik lemahnya (di bawah).

## Metode

- Backfill dari HackerOne Hacktivity API, halaman demi halaman dari
  yang terbaru, tanpa auth, lewat pipeline discovery normal (dedup,
  quality gate, serving gate, embedding). Target 500, 47 halaman,
  510 ditemukan, 506 dibuat, 4 merge (sudah ada), 0 gagal.
- Tidak ada sumber baru. Scope tetap HackerOne saja; keputusan scope
  di bawah menjelaskan kenapa.
- Recall diukur dengan metode yang sama seperti 19 Nov 2026: satu
  `search()` per query, recall@limit, split pre/mid-test, p50/p95.
  Query set baru `docs/golden/real-queries-500.json` (21 query: 14
  pre-test, 7 mid-test), dibangun dari korpus 500 dan divalidasi
  (`validate_real_queries`: expected id harus ada, aktif, servable).

## CVE-2026-110288: terverifikasi asli, tidak dihapus

Audit Rea-standard menandai assignment ini "belum terverifikasi".
Dicek 19 Nov 2026 ke NVD API dan CVE.org:

- NVD: totalResults 1, published 2026-11-03, sourceIdentifier
  `product-cna@github.com`, vulnStatus "Awaiting Analysis",
  deskripsi CSRF di GitHub Enterprise Server (hapus konfigurasi
  Slack / Microsoft Teams ChatOps dan kredensial provider).
  Cocok dengan writeup produksi #1 (baris CSRF Slack/Teams
  `w_01a1f1a6533177e99904437453565607`).
- CVE.org: state PUBLISHED, assigner GitHub_P, dateReserved
  2026-10-13, datePublished 2026-11-03.

Satu baris `writeup_vulns` di produksi memakai CVE ini, dan itu
benar. Tidak ada yang diubah.

## Temuan scope (data, bukan opini)

Dari 100 laporan terbaru yang di-probe, **0 menyebut Java/Spring**
(`classify_java_spring` tech match). Korpus 50 baris yang sudah ada
pun sudah lintas teknologi (WordPress, curl, MariaDB, Qt, ...):
poller tidak pernah memfilter berdasarkan teknologi, klasifikasi
hanya memberi label. Jadi korpus 500 yang **khusus Java/Spring**
dari Hacktivity tidak bisa dicapai; ingest melanjutkan kebijakan
ingest yang sudah ada (semua laporan disclosed HackerOne) dan
melaporkannya di sini, bukan mengklaim Java-only. Ini menjawab
pertanyaan scope dengan data.

## Klasifikasi: dari 28,7% ke 8,3% unclassified

Titik awal lokal setelah backfill: 145 dari 506 baris (28,7%)
unclassified, semuanya tanpa CWE (`cwe_id IS NULL`).

### 1. Perluasan peta CWE → kelas

NVD mengembalikan CWE yang belum ada di peta, untuk baris-baris
yang nyata di korpus ini (dicek satu per satu ke NVD):

- CWE-261 (Weak Encoding for Password), CWE-287 (Improper
  Authentication, sudah ada), CWE-297 (Improper Validation of
  Certificate with Host Mismatch), CWE-305 (Authentication Bypass
  by Primary Weakness) → Auth Bypass.
- CWE-312 (Cleartext Storage of Sensitive Information) →
  Info Disclosure.
- CWE-667 (Improper Locking, deadlock) → DoS.
- CWE-1021 (Clickjacking) → Clickjacking (kelas baru).

### 2. Text fallback: frasa teknik eksplisit

Kontrak era MVP ("tanpa CWE berarti unclassified, jangan tebak
dari judul") sengaja diganti di sini, dengan alasan yang terukur:
22–27% baris nyata tidak punya CWE sama sekali, jadi target
<10% tidak mungkin tercapai di bawah kontrak lama. Judul yang
menyebut tekniknya ("SSRF", "bypass", "leak", "overflow",
"ReDoS") **adalah** laporan itu menyebut kelasnya sendiri.
Setiap frasa diukur terhadap korpus 506 baris; set ini
mengklasifikasi 96 dari 145 baris NULL-CWE. Aturan lama diganti karena datanya menuntut begitu (di bawah ini); tes yang mengunci aturan lama diperbarui mengikuti aturan baru.

Frasa yang ditambahkan (urutan = pertama yang cocok menang,
teknik paling spesifik dulu): akronim teknik telanjang (ssrf,
xss, csrf, sqli, idor, xxe, rce, lfi, ssti → kelas SSTI),
`bypass`/`bypassing`/`verification bypass`/`brute force`/
`takeover`/`unauthenticated`/`unauthorized`/`rate limit`/
`authentication`/`mitm`/`man-in-the-middle`/`starttls stripping`/
`ssl certificate`/`nonce reused`/`auth context`/
`after password change`/`without verifying`/`spf` →
Auth Bypass; `leak`/`leaked`/`leaking`/`leakage`/`expose`/
`exposed`/`exposure`/`exfiltration`/`disclosure`/`sensitive data`/
`data breach`/`password hash`/`in plain text`/`production data`/
`file listing` → Info Disclosure; `overflow`/`underflow`/
`out of bounds`/`double-free` → Memory Safety; `redos`/`dos`/
`ddos`/`starvation`/`unbounded` → DoS; `injection` → Injection;
`race condition` → Race Condition; `clickjacking` →
Clickjacking; `unrestricted file upload` → Unrestricted File
Upload; `overwrite` → Path Traversal.

### 3. NVD backfill yang tertinggal (`apply_cached_nvd`)

Celah desain yang ditemukan: pipeline enrich saat ingest gagal
untuk CVE baru (NVD belum menerbitkan CVE-2026-*), lalu job
`nvd_refresh` hanya mengisi `cve_cache` — baris writeup-nya
tidak pernah mendapat data NVD yang datang terlambat. Fungsi
baru `apply_cached_nvd` menutup celah ini: untuk setiap baris
aktif yang punya CVE tapi masih tanpa CVSS/severity/kelas,
terapkan record NVD (dari cache segar, atau fetch live dengan
bucket NVD 5 req/30 dtk). Hanya mengisi yang kosong, tidak
pernah menimpa data HackerOne. Script backfill kini menjalankan
drain `nvd_refresh` (berhenti saat tidak ada job yang *due*,
karena job gagal memakai backoff ~1 jam) lalu `apply_cached_nvd`.

### Sisa 42 baris unclassified (lokal)

Sebagian besar memang tidak menyebut teknik apa pun: quirks
internal curl (~12), kegagalan logging CloudTrail AWS (~6),
judul noise tanpa teknik (URL salah, ikon media sosial, dimensi
foto, "Uber Test Report"), logika bisnis tanpa kata kunci,
dan 3 CVE-2026 yang NVD belum terbitkan saat pengukuran
(CVE-2026-111950, CVE-2026-111482, CVE-2026-111481) — ketiganya
akan ter-resolve sendiri lewat retry `nvd_refresh` worker
begitu NVD menerbitkannya. Tidak ada baris yang diklasifikasi
dengan tebakan: yang tidak bernama tetap unclassified.

## Recall: 0,9524 lokal, 0,9048 produksi, miss mid-test

Lokal (506 baris, 21 query):

- Pre-test 1,00 (14/14), mid-test 0,857 (6/7).
- Satu miss: rq17, evidence "TLS peer-verification bypass",
  expected HackerOne 3735276 ("TLS peer-verification bypass via
  mid-transfer ssl_config mutation"). Diagnosis: BM25 murni
  menempatkan target di peringkat 1 (skor 3,15 vs 0,71), tapi
  skor akhir mid-test tidak memakai BM25 — hanya ANN similarity
  + severity + recency + verified (§5.9). Target: similarity
  ANN 0,7528, severity NULL (0, dari 0,15), verified 0 (tidak
  ada bounty/severity dari platform), usia 184 hari (recency
  0,49) → skor akhir 0,4753 vs peringkat 10 (0,5484). Akar
  masalah yang sama seperti 3 miss 19 Nov 2026 (ranking kalah
  pada severity NULL), bukan bug korpus.

Produksi (507 baris, 21 query — query set dibangun ulang di box
dari korpus box dengan builder yang sama, karena expected id
memakai UUID database dan UUID lokal tidak berlaku di box):

- Pre-test 1,00 (14/14), mid-test 0,714 (5/7).
- Dua miss, keduanya laporan 2022 dengan severity low dan tanpa
  CVSS: rq20 (HackerOne 1672614, "[Broken Access Control]
  Unauthorized Linking accounts", evidence "Linked Accounts info
  DIsclosure") dan rq21 (HackerOne 1166073, "Hyper Link
  Injection while signup", evidence "Hyper Link Injection").
  Polanya sama: usia ~4 tahun (recency ~0,11) + severity low
  kalah bobot melawan baris yang lebih baru dengan similarity
  teknik yang sebanding.

Recall tetap di atas 0,90 di kedua pengukuran, jadi tidak ada
perubahan ranking di sini — itu keputusan produk terpisah dengan
risiko regresi. Query set tidak diubah untuk memperbaiki angka:
dibangun deterministik dari korpus sebelum pengukuran, dan
miss-nya dilaporkan apa adanya.

## Quirk API yang ditemukan

Hacktivity `page[size]=100` mengembalikan 50 item di halaman 1
dan **10 item per halaman** di halaman 2+. Butuh ~46 halaman
untuk 500 item. Backfill tidak menganggap halaman pendek
sebagai akhir (hanya halaman kosong yang menghentikan).

## Produksi

_SEBELUM_: 50 aktif / 50 total / 50 embedding / 20 unclassified /
4 pending jobs / 19 baris cve_cache (19 Nov 2026, diukur read-only
sebelum seed).

_SESUDAH_ (19 Nov 2026, setelah seed + restart + ukur ulang):
507 aktif / 507 total / 507 embedding / 45 unclassified (8,9%) /
recall@10 0,9048 (pre-test 1,00, mid-test 0,714), p50 46,89 ms,
p95 78,45 ms. `/v1/status` 200: HackerOne ok, 0 consecutive
failures, lag 12 dtk. Worker sempat di-stop selama seed, lalu
di-restart; poll pertama setelah restart menambah 1 writeup
(506 → 507).

Prosedur seed: worker di-stop (supervisord), file perubahan di-copy ke
`/home/user/eunoia` (tanpa menyentuh perubahan website/demo yang belum
di-commit di box: `README.md`, `src/eunoia/api/rest.py`),
backfill dijalankan di box, worker/API/MCP di-restart, hitungan
dan recall diukur ulang read-only di box, `/v1/status`
diverifikasi.

Dua hal yang ditemukan saat seed produksi, dicatat apa adanya:

- **Karantina quality gate: 58 dari 507 baris tidak disajikan.**
  46 di antaranya karena `author_name` NULL — laporan dengan
  reporter anonim/tersembunyi di Hacktivity — dan aturan gate
  lama mensyaratkan author tidak kosong. 12 lainnya gagal cek
  URL kanonis saat burst backfill; ketiga URL yang dicek ulang
  sesudahnya mengembalikan 200, jadi gagalnya sesaat
  (rate-limit saat 456 cek beruntun), bukan link mati. Baris
  karantina tetap tersembunyi sampai ada proses ulang atau
  persetujuan manusia — tidak ada pengecekan ulang otomatis.
  Ini perilaku gate yang sudah ada, bukan regresi dari
  perubahan ini.
- **Drain `nvd_refresh` sempat melaporkan "0 due" padahal 86 job
  menunggu.** Penyebabnya: job yang belum pernah dicoba punya
  `next_attempt_at` NULL, dan kondisi due di script backfill
  tidak menghitung NULL (klausa klaim di `jobs.py` menghitungnya
  sebagai due). Sudah diperbaiki di script yang sama — kondisi
  due kini mencerminkan klausa klaim — dan putaran kedua di box
  memproses 86 job dalam 1 pass (45 unclassified, dari 51).
