# GitHub sync plan — outcome recorded 19 Nov 2026

Tanggal verifikasi awal: 19 Nov 2026, ~18:47 WIB.
Status awal: DOKUMEN PERSIAPAN SAJA. Belum ada push, merge, atau release.
Push butuh persetujuan eksplisit user.

## Outcome (19 Nov 2026, ~20:45 WIB)

Push **berhasil** dari terminal laptop user (bukan lewat connector):
`git fetch origin` dulu (lease lama dari bundle bikin stale info),
lalu `git push --force-with-lease origin rea-standard:main`.
Remote `main` berubah `7d1efbeb` → `3731a3a`, dan CI GitHub pertama
hijau di commit itu (kedua job: `test` dan `no-db`).

Keadaan sekarang: remote `main` adalah `3731a3a` (19 Nov 2026).
Branch `rea-standard` lokal sudah lebih baru (HEAD `3568bb4`,
website/demo, korpus 500, MCP, skills, showcases) dan belum ada
di `main` remote. Push berikutnya memakai cara yang sama (bundle
atau push langsung dari laptop) setelah review tiap tugas selesai.

## Status lokal vs remote (terverifikasi dengan `git ls-remote` + `git fetch`)

- Remote: `https://github.com/rfypych/eunoia.git`
- Remote `main`: `7d1efbeb` ("Add seed_sources.py + setup_dev_db.sh;
  real-corpus golden set + recall@10 0.90", 19 Nov 2026 15:39 WIB).
- Lokal `main`: `1c45598` (31 commit).
- Lokal `rea-standard`: `3f9ba30` (1 commit di atas `main`).
- Remote TIDAK punya branch `rea-standard`.

## History: lokal lengkap, remote snapshot (jangan disembunyikan)

- Lokal `main` punya history lengkap 31 commit (MVP 16 tugas + fix wave
  + deploy fix + golden set).
- Remote `main` punya 6 commit yang TIDAK punya ancestor yang sama
  dengan lokal (`git merge-base main origin/main` kosong, exit 1):
  `2509913` (Initial commit, README kosong) + `fe723e4` (snapshot MVP)
  + 4 commit snapshot oleh `0xrphy` (`1e544f7`, `92096b5`, `3019bd6`,
  `7d1efbeb`).
- Isi file remote dan lokal SAMA, kecuali bit executable:
  `git diff main origin/main` hanya menunjukkan mode `100755` -> `100644`
  pada `scripts/setup_dev_db.sh` dan `scripts/setup_test_db.sh`
  (blob sama). Per pasang commit snapshot vs lokal juga sama kecuali
  bit itu (`fe723e4` vs `ee33ed5`, `3019bd6` vs `5fa7df4`, dst).
- Artinya: tidak ada konten yang hilang bila history remote diganti
  dengan history lokal; yang hilang hanya 6 commit snapshot itu
  sendiri (diganti 31 commit lokal yang isinya sama, lebih rinci).

## Rencana push (2 langkah, berurutan)

### Langkah 1 — Push branch `rea-standard` (AMAN, tanpa force, tanpa ubah main)

Perintah (dijalankan dari `~/workspace/eunoia`, branch `rea-standard`):

```bash
git push origin rea-standard
```

- Ini push biasa, branch baru di remote. Tidak mengubah `main` remote,
  tidak menimpa apa pun.
- CI (`.github/workflows/ci.yml`, trigger `push` ke `main` dan
  `rea-standard`, plus `pull_request`) akan jalan di branch ini:
  job `test` (full suite via `setup_dev.sh` + Docker Postgres/pgvector)
  dan job `no-db`.
- Verifikasi setelah push: `git ls-remote origin rea-standard` harus
  sama dengan `3f9ba30` (atau HEAD `rea-standard` saat itu), dan
  kedua job CI hijau di tab Actions repo.
- Kalau CI gagal di push pertama ini, tugas setup dev dibuka lagi
  (bukan sync ini yang disalahkan).

### Langkah 2 — Samakan `main` remote dengan `main` lokal (BUTUH KEPUTUSAN USER)

Masalah: `git push origin main` biasa akan DITOLAK
(non-fast-forward, history tidak berhubungan). Satu-satunya cara
agar sync ini terpenuhi ("remote head sama dengan HEAD lokal")
adalah force-push:

```bash
git push --force-with-lease origin main
```

- Efek: remote `main` menjadi `1c45598` (31 commit lokal). 6 commit
  snapshot remote diganti; isinya sudah terbukti sama (lihat atas).
- Risiko: siapa pun yang sudah clone remote `main` harus clone ulang
  / reset. Repo ini milik user sendiri, tidak ada kontributor lain
  yang tercatat; tetap harus diputuskan user, bukan ditebak.
- Alternatif yang DITOLAK: lanjut pola snapshot (commit baru di atas
  `7d1efbeb`). Itu menjaga history remote, tapi sync ini
  ("remote head = HEAD lokal") tidak akan pernah terpenuhi dan
  history lokal lengkap tetap tidak naik ke GitHub.
- Setelah langkah 2, `rea-standard` menjadi branch normal turunan
  `main` (merge-base `1c45598`), sehingga PR `rea-standard` -> `main`
  bisa di-merge normal. Tanpa langkah 2, PR itu tidak bisa di-merge
  bersih karena history tidak berhubungan.
- Urutan yang disarankan: langkah 1 dulu, tunggu CI hijau,
  baru langkah 2 (force-push `main`), lalu buka PR / merge
  `rea-standard` ke `main`.

## Verifikasi akhir (setelah kedua langkah disetujui dan dijalankan)

```bash
git ls-remote origin
# main harus 3731a3a (19 Nov 2026, setelah push dari laptop user)
git log --oneline origin/main..main       # harus kosong, setelah main lokal disamakan
```

## Keputusan yang butuh user (jangan ditebak)

1. **Setuju force-push `main` (langkah 2)?** Ya / tidak. Kalau tidak,
   berhenti di langkah 1 dan sync ini ditulis belum terpenuhi
   dengan alasan ini.
2. **Kapan push?** Langkah 1 bisa jalan begitu user bilang gas;
   langkah 2 setelah CI hijau di langkah 1 (atau bersamaan, bila
   user memutuskan begitu).
3. **Merge `rea-standard` ke `main` setelah CI hijau?** Via PR di
   GitHub atau merge lokal + push. Bukan bagian dari push itu sendiri.
