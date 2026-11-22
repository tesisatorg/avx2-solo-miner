# avx2-solo-miner

[English](README.md) | **Türkçe**

Hobi amaçlı, **eğitim odaklı** bir solo Bitcoin madencisi: PHP (Stratum v1 istemcisi ve işçi yönetimi) + C (çok motorlu SHA-256d tarayıcı: AVX-512, SHA-NI, AVX2) + isteğe bağlı Overt AsicBoost (BIP 310 version rolling).

> **Dürüst beklenti:** Bu yazılım size para kazandırmaz. Bir i7 dizüstü ~40-50 MH/s verir; ağ ~1 ZH/s civarında. Solo olarak blok bulma olasılığı pratikte sıfırdır (yüzlerce milyon yıl mertebesi). Amaç, madenciliğin nasıl çalıştığını ve optimizasyonu (midstate, tur eleme, SIMD, AsicBoost) görmek ve öğrenmektir. Elektrik maliyetini ve işlemci ısınmasını göz önünde bulundurun.

## Özellikler
- Midstate + nonce'un 3. turdan girmesi, ikinci özetteki 61 tur kısayolu, sabit katlanmış mesaj programı
- Birden çok motor, başlangıçta işlemcinize göre otomatik seçilir (program hepsini ölçer, en hızlısını alır):
  - `avx512`: 16 şerit, doğal dönme ve üçlü mantık komutları
  - `avx512vl`: aynı AVX-512 komutlarıyla 8 şerit
  - `shani`: Intel SHA uzantıları (AMD Zen'de de var), birden çok akış iç içe
  - `avx2`: 8 şerit, 2013'ten beri her işlemcide çalışır (Haswell, Zen)
  - `scalar`: her yerde çalışan yavaş yedek
- Her isabet gönderilmeden önce skaler kodla yeniden doğrulanır
- Overt AsicBoost: ikinci blok mesaj programı birçok blok sürümü için paylaşılır
- `--selftest`: genesis bloğu, merkle katlama, nbits hedefi ve her motorun skaler referansla karşılaştırması

## Ölçülen hız (tek iş parçacığı, M=16 sürüm)
Yalnızca tek bir makinede ölçüldü: AVX-512 ve SHA-NI olan bir Intel Xeon sanal makinesi. Sizin işlemciniz farklı olur; program en hızlı motoru kendisi seçer.

| Motor | İş parçacığı başına MH/s |
| --- | --- |
| avx512 | ~45 |
| avx512vl | ~29 |
| shani | ~15,5 |
| avx2 | ~15 |
| scalar | ~1,5 |

Yalnızca AVX2 olan bir dizüstüde (i7-6700HQ, AVX-512 ve SHA-NI yok) `avx2` motoru tüm çekirdeklerle yaklaşık 40-52 MH/s verir. Diğer motorlar daha yeni işlemci ister ve orada ölçülmedi.

## Kurulum
1. PHP 8+ (CLI) ve GCC (Windows için MSYS2/MinGW) gerekir.
2. Derleyin (ek bayrak gerekmez, motorlar çalışma anında seçilir):
   ```
   gcc -O3 -o sha256d_scan.exe sha256d_scan.c      # Windows
   gcc -O3 -o sha256d_scan sha256d_scan.c          # Linux
   ```
3. `config.example.php` dosyasını `config.php` olarak kopyalayıp kendi BTC adresinizi yazın.
4. Doğrulama: `php miner.php --selftest`
5. Çalıştırma: `php miner.php` (tüm çekirdekler) veya `php miner.php 6` (6 işçi). Durdurmak için Ctrl+C ya da `run.flag` dosyasını silin.

Tarayıcıdan değil, komut satırından çalıştırın. C programı yoksa çok yavaş olan saf PHP moduna düşer.

C programının komutları: `sha256d_scan --info` (bulunan motorlar), `--test` (her motoru doğrular), `--tune` (ölçüp en iyisini seçer), `--bench 16 avx2` (tek motoru ölçer). Bir motoru zorlamak için `SHA256D_ENGINE=avx2` ortam değişkenini kullanın.

## Isı ve güç
Tam güçte işlemci çok ısınabilir. Windows'ta "maksimum işlemci durumu"nu %99 yapmak turbo'yu kapatır (~%20 yavaşlar, ~15 °C serinler). İşçi sayısını çekirdek sayısının altında tutmak da bir seçenektir.

## Havuz
Varsayılan `solo.ckpool.org:3333`. Adresiniz kullanıcı adı olarak gönderilir; ödül blok bulunursa doğrudan o adrese gider. Havuz başlangıç zorluğu yüksektir, program `mining.suggest_difficulty` ile düşük zorluk ister.

## Dizin
- `miner.php`: Stratum istemcisi, işçi süreçleri, testler
- `sha256d_scan.c`: tüm motorlar tek dosyada (üretilmiş)
- `tools/gen_kernels.py` + `tools/skeleton.c`: AVX2 / AVX-512 çekirdek üreteci. Yeniden üretmek için `python3 tools/gen_kernels.py tools/skeleton.c > sha256d_scan.c`
- `tests/`: uçtan uca test için sahte havuz
- `CHANGELOG.md`

## Sorumluluk
Yalnızca kendi donanımınızda ve kendi adresinizle kullanın. Başkasının cihazında izinsiz çalıştırmak yasa dışıdır.

## Lisans
MIT (bkz. LICENSE).
