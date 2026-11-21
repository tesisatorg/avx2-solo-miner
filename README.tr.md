# avx2-solo-miner

[English](README.md) | **Türkçe**

Hobi amaçlı, **eğitim odaklı** bir solo Bitcoin madencisi: PHP (Stratum v1 istemcisi ve işçi yönetimi) + C (AVX2 ile 8'li paralel SHA-256d tarayıcı) + isteğe bağlı Overt AsicBoost (BIP 310 version rolling).

> **Dürüst beklenti:** Bu yazılım size para kazandırmaz. Bir i7 dizüstü ~40-50 MH/s verir; ağ ~1 ZH/s civarında. Solo olarak blok bulma olasılığı pratikte sıfırdır (yüzlerce milyon yıl mertebesi). Amaç, madenciliğin nasıl çalıştığını ve optimizasyonu (midstate, tur eleme, AVX2, AsicBoost) görmek ve öğrenmektir. Elektrik maliyetini ve işlemci ısınmasını göz önünde bulundurun.

## Özellikler
- Midstate + nonce'un 3. turdan girmesi, ikinci özetteki 61 tur kısayolu, sabit katlanmış mesaj programı
- AVX2 ile 8 nonce'u aynı anda tarama, isabetlerde skaler yeniden doğrulama
- Overt AsicBoost: ikinci blok mesaj programı birden çok version için paylaşılır (~%14 ölçülmüş kazanç)
- `--selftest`: genesis bloğu, merkle katlama, nbits hedefi ve C çekirdeği testleri

## Kurulum
1. PHP 8+ (CLI) ve GCC (Windows için MSYS2/MinGW) gerekir.
2. Derleyin:
   ```
   gcc -O3 -mavx2 -march=haswell -o sha256d_scan.exe sha256d_scan.c      # Windows
   gcc -O3 -mavx2 -march=haswell -o sha256d_scan sha256d_scan.c          # Linux
   ```
3. `config.example.php` dosyasını `config.php` olarak kopyalayıp kendi BTC adresinizi yazın.
4. Doğrulama: `php miner.php --selftest`
5. Çalıştırma: `php miner.php` (tüm çekirdekler) veya `php miner.php 6` (6 işçi). Durdurmak için Ctrl+C ya da `run.flag` dosyasını silin.

Tarayıcıdan değil, komut satırından çalıştırın. C çekirdeği yoksa çok yavaş olan saf PHP moduna düşer.

## Isı ve güç
Tam güçte işlemci çok ısınabilir. Windows'ta "maksimum işlemci durumu"nu %99 yapmak turbo'yu kapatır (~%20 yavaşlar, ~15 °C serinler). İşçi sayısını çekirdek sayısının altında tutmak da bir seçenektir.

## Havuz
Varsayılan `solo.ckpool.org:3333`. Adresiniz kullanıcı adı olarak gönderilir; ödül blok bulunursa doğrudan o adrese gider. Havuz başlangıç zorluğu yüksektir, program `mining.suggest_difficulty` ile düşük zorluk ister.

## Dizin
- `miner.php` : Stratum istemcisi, işçi süreçleri, testler
- `sha256d_scan.c` : AVX2 + AsicBoost çekirdeği (`tools/gen_ab.py` ile üretilmiş düz kod)
- `tools/` : çekirdek üreteci ve şablonu
- `tests/` : sahte havuz (mock) ile uçtan uca test

## Sorumluluk
Yalnızca kendi donanımınızda ve kendi adresinizle kullanın. Başkasının cihazında izinsiz çalıştırmak yasa dışıdır.

## Lisans
MIT (bkz. LICENSE).