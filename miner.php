<?php
/**
 * Solo Bitcoin madencisi v2.2 (solo.ckpool.org / Stratum v1) - C motoru (AVX-512/SHA-NI/AVX2) + OVERT ASICBOOST (version rolling) + istege bagli GPU (OpenCL)
 * v2.1: clean_jobs destegi, kademeli yeniden baglanma, share kabul/red sayaci, kopan worker'i yeniden baslatma, blok bulununca dosyaya kayit
 *
 * Kullanim (CMD'de, tarayicidan DEGIL):
 *   C:\xampp\php\php.exe miner.php            -> tum cekirdekler
 *   C:\xampp\php\php.exe miner.php 6          -> 6 worker
 *   C:\xampp\php\php.exe miner.php --selftest -> dogrulama testleri
 *
 * GPU: ayni klasorde gpu_scan.exe varsa ve --test gecerse ek bir GPU worker'i otomatik acilir. Kapatmak: GPU=0 (ortam degiskeni). Isi icin GPU_DUTY=50 gibi.
 * Ayni klasorde sha256d_scan.exe (sha256d_scan.c'den derlenmis) olmali. Motor (AVX-512/SHA-NI/AVX2) baslangicta otomatik secilir.
 * Havuz version rolling'i (BIP 310) kabul ederse AsicBoost acilir; etmezse eski gibi calisir.
 */
// Ayarlar config.php'den okunur (config.example.php'yi kopyalayip duzenleyin).
$cfgFile = __DIR__ . '/config.php';
$cfg = is_file($cfgFile) ? (require $cfgFile) : [];
define('ADDRESS', getenv('MINER_ADDRESS') ?: ($cfg['address'] ?? ''));
define('HOST', $cfg['host'] ?? 'solo.ckpool.org');
define('PORT', (int)($cfg['port'] ?? 3333));
const CHUNK_C   = 8000000;   // C modunda iki socket kontrolu arasi HASH sayisi (~1-2 sn)
const CHUNK_PHP = 400000;    // saf PHP modunda
const CHUNK_GPU = 134217728; // GPU modunda iki socket kontrolu arasi nonce (2^27)
const MAX_M     = 16;        // ayni nonce icin denenecek version sayisi (AsicBoost paylasimi)

set_time_limit(0);
if (ADDRESS === '' && !in_array('--selftest', $argv ?? [], true)) { die("Cuzdan adresi yok: config.example.php dosyasini config.php olarak kopyalayip 'address' alanini doldurun.\n"); }
if (PHP_SAPI !== 'cli') { die("Bu betik tarayicidan degil, komut satirindan calistirilmali: php miner.php\n"); }
// bu surumde sadece worker modu 'ayni dosyayi' cagirir
define('SELF', __FILE__);

/* ---------------- yardimci fonksiyonlar ---------------- */
function sha256d(string $d): string { return hash('sha256', hash('sha256', $d, true), true); }

function merkle_root(string $coinb1, string $en1, string $en2, string $coinb2, array $branch): string {
    $m = sha256d(hex2bin($coinb1 . $en1 . $en2 . $coinb2));
    foreach ($branch as $h) $m = sha256d($m . hex2bin($h));
    return $m;                                   // HAM digest: header'a oldugu gibi girer (ters CEVIRME!)
}

/** 76 baytlik header oneki (nonce haric) */
function header76(string $version, string $prevhash, string $merkle_raw, string $ntime, string $nbits): string {
    $prev = '';
    foreach (str_split($prevhash, 8) as $w) $prev .= strrev(hex2bin($w));  // stratum: her 4-bayt kelime ters
    return strrev(hex2bin($version)) . $prev . $merkle_raw . strrev(hex2bin($ntime)) . strrev(hex2bin($nbits));
}

/** nbits -> 32 baytlik big-endian hedef */
function nbits_target(string $nbits): string {
    $exp  = hexdec(substr($nbits, 0, 2));
    $coef = hex2bin(substr($nbits, 2, 6));
    return str_pad(str_pad($coef, $exp, "\0", STR_PAD_RIGHT), 32, "\0", STR_PAD_LEFT);
}

function popcount32(int $x): int { $c = 0; while ($x) { $c += $x & 1; $x >>= 1; } return $c; }

function c_binary(): ?string {
    foreach (['sha256d_scan.exe', 'sha256d_scan'] as $f) { $p = __DIR__ . DIRECTORY_SEPARATOR . $f; if (is_file($p)) return $p; }
    return null;
}
/** C motoru AsicBoost destekli (v4) mi? */
function gpu_binary(): ?string {
    foreach (['gpu_scan.exe', 'gpu_scan'] as $f) { $p = __DIR__ . DIRECTORY_SEPARATOR . $f; if (is_file($p)) return $p; }
    return null;
}
function c_has_ab(string $bin): bool { $o = []; @exec(escapeshellarg($bin) . ' --info', $o); return str_contains(implode(' ', $o), 'asicboost'); }

/* ---------------- selftest ---------------- */
function selftest(): void {
    $ok = true;
    $mr = strrev(hex2bin('4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b'));
    $h76 = header76('00000001', str_repeat('00', 32), $mr, dechex(1231006505), '1d00ffff');
    $hash = bin2hex(strrev(sha256d($h76 . pack('V', 2083236893))));
    $t1 = $hash === '000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f';
    echo "Genesis header/hash : ", $t1 ? "OK" : "HATA ($hash)", "\n"; $ok &= $t1;
    $cb = strrev(hex2bin('b1fea52486ce0c62bb442b530a3f0132b826c74e473d1f2c220bfa78111c5082'));
    $tx = strrev(hex2bin('f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16'));
    $root = bin2hex(strrev(sha256d($cb . $tx)));
    $t2 = $root === '7dac2c5666815c17a3b36427de37bb9d2e2c5ccec3f8633eb91a4205cb4c10ff';
    echo "Merkle katlama      : ", $t2 ? "OK" : "HATA ($root)", "\n"; $ok &= $t2;
    $t3 = bin2hex(nbits_target('17021673')) === '0000000000000000000216730000000000000000000000000000000000000000';
    echo "nbits -> hedef      : ", $t3 ? "OK" : "HATA", "\n"; $ok &= $t3;
    $bin = c_binary();
    if ($bin) {
        $m = hex2bin('1e700c0640e1c2829358d8e8359dbe383ccf6c8931391f965ed8f9c260b77a37');
        $h = header76('20a00000', implode('', array_reverse(str_split('000000000000000000026fbdde4548920fd895ce0869737fcfb2c110156ffb4d', 8))), strrev($m), '664ba3a6', '1703629a');
        $out = []; exec(escapeshellarg($bin) . ' ' . bin2hex($h) . ' 4241853000 2000', $out);
        $t4 = isset($out[0]) && str_contains($out[0], '00000000000000000001f093493ae93f');
        echo "C cekirdegi         : ", $t4 ? "OK" : "HATA", "\n"; $ok &= $t4;
        if (c_has_ab($bin)) {
            $o = []; exec(escapeshellarg($bin) . ' --test', $o);
            $t5 = str_contains(implode(' ', $o), 'TEST OK');
            echo "AsicBoost (version) : ", $t5 ? "OK (" . trim(implode(' ', $o)) . ")" : "HATA", "\n"; $ok &= $t5;
        } else echo "AsicBoost (version) : (C motoru eski surum, AsicBoost kapali)\n";
    } else echo "C cekirdegi         : (bulunamadi, saf PHP modu kullanilacak)\n";
    exit($ok ? 0 : 1);
}

/* ---------------- stratum ---------------- */
class Stratum {
    public $sock; public $buf = ''; public $en1; public $en2size; public $diff = 1.0; public $job = null; public $nid = 100; public $vmask = 0;
    public $clean = false; public $lastRx; public static $acc = 0, $rej = 0;
    function __construct() {
        $this->sock = @stream_socket_client('tcp://' . HOST . ':' . PORT, $e, $es, 15);
        if (!$this->sock) throw new Exception("baglanti hatasi: $es");
        stream_set_timeout($this->sock, 15);
        $this->lastRx = microtime(true);
        // BIP 310: version rolling anlasmasi (subscribe'dan ONCE)
        $this->send(5, 'mining.configure', [['version-rolling'], ['version-rolling.mask' => '1fffe000', 'version-rolling.min-bit-count' => 2]]);
        $this->send(1, 'mining.subscribe', []);
        $this->send(2, 'mining.authorize', [ADDRESS, 'x']);
        $this->send(3, 'mining.suggest_difficulty', [1]);
        $t = time();
        while ($this->job === null && time() - $t < 30) $this->poll(true);
        if ($this->job === null) throw new Exception('is alinamadi');
        stream_set_blocking($this->sock, false);
    }
    function send($id, $m, $p) { fwrite($this->sock, json_encode(['id' => $id, 'method' => $m, 'params' => $p]) . "\n"); }
    function poll(bool $block = false): bool {
        $new = false;
        $d = fread($this->sock, 65536);
        if ($d === false || ($d === '' && feof($this->sock))) throw new Exception('baglanti koptu');
        if ($d === '' && $block) { usleep(100000); }
        if ($d !== '') $this->lastRx = microtime(true);
        $this->buf .= $d;
        while (($p = strpos($this->buf, "\n")) !== false) {
            $line = substr($this->buf, 0, $p); $this->buf = substr($this->buf, $p + 1);
            $m = json_decode($line, true); if (!$m) continue;
            if (($m['id'] ?? null) === 2 && array_key_exists('result', $m) && $m['result'] !== true) throw new Exception('yetkilendirme reddedildi: ' . json_encode($m['error'] ?? $m['result']));
            if (($m['id'] ?? null) === 5) {
                if (isset($m['result']) && is_array($m['result']) && !empty($m['result']['version-rolling']))
                    $this->vmask = hexdec((string)($m['result']['version-rolling.mask'] ?? '0')) & 0xffffffff;
            }
            elseif (($m['id'] ?? null) === 1 && isset($m['result'])) { $this->en1 = $m['result'][1]; $this->en2size = $m['result'][2]; }
            elseif (($m['method'] ?? '') === 'mining.set_difficulty') $this->diff = (float)$m['params'][0];
            elseif (($m['method'] ?? '') === 'mining.set_version_mask') $this->vmask = hexdec((string)$m['params'][0]) & 0xffffffff;
            elseif (($m['method'] ?? '') === 'mining.notify') { $this->job = $m['params']; $new = true; if (!empty($m['params'][8])) $this->clean = true; }
            elseif (($m['id'] ?? 0) >= 100) {
                if (!empty($m['result'])) { self::$acc++; echo '[', date('H:i:s'), '] share KABUL (bu worker: ', self::$acc, ")\n"; }
                else { self::$rej++; $why = is_array($m['error'] ?? null) ? ($m['error'][1] ?? json_encode($m['error'])) : json_encode($m['error'] ?? $m['result'] ?? '?'); echo '[', date('H:i:s'), '] share RED: ', $why, "\n"; }
            }
        }
        return $new;
    }
}

function worker(int $id, $gpuDev = false): void {   // $gpuDev: false = CPU, 'auto' veya cihaz no = GPU
    $gpu = ($gpuDev !== false);
    $bin = $gpu ? gpu_binary() : c_binary();
    $ab  = !$gpu && $bin && c_has_ab($bin);
    $gp = null; $gpipes = [];   // GPU: kalici gpu_scan --serve sureci
    if ($gpu) {
        $gcmd = [$bin, '--serve']; if ($gpu && $gpuDev !== 'auto') $gcmd[] = (string)$gpuDev;
        $gp = @proc_open($gcmd, [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => STDERR], $gpipes);
        if (!is_resource($gp)) { echo "[w$id] GPU sureci baslatilamadi\n"; return; }
    }
    $statf = __DIR__ . "/stats_$id.txt";
    $flag  = __DIR__ . '/run.flag';
    $fails = 0;
    while (true) {
        try {
            $s = new Stratum(); $fails = 0;
            $mask = (int)$s->vmask;
            $M = ($ab && $mask) ? min(MAX_M, 1 << min(6, popcount32($mask))) : 1;
            if ($M < 2) { $M = 1; }
            $useMask = ($M > 1) ? $mask : 0;
            echo "[w$id] baglandi, mod: ", $gpu ? 'GPU (OpenCL)' : ($bin ? ($M > 1 ? "C+AsicBoost x$M (maske " . sprintf('%08x', $mask) . ")" : 'C') : 'PHP'), ", zorluk {$s->diff}\n";
            $total = 0; $t0 = microtime(true); $lastStat = $t0; $s->clean = false;
            while (is_file($flag)) {
                [$job_id, $prevhash, $c1, $c2, $branch, $ver, $nbits, $ntime] = $s->job;
                $en2 = bin2hex(random_bytes($s->en2size));
                $h76 = header76($ver, $prevhash, merkle_root($c1, $s->en1, $en2, $c2, $branch), $ntime, $nbits);
                $target = nbits_target($nbits);
                $myjob = $s->job; $nonce = 0; $found = []; $s->clean = false;
                $chunkN = $gpu ? (int)(getenv("MINER_CHUNK_GPU") ?: CHUNK_GPU) : ($bin ? max(8, intdiv(CHUNK_C, $M)) : CHUNK_PHP);   // nonce sayisi/cagri
                while ($nonce <= 0xFFFFFFFF) {
                    $cnt = min($chunkN, 0x100000000 - $nonce);
                    if ($gpu) {
                        $out = [];
                        fwrite($gpipes[0], bin2hex($h76) . " $nonce $cnt\n"); fflush($gpipes[0]);
                        while (($l = fgets($gpipes[1])) !== false) {
                            $l = trim($l);
                            if ($l === 'DONE') break;
                            if ($l === 'ERR') throw new Exception('GPU hatasi');
                            $out[] = $l;
                        }
                        if ($l === false) throw new Exception('GPU sureci kapandi');
                        foreach ($out as $l) {
                            $p = explode(' ', $l);
                            if (count($p) >= 3) $found[] = [(int)$p[0], $p[2], null];
                        }
                    } elseif ($bin) {
                        $out = [];
                        $cmd = escapeshellarg($bin) . ' ' . bin2hex($h76) . " $nonce $cnt" . ($ab ? sprintf(' %08x %d', $useMask, $M) : '');
                        exec($cmd, $out);
                        foreach ($out as $l) {
                            $p = explode(' ', trim($l));
                            if (count($p) >= 3) $found[] = [(int)$p[0], $p[2], isset($p[3]) ? hexdec($p[3]) : null];
                        }
                    } else {
                        $zero = "\0\0\0\0";
                        for ($n = $nonce, $e = $nonce + $cnt; $n < $e; $n++) {
                            $hh = sha256d($h76 . pack('V', $n));
                            if (substr($hh, 28, 4) === $zero) $found[] = [$n, bin2hex(strrev($hh)), null];
                        }
                    }
                    $nonce += $cnt; $total += $cnt * $M;
                    foreach ($found as [$n, $hex, $vfull]) {
                        $be = hex2bin($hex);
                        $isBlock = strcmp($be, $target) <= 0;
                        $shareOk = hexdec(substr($hex, 0, 16)) <= 4294901760.0 / max($s->diff, 0.000001);
                        if ($isBlock || $shareOk) {
                            $params = [ADDRESS, $myjob[0], $en2, $myjob[7], sprintf('%08x', $n)];
                            if ($useMask && $vfull !== null) $params[] = sprintf('%08x', $vfull & $useMask);   // BIP 310: version_bits
                            $s->send($s->nid++, 'mining.submit', $params);
                            echo "[w$id] ", $isBlock ? '*** BLOK BULUNDU ***' : 'share gonderildi', " $hex nonce=$n", ($useMask && $vfull !== null ? sprintf(' vbits=%08x', $vfull & $useMask) : ''), "\n";
                            if ($isBlock) @file_put_contents(__DIR__ . '/BLOK_BULUNDU.txt', date('c') . " hash=$hex nonce=$n params=" . json_encode($params) . "\n", FILE_APPEND);
                        }
                    }
                    $found = [];
                    $now = microtime(true);
                    if ($now - $lastStat >= 3) { file_put_contents($statf, (int)($total / ($now - $t0)) . ' ' . Stratum::$acc . ' ' . Stratum::$rej); $lastStat = $now; $total = 0; $t0 = $now; }
                    if ($s->poll() && ($s->job[1] !== $myjob[1] || $s->clean)) {
                        echo "[w$id] ", ($s->job[1] !== $myjob[1] ? 'yeni blok algilandi' : 'havuz eski isi gecersiz kildi (clean_jobs)'), "\n"; $s->clean = false; break;
                    }
                    if (microtime(true) - $s->lastRx > 900) throw new Exception('havuz 15 dk sessiz kaldi');
                    if (!is_file($flag)) { if ($gp) { fclose($gpipes[0]); proc_close($gp); } return; }
                }
            }
            if ($gp) { fclose($gpipes[0]); proc_close($gp); }
            return;
        } catch (Throwable $e) {
            if ($gp && $gpu) { $stg = proc_get_status($gp); if (!$stg['running']) { echo "[w$id] GPU sureci kapandi, GPU worker durduruldu\n"; @proc_close($gp); return; } }
            $fails++; $wait = min(60, 2 ** min($fails, 6));
            echo "[w$id] hata: ", $e->getMessage(), " - $wait sn sonra yeniden\n";
            for ($k = 0; $k < $wait && is_file($flag); $k++) sleep(1);
            if (!is_file($flag)) return;
        }
    }
}

/* ---------------- ana ---------------- */
$opt = getopt('', ['worker:', 'selftest', 'gpu:']);
if (isset($opt['selftest'])) selftest();
if (isset($opt['worker'])) { worker((int)$opt['worker'], isset($opt['gpu']) ? (string)$opt['gpu'] : false); exit; }

// Mod: "php miner.php" = CPU + GPU | "php miner.php gpu" = yalniz ekran karti | "php miner.php cpu" = yalniz CPU | "php miner.php 6" = 6 CPU worker (+GPU)
$mode = strtolower((string)($argv[1] ?? ''));
$gpuOnly = ($mode === 'gpu');
if ($mode === 'cpu') putenv('GPU=0');
$n = ($gpuOnly || $mode === 'cpu') ? 0 : (int)($argv[1] ?? 0);
if ($gpuOnly) { $n = 0; }
elseif ($n < 1) { $n = (int)(getenv('NUMBER_OF_PROCESSORS') ?: 0); if ($n < 1) $n = (int)@shell_exec('nproc'); if ($n < 1) $n = 2; }
file_put_contents(__DIR__ . '/run.flag', '1');
$bin = c_binary();
// Islemciye gore en hizli motoru olc ve sec (AVX-512 / SHA-NI / AVX2); isciler ortam degiskenini miras alir
if (!$gpuOnly && $bin && !getenv('SHA256D_ENGINE')) {
    $o = []; @exec(escapeshellarg($bin) . ' --tune 16', $o);
    foreach ($o as $l) if (preg_match('/^BEST (\w+)/', $l, $mm)) putenv('SHA256D_ENGINE=' . $mm[1]);
}
$eng = getenv('SHA256D_ENGINE') ?: '-';
// GPU: gpu_scan var, GPU=0 degil ve kendi testi gecerse ek worker olarak calisir.
// Birden fazla ekran karti icin cihaz numaralari: set GPU_DEVICES=2,0   (numaralar: gpu_scan.exe --info)
$gpuDevs = []; $gbin = gpu_binary();
if ($gbin && getenv('GPU') !== '0') {
    $want = getenv('GPU_DEVICES') !== false && getenv('GPU_DEVICES') !== '' ? array_map('trim', explode(',', getenv('GPU_DEVICES'))) : ['auto'];
    foreach ($want as $dv) {
        $go = []; @exec(escapeshellarg($gbin) . ' --test' . ($dv === 'auto' ? '' : ' ' . (int)$dv) . ' 2>&1', $go);
        if (str_contains(implode(' ', $go), 'TEST OK')) { $gpuDevs[] = ($dv === 'auto' ? 'auto' : (string)(int)$dv); echo "GPU: " . trim(preg_replace('/^GPU: /', '', $go[0] ?? '')) . " (test OK)\n"; }
        else echo "GPU (" . $dv . ") testi gecmedi, atlandi: " . implode(' | ', $go) . "\n";
    }
}
$useGpu = count($gpuDevs) > 0;
$total = $n + count($gpuDevs);
if ($total < 1) { @unlink(__DIR__ . '/run.flag'); die("Calistirilacak GPU bulunamadi (gpu_scan.exe yok ya da testi gecmedi). 'php miner.php' ile CPU modunu kullan.\n"); }
echo "Cuzdan: " . ADDRESS . "\nWorker: $n CPU + " . count($gpuDevs) . " GPU | mod: " . ($n < 1 ? 'yalniz GPU' : ($bin ? ('C cekirdegi, motor: ' . $eng . (c_has_ab($bin) ? ' (AsicBoost destekli)' : '')) : 'saf PHP')) . "\nDurdurmak icin Ctrl+C veya run.flag dosyasini sil.\n\n";
function spawn_worker(int $i) {
    global $n, $gpuDevs;
    $cmd = [PHP_BINARY, SELF, "--worker=$i"]; if ($i >= $n) $cmd[] = '--gpu=' . $gpuDevs[$i - $n];
    return proc_open($cmd, [0 => ['file', 'php://stdin', 'r'], 1 => STDOUT, 2 => STDERR], $pipes);
}
$procs = []; $accDone = array_fill(0, $total, 0); $rejDone = array_fill(0, $total, 0); $tStart = time();
for ($i = 0; $i < $total; $i++) { @unlink(__DIR__ . "/stats_$i.txt"); $procs[$i] = spawn_worker($i); }
while (is_file(__DIR__ . '/run.flag')) {
    sleep(10);
    $sum = 0; $acc = 0; $rej = 0; $gsum = 0;
    for ($i = 0; $i < $total; $i++) {
        $p = explode(' ', trim((string)@file_get_contents(__DIR__ . "/stats_$i.txt")) . ' 0 0 0');
        $sum += (int)$p[0]; if ($i >= $n) $gsum = ($gsum ?? 0) + (int)$p[0]; $acc += (int)$p[1] + $accDone[$i]; $rej += (int)$p[2] + $rejDone[$i];
        // beklenmedik sekilde kapanan worker'i yeniden baslat
        $st = is_resource($procs[$i]) ? proc_get_status($procs[$i]) : ['running' => false];
        if (!$st['running'] && is_file(__DIR__ . '/run.flag')) {
            echo "[ana] worker $i beklenmedik sekilde kapandi, yeniden baslatiliyor\n";
            $accDone[$i] += (int)$p[1]; $rejDone[$i] += (int)$p[2];
            if (is_resource($procs[$i])) proc_close($procs[$i]);
            @unlink(__DIR__ . "/stats_$i.txt");
            $procs[$i] = spawn_worker($i);
        }
    }
    $up = time() - $tStart;
    if ($useGpu) printf("[%s]   (CPU: %.2f MH/s + GPU: %.2f MH/s)\n", date('H:i:s'), ($sum - ($gsum ?? 0)) / 1e6, ($gsum ?? 0) / 1e6);
    printf("[%s] TOPLAM HIZ: %s H/s (%.2f MH/s) | share kabul: %d red: %d | sure: %dsa %02ddk\n", date('H:i:s'), number_format($sum), $sum / 1e6, $acc, $rej, intdiv($up, 3600), intdiv($up % 3600, 60));
}
