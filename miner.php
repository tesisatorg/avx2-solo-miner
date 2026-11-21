<?php
/**
 * Solo Bitcoin madencisi (solo.ckpool.org / Stratum v1) - AVX2 C motoru + OVERT ASICBOOST (version rolling)
 *
 * Kullanim (CMD'de, tarayicidan DEGIL):
 *   C:\xampp\php\php.exe miner.php            -> tum cekirdekler
 *   C:\xampp\php\php.exe miner.php 6          -> 6 worker
 *   C:\xampp\php\php.exe miner.php --selftest -> dogrulama testleri
 *
 * Ayni klasorde sha256d_scan.exe (sha256d_scan.c'den derlenmis) olmali.
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
    function __construct() {
        $this->sock = @stream_socket_client('tcp://' . HOST . ':' . PORT, $e, $es, 15);
        if (!$this->sock) throw new Exception("baglanti hatasi: $es");
        stream_set_timeout($this->sock, 15);
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
        $this->buf .= $d;
        while (($p = strpos($this->buf, "\n")) !== false) {
            $line = substr($this->buf, 0, $p); $this->buf = substr($this->buf, $p + 1);
            $m = json_decode($line, true); if (!$m) continue;
            if (($m['id'] ?? null) === 5) {
                if (isset($m['result']) && is_array($m['result']) && !empty($m['result']['version-rolling']))
                    $this->vmask = hexdec((string)($m['result']['version-rolling.mask'] ?? '0')) & 0xffffffff;
            }
            elseif (($m['id'] ?? null) === 1 && isset($m['result'])) { $this->en1 = $m['result'][1]; $this->en2size = $m['result'][2]; }
            elseif (($m['method'] ?? '') === 'mining.set_difficulty') $this->diff = (float)$m['params'][0];
            elseif (($m['method'] ?? '') === 'mining.set_version_mask') $this->vmask = hexdec((string)$m['params'][0]) & 0xffffffff;
            elseif (($m['method'] ?? '') === 'mining.notify') { $this->job = $m['params']; $new = true; }
            elseif (($m['id'] ?? 0) >= 100) { echo '[', date('H:i:s'), '] Pool cevabi: ', $line, "\n"; }
        }
        return $new;
    }
}

function worker(int $id): void {
    $bin = c_binary();
    $ab  = $bin && c_has_ab($bin);
    $statf = __DIR__ . "/stats_$id.txt";
    $flag  = __DIR__ . '/run.flag';
    while (true) {
        try {
            $s = new Stratum();
            $mask = (int)$s->vmask;
            $M = ($ab && $mask) ? min(MAX_M, 1 << min(6, popcount32($mask))) : 1;
            if ($M < 2) { $M = 1; }
            $useMask = ($M > 1) ? $mask : 0;
            echo "[w$id] baglandi, mod: ", $bin ? ($M > 1 ? "C+AsicBoost x$M (maske " . sprintf('%08x', $mask) . ")" : 'C') : 'PHP', ", zorluk {$s->diff}\n";
            $total = 0; $t0 = microtime(true); $lastStat = $t0;
            while (is_file($flag)) {
                [$job_id, $prevhash, $c1, $c2, $branch, $ver, $nbits, $ntime] = $s->job;
                $en2 = bin2hex(random_bytes($s->en2size));
                $h76 = header76($ver, $prevhash, merkle_root($c1, $s->en1, $en2, $c2, $branch), $ntime, $nbits);
                $target = nbits_target($nbits);
                $myjob = $s->job; $nonce = 0; $found = [];
                $chunkN = $bin ? max(8, intdiv(CHUNK_C, $M)) : CHUNK_PHP;   // nonce sayisi/cagri
                while ($nonce <= 0xFFFFFFFF) {
                    $cnt = min($chunkN, 0x100000000 - $nonce);
                    if ($bin) {
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
                        }
                    }
                    $found = [];
                    $now = microtime(true);
                    if ($now - $lastStat >= 3) { file_put_contents($statf, (int)($total / ($now - $t0))); $lastStat = $now; $total = 0; $t0 = $now; }
                    if ($s->poll() && $s->job[1] !== $myjob[1]) { echo "[w$id] yeni blok algilandi\n"; break; }
                    if (!is_file($flag)) return;
                }
            }
            return;
        } catch (Throwable $e) { echo "[w$id] hata: ", $e->getMessage(), " - 5 sn sonra yeniden\n"; sleep(5); }
    }
}

/* ---------------- ana ---------------- */
$opt = getopt('', ['worker:', 'selftest']);
if (isset($opt['selftest'])) selftest();
if (isset($opt['worker'])) { worker((int)$opt['worker']); exit; }

$n = (int)($argv[1] ?? 0);
if ($n < 1) { $n = (int)(getenv('NUMBER_OF_PROCESSORS') ?: 0); if ($n < 1) $n = (int)@shell_exec('nproc'); if ($n < 1) $n = 2; }
file_put_contents(__DIR__ . '/run.flag', '1');
$bin = c_binary();
echo "Cuzdan: " . ADDRESS . "\nWorker: $n | mod: " . ($bin ? ('C cekirdegi' . (c_has_ab($bin) ? ' (AsicBoost destekli)' : '')) : 'saf PHP') . "\nDurdurmak icin Ctrl+C veya run.flag dosyasini sil.\n\n";
$procs = [];
for ($i = 0; $i < $n; $i++) {
    @unlink(__DIR__ . "/stats_$i.txt");
    $procs[] = proc_open([PHP_BINARY, SELF, "--worker=$i"], [0 => ['file', 'php://stdin', 'r'], 1 => STDOUT, 2 => STDERR], $pipes);
}
while (is_file(__DIR__ . '/run.flag')) {
    sleep(10);
    $sum = 0; for ($i = 0; $i < $n; $i++) $sum += (int)@file_get_contents(__DIR__ . "/stats_$i.txt");
    printf("[%s] TOPLAM HIZ: %s H/s (%.2f MH/s)\n", date('H:i:s'), number_format($sum), $sum / 1e6);
}
