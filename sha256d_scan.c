/* sha256d_scan v4 - AVX2 8-way Bitcoin header nonce tarayici + OVERT ASICBOOST (version rolling, BIP 310/320)
 *
 * Fikir: 2. blok mesaj genisletmesi (message schedule) versiyondan bagimsizdir. Ayni nonce icin M farkli
 *        version degeri denenirken genisletme BIR KEZ hesaplanir, M versiyon arasinda paylasilir.
 * Diger teknikler (v3'ten): ilk 3 tur on-hesap, sabit kelime katlama, maj hilesi, 61 tur + son 4 turda 'a' atla,
 *        2. hash 0. tur katlama, movemask ile hizli hit kontrolu.
 *
 * Derle (MSYS2 MINGW64):  gcc -O3 -mavx2 -march=haswell -o sha256d_scan.exe sha256d_scan_ab.c
 * Kullanim: sha256d_scan.exe <76 bayt header hex> <start_nonce> <count> [version_mask_hex M]
 *           sha256d_scan.exe --info | --test | --bench [M]
 * Cikti: "nonce_dec nonce_hex hash_display_hex version_hex"  (>=32 sifir bitli hash'ler)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <immintrin.h>
typedef __m256i V;
#define ROR32(x,n) (((x)>>(n))|((x)<<(32-(n))))
#define ADD(a,b) _mm256_add_epi32(a,b)
#define XOR(a,b) _mm256_xor_si256(a,b)
#define AND(a,b) _mm256_and_si256(a,b)
#define OR(a,b) _mm256_or_si256(a,b)
#define SHR(x,n) _mm256_srli_epi32(x,n)
#define SHL(x,n) _mm256_slli_epi32(x,n)
#define ROR(x,n) OR(SHR(x,n),SHL(x,32-(n)))
#define SIG0V(x) XOR(XOR(ROR(x,7),ROR(x,18)),SHR(x,3))
#define SIG1V(x) XOR(XOR(ROR(x,17),ROR(x,19)),SHR(x,10))
#define BS0V(x) XOR(XOR(ROR(x,2),ROR(x,13)),ROR(x,22))
#define BS1V(x) XOR(XOR(ROR(x,6),ROR(x,11)),ROR(x,25))
#define CH(e,f,g) XOR(g,AND(e,XOR(f,g)))
#define NC 33
#define MAXM 64
typedef struct { uint32_t st3[8]; uint32_t mid[8]; } VS;

static const uint32_t K[64]={
0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
static const uint32_t IV[8]={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};

static void compress(uint32_t s[8], const uint32_t in[16]){
  uint32_t w[64],a,b,c,d,e,f,g,h,t1,t2;int i;
  for(i=0;i<16;i++)w[i]=in[i];
  for(i=16;i<64;i++){uint32_t s0=ROR32(w[i-15],7)^ROR32(w[i-15],18)^(w[i-15]>>3),s1=ROR32(w[i-2],17)^ROR32(w[i-2],19)^(w[i-2]>>10);w[i]=w[i-16]+s0+w[i-7]+s1;}
  a=s[0];b=s[1];c=s[2];d=s[3];e=s[4];f=s[5];g=s[6];h=s[7];
  for(i=0;i<64;i++){
    t1=h+(ROR32(e,6)^ROR32(e,11)^ROR32(e,25))+((e&f)^(~e&g))+K[i]+w[i];
    t2=(ROR32(a,2)^ROR32(a,13)^ROR32(a,22))+((a&b)^(a&c)^(b&c));
    h=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;
  }
  s[0]+=a;s[1]+=b;s[2]+=c;s[3]+=d;s[4]+=e;s[5]+=f;s[6]+=g;s[7]+=h;
}
static uint32_t be32(const uint8_t*p){return (uint32_t)p[0]<<24|p[1]<<16|p[2]<<8|p[3];}
static int hexv(char c){ if(c>='0'&&c<='9')return c-'0'; c=(char)(c|32); return c>='a'&&c<='f'?c-'a'+10:-1; }
static void scalar_hash(const uint8_t*hdr,uint32_t nonce,uint32_t out[8]){
  uint32_t mid[8],blk[16],blk2[16]={0},i;
  memcpy(mid,IV,32);{uint32_t b0[16];for(i=0;i<16;i++)b0[i]=be32(hdr+4*i);compress(mid,b0);}
  blk[0]=be32(hdr+64);blk[1]=be32(hdr+68);blk[2]=be32(hdr+72);
  blk[3]=((nonce&0xff)<<24)|((nonce&0xff00)<<8)|((nonce>>8)&0xff00)|(nonce>>24);
  blk[4]=0x80000000u;for(i=5;i<15;i++)blk[i]=0;blk[15]=640;
  compress(mid,blk);memcpy(blk2,mid,32);blk2[8]=0x80000000u;blk2[15]=256;
  memcpy(out,IV,32);compress(out,blk2);
}

/* versiyondan bagimsiz on-hesap (w0..w2 ve sabit-katlanmis schedule sabitleri) */
static void prepare_shared(const uint8_t *hdr, uint32_t *c){
  c[8]=be32(hdr+64);c[9]=be32(hdr+68);c[10]=be32(hdr+72);
    c[19] = ROR32(c[9],7)^ROR32(c[9],18)^(c[9]>>3);
    c[20] = c[8] + c[19];
    c[21] = c[20] + 0xe49b69c1u;
    c[22] = ROR32(c[10],7)^ROR32(c[10],18)^(c[10]>>3);
    c[23] = c[9] + c[22] + 0x01100000u;
    c[24] = c[23] + 0xefbe4786u;
    c[25] = ROR32(c[20],17)^ROR32(c[20],19)^(c[20]>>10);
    c[26] = c[10] + c[25];
    c[27] = ROR32(c[23],17)^ROR32(c[23],19)^(c[23]>>10);
    c[28] = c[27] + 0x11002000u;
    c[29] = ROR32(c[20],7)^ROR32(c[20],18)^(c[20]>>3);
    c[30] = c[29] + 0x00000280u;
    c[31] = ROR32(c[23],7)^ROR32(c[23],18)^(c[23]>>3);
    c[32] = c[20] + c[31];
}
/* versiyona ozel on-hesap: ilk 64 bayt midstate + ilk 3 tur */
static void prepare_ver(const uint8_t *hdr, VS *v){
  uint32_t mid[8],b0[16],w[3],a,b,cc,d,e,f,g,h,t1,t2;int i;
  memcpy(mid,IV,32);for(i=0;i<16;i++)b0[i]=be32(hdr+4*i);compress(mid,b0);
  w[0]=be32(hdr+64);w[1]=be32(hdr+68);w[2]=be32(hdr+72);
  a=mid[0];b=mid[1];cc=mid[2];d=mid[3];e=mid[4];f=mid[5];g=mid[6];h=mid[7];
  for(i=0;i<3;i++){
    t1=h+(ROR32(e,6)^ROR32(e,11)^ROR32(e,25))+((e&f)^(~e&g))+K[i]+w[i];
    t2=(ROR32(a,2)^ROR32(a,13)^ROR32(a,22))+((a&b)^(a&cc)^(b&cc));
    h=g;g=f;f=e;e=d+t1;d=cc;cc=b;b=a;a=t1+t2;
  }
  v->st3[0]=a;v->st3[1]=b;v->st3[2]=cc;v->st3[3]=d;v->st3[4]=e;v->st3[5]=f;v->st3[6]=g;v->st3[7]=h;
  for(i=0;i<8;i++)v->mid[i]=mid[i];
}
/* nonce'a bagli, versiyondan bagimsiz: 2. blok mesaj genisletmesi (bir kez) */
static inline void sched8(const uint32_t *c, V nonce, V *KW){
    V nonce_w3 = nonce;
    KW[3] = ADD(nonce_w3,_mm256_set1_epi32((int)0xe9b5dba5u));
    V v0 = SIG0V(nonce_w3);
    V v1 = ADD(v0,_mm256_set1_epi32((int)c[26]));
    KW[18] = ADD(v1,_mm256_set1_epi32((int)0x0fc19dc6u));
    V v2 = ADD(nonce_w3,_mm256_set1_epi32((int)c[28]));
    KW[19] = ADD(v2,_mm256_set1_epi32((int)0x240ca1ccu));
    V v3 = SIG1V(v1);
    V v4 = ADD(v3,_mm256_set1_epi32((int)0x80000000u));
    KW[20] = ADD(v4,_mm256_set1_epi32((int)0x2de92c6fu));
    V v5 = SIG1V(v2);
    V v6 = v5;
    KW[21] = ADD(v6,_mm256_set1_epi32((int)0x4a7484aau));
    V v7 = SIG1V(v4);
    V v8 = ADD(v7,_mm256_set1_epi32((int)0x00000280u));
    KW[22] = ADD(v8,_mm256_set1_epi32((int)0x5cb0a9dcu));
    V v9 = SIG1V(v6);
    V v10 = ADD(v9,_mm256_set1_epi32((int)c[20]));
    KW[23] = ADD(v10,_mm256_set1_epi32((int)0x76f988dau));
    V v11 = SIG1V(v8);
    V v12 = ADD(v11,_mm256_set1_epi32((int)c[23]));
    KW[24] = ADD(v12,_mm256_set1_epi32((int)0x983e5152u));
    V v13 = SIG1V(v10);
    V v14 = ADD(v1,v13);
    KW[25] = ADD(v14,_mm256_set1_epi32((int)0xa831c66du));
    V v15 = SIG1V(v12);
    V v16 = ADD(v2,v15);
    KW[26] = ADD(v16,_mm256_set1_epi32((int)0xb00327c8u));
    V v17 = SIG1V(v14);
    V v18 = ADD(v4,v17);
    KW[27] = ADD(v18,_mm256_set1_epi32((int)0xbf597fc7u));
    V v19 = SIG1V(v16);
    V v20 = ADD(v6,v19);
    KW[28] = ADD(v20,_mm256_set1_epi32((int)0xc6e00bf3u));
    V v21 = SIG1V(v18);
    V v22 = ADD(v8,v21);
    KW[29] = ADD(v22,_mm256_set1_epi32((int)0xd5a79147u));
    V v23 = SIG1V(v20);
    V v24 = ADD(ADD(v10,v23),_mm256_set1_epi32((int)0x00a00055u));
    KW[30] = ADD(v24,_mm256_set1_epi32((int)0x06ca6351u));
    V v25 = SIG1V(v22);
    V v26 = ADD(ADD(v12,v25),_mm256_set1_epi32((int)c[30]));
    KW[31] = ADD(v26,_mm256_set1_epi32((int)0x14292967u));
    V v27 = SIG1V(v24);
    V v28 = ADD(ADD(v14,v27),_mm256_set1_epi32((int)c[32]));
    KW[32] = ADD(v28,_mm256_set1_epi32((int)0x27b70a85u));
    V v29 = SIG0V(v1);
    V v30 = SIG1V(v26);
    V v31 = ADD(ADD(ADD(v29,v16),v30),_mm256_set1_epi32((int)c[23]));
    KW[33] = ADD(v31,_mm256_set1_epi32((int)0x2e1b2138u));
    V v32 = SIG0V(v2);
    V v33 = SIG1V(v28);
    V v34 = ADD(ADD(ADD(v1,v32),v18),v33);
    KW[34] = ADD(v34,_mm256_set1_epi32((int)0x4d2c6dfcu));
    V v35 = SIG0V(v4);
    V v36 = SIG1V(v31);
    V v37 = ADD(ADD(ADD(v2,v35),v20),v36);
    KW[35] = ADD(v37,_mm256_set1_epi32((int)0x53380d13u));
    V v38 = SIG0V(v6);
    V v39 = SIG1V(v34);
    V v40 = ADD(ADD(ADD(v4,v38),v22),v39);
    KW[36] = ADD(v40,_mm256_set1_epi32((int)0x650a7354u));
    V v41 = SIG0V(v8);
    V v42 = SIG1V(v37);
    V v43 = ADD(ADD(ADD(v6,v41),v24),v42);
    KW[37] = ADD(v43,_mm256_set1_epi32((int)0x766a0abbu));
    V v44 = SIG0V(v10);
    V v45 = SIG1V(v40);
    V v46 = ADD(ADD(ADD(v8,v44),v26),v45);
    KW[38] = ADD(v46,_mm256_set1_epi32((int)0x81c2c92eu));
    V v47 = SIG0V(v12);
    V v48 = SIG1V(v43);
    V v49 = ADD(ADD(ADD(v10,v47),v28),v48);
    KW[39] = ADD(v49,_mm256_set1_epi32((int)0x92722c85u));
    V v50 = SIG0V(v14);
    V v51 = SIG1V(v46);
    V v52 = ADD(ADD(ADD(v12,v50),v31),v51);
    KW[40] = ADD(v52,_mm256_set1_epi32((int)0xa2bfe8a1u));
    V v53 = SIG0V(v16);
    V v54 = SIG1V(v49);
    V v55 = ADD(ADD(ADD(v14,v53),v34),v54);
    KW[41] = ADD(v55,_mm256_set1_epi32((int)0xa81a664bu));
    V v56 = SIG0V(v18);
    V v57 = SIG1V(v52);
    V v58 = ADD(ADD(ADD(v16,v56),v37),v57);
    KW[42] = ADD(v58,_mm256_set1_epi32((int)0xc24b8b70u));
    V v59 = SIG0V(v20);
    V v60 = SIG1V(v55);
    V v61 = ADD(ADD(ADD(v18,v59),v40),v60);
    KW[43] = ADD(v61,_mm256_set1_epi32((int)0xc76c51a3u));
    V v62 = SIG0V(v22);
    V v63 = SIG1V(v58);
    V v64 = ADD(ADD(ADD(v20,v62),v43),v63);
    KW[44] = ADD(v64,_mm256_set1_epi32((int)0xd192e819u));
    V v65 = SIG0V(v24);
    V v66 = SIG1V(v61);
    V v67 = ADD(ADD(ADD(v22,v65),v46),v66);
    KW[45] = ADD(v67,_mm256_set1_epi32((int)0xd6990624u));
    V v68 = SIG0V(v26);
    V v69 = SIG1V(v64);
    V v70 = ADD(ADD(ADD(v24,v68),v49),v69);
    KW[46] = ADD(v70,_mm256_set1_epi32((int)0xf40e3585u));
    V v71 = SIG0V(v28);
    V v72 = SIG1V(v67);
    V v73 = ADD(ADD(ADD(v26,v71),v52),v72);
    KW[47] = ADD(v73,_mm256_set1_epi32((int)0x106aa070u));
    V v74 = SIG0V(v31);
    V v75 = SIG1V(v70);
    V v76 = ADD(ADD(ADD(v28,v74),v55),v75);
    KW[48] = ADD(v76,_mm256_set1_epi32((int)0x19a4c116u));
    V v77 = SIG0V(v34);
    V v78 = SIG1V(v73);
    V v79 = ADD(ADD(ADD(v31,v77),v58),v78);
    KW[49] = ADD(v79,_mm256_set1_epi32((int)0x1e376c08u));
    V v80 = SIG0V(v37);
    V v81 = SIG1V(v76);
    V v82 = ADD(ADD(ADD(v34,v80),v61),v81);
    KW[50] = ADD(v82,_mm256_set1_epi32((int)0x2748774cu));
    V v83 = SIG0V(v40);
    V v84 = SIG1V(v79);
    V v85 = ADD(ADD(ADD(v37,v83),v64),v84);
    KW[51] = ADD(v85,_mm256_set1_epi32((int)0x34b0bcb5u));
    V v86 = SIG0V(v43);
    V v87 = SIG1V(v82);
    V v88 = ADD(ADD(ADD(v40,v86),v67),v87);
    KW[52] = ADD(v88,_mm256_set1_epi32((int)0x391c0cb3u));
    V v89 = SIG0V(v46);
    V v90 = SIG1V(v85);
    V v91 = ADD(ADD(ADD(v43,v89),v70),v90);
    KW[53] = ADD(v91,_mm256_set1_epi32((int)0x4ed8aa4au));
    V v92 = SIG0V(v49);
    V v93 = SIG1V(v88);
    V v94 = ADD(ADD(ADD(v46,v92),v73),v93);
    KW[54] = ADD(v94,_mm256_set1_epi32((int)0x5b9cca4fu));
    V v95 = SIG0V(v52);
    V v96 = SIG1V(v91);
    V v97 = ADD(ADD(ADD(v49,v95),v76),v96);
    KW[55] = ADD(v97,_mm256_set1_epi32((int)0x682e6ff3u));
    V v98 = SIG0V(v55);
    V v99 = SIG1V(v94);
    V v100 = ADD(ADD(ADD(v52,v98),v79),v99);
    KW[56] = ADD(v100,_mm256_set1_epi32((int)0x748f82eeu));
    V v101 = SIG0V(v58);
    V v102 = SIG1V(v97);
    V v103 = ADD(ADD(ADD(v55,v101),v82),v102);
    KW[57] = ADD(v103,_mm256_set1_epi32((int)0x78a5636fu));
    V v104 = SIG0V(v61);
    V v105 = SIG1V(v100);
    V v106 = ADD(ADD(ADD(v58,v104),v85),v105);
    KW[58] = ADD(v106,_mm256_set1_epi32((int)0x84c87814u));
    V v107 = SIG0V(v64);
    V v108 = SIG1V(v103);
    V v109 = ADD(ADD(ADD(v61,v107),v88),v108);
    KW[59] = ADD(v109,_mm256_set1_epi32((int)0x8cc70208u));
    V v110 = SIG0V(v67);
    V v111 = SIG1V(v106);
    V v112 = ADD(ADD(ADD(v64,v110),v91),v111);
    KW[60] = ADD(v112,_mm256_set1_epi32((int)0x90befffau));
    V v113 = SIG0V(v70);
    V v114 = SIG1V(v109);
    V v115 = ADD(ADD(ADD(v67,v113),v94),v114);
    KW[61] = ADD(v115,_mm256_set1_epi32((int)0xa4506cebu));
    V v116 = SIG0V(v73);
    V v117 = SIG1V(v112);
    V v118 = ADD(ADD(ADD(v70,v116),v97),v117);
    KW[62] = ADD(v118,_mm256_set1_epi32((int)0xbef9a3f7u));
    V v119 = SIG0V(v76);
    V v120 = SIG1V(v115);
    V v121 = ADD(ADD(ADD(v73,v119),v100),v120);
    KW[63] = ADD(v121,_mm256_set1_epi32((int)0xc67178f2u));
}
/* her versiyon icin: kalan turlar */
static inline V hash8v(const uint32_t *c, const VS *vs, const V *KW){
    V a1 = _mm256_set1_epi32((int)vs->st3[0]);
    V b1 = _mm256_set1_epi32((int)vs->st3[1]);
    V c1 = _mm256_set1_epi32((int)vs->st3[2]);
    V d1 = _mm256_set1_epi32((int)vs->st3[3]);
    V e1 = _mm256_set1_epi32((int)vs->st3[4]);
    V f1 = _mm256_set1_epi32((int)vs->st3[5]);
    V g1 = _mm256_set1_epi32((int)vs->st3[6]);
    V h1 = _mm256_set1_epi32((int)vs->st3[7]);
    V bc1 = XOR(b1,c1);
    V t_p3 = ADD(ADD(ADD(h1,BS1V(e1)),CH(e1,f1,g1)),KW[3]);
    d1 = ADD(d1,t_p3);
    V ab_p3 = XOR(a1,b1);
    h1 = ADD(ADD(t_p3,BS0V(a1)),XOR(b1,AND(ab_p3,bc1)));
    V t_p4 = ADD(ADD(ADD(g1,BS1V(d1)),CH(d1,e1,f1)),_mm256_set1_epi32((int)0xb956c25bu));
    c1 = ADD(c1,t_p4);
    V ab_p4 = XOR(h1,a1);
    g1 = ADD(ADD(t_p4,BS0V(h1)),XOR(a1,AND(ab_p4,ab_p3)));
    V t_p5 = ADD(ADD(ADD(f1,BS1V(c1)),CH(c1,d1,e1)),_mm256_set1_epi32((int)0x59f111f1u));
    b1 = ADD(b1,t_p5);
    V ab_p5 = XOR(g1,h1);
    f1 = ADD(ADD(t_p5,BS0V(g1)),XOR(h1,AND(ab_p5,ab_p4)));
    V t_p6 = ADD(ADD(ADD(e1,BS1V(b1)),CH(b1,c1,d1)),_mm256_set1_epi32((int)0x923f82a4u));
    a1 = ADD(a1,t_p6);
    V ab_p6 = XOR(f1,g1);
    e1 = ADD(ADD(t_p6,BS0V(f1)),XOR(g1,AND(ab_p6,ab_p5)));
    V t_p7 = ADD(ADD(ADD(d1,BS1V(a1)),CH(a1,b1,c1)),_mm256_set1_epi32((int)0xab1c5ed5u));
    h1 = ADD(h1,t_p7);
    V ab_p7 = XOR(e1,f1);
    d1 = ADD(ADD(t_p7,BS0V(e1)),XOR(f1,AND(ab_p7,ab_p6)));
    V t_p8 = ADD(ADD(ADD(c1,BS1V(h1)),CH(h1,a1,b1)),_mm256_set1_epi32((int)0xd807aa98u));
    g1 = ADD(g1,t_p8);
    V ab_p8 = XOR(d1,e1);
    c1 = ADD(ADD(t_p8,BS0V(d1)),XOR(e1,AND(ab_p8,ab_p7)));
    V t_p9 = ADD(ADD(ADD(b1,BS1V(g1)),CH(g1,h1,a1)),_mm256_set1_epi32((int)0x12835b01u));
    f1 = ADD(f1,t_p9);
    V ab_p9 = XOR(c1,d1);
    b1 = ADD(ADD(t_p9,BS0V(c1)),XOR(d1,AND(ab_p9,ab_p8)));
    V t_p10 = ADD(ADD(ADD(a1,BS1V(f1)),CH(f1,g1,h1)),_mm256_set1_epi32((int)0x243185beu));
    e1 = ADD(e1,t_p10);
    V ab_p10 = XOR(b1,c1);
    a1 = ADD(ADD(t_p10,BS0V(b1)),XOR(c1,AND(ab_p10,ab_p9)));
    V t_p11 = ADD(ADD(ADD(h1,BS1V(e1)),CH(e1,f1,g1)),_mm256_set1_epi32((int)0x550c7dc3u));
    d1 = ADD(d1,t_p11);
    V ab_p11 = XOR(a1,b1);
    h1 = ADD(ADD(t_p11,BS0V(a1)),XOR(b1,AND(ab_p11,ab_p10)));
    V t_p12 = ADD(ADD(ADD(g1,BS1V(d1)),CH(d1,e1,f1)),_mm256_set1_epi32((int)0x72be5d74u));
    c1 = ADD(c1,t_p12);
    V ab_p12 = XOR(h1,a1);
    g1 = ADD(ADD(t_p12,BS0V(h1)),XOR(a1,AND(ab_p12,ab_p11)));
    V t_p13 = ADD(ADD(ADD(f1,BS1V(c1)),CH(c1,d1,e1)),_mm256_set1_epi32((int)0x80deb1feu));
    b1 = ADD(b1,t_p13);
    V ab_p13 = XOR(g1,h1);
    f1 = ADD(ADD(t_p13,BS0V(g1)),XOR(h1,AND(ab_p13,ab_p12)));
    V t_p14 = ADD(ADD(ADD(e1,BS1V(b1)),CH(b1,c1,d1)),_mm256_set1_epi32((int)0x9bdc06a7u));
    a1 = ADD(a1,t_p14);
    V ab_p14 = XOR(f1,g1);
    e1 = ADD(ADD(t_p14,BS0V(f1)),XOR(g1,AND(ab_p14,ab_p13)));
    V t_p15 = ADD(ADD(ADD(d1,BS1V(a1)),CH(a1,b1,c1)),_mm256_set1_epi32((int)0xc19bf3f4u));
    h1 = ADD(h1,t_p15);
    V ab_p15 = XOR(e1,f1);
    d1 = ADD(ADD(t_p15,BS0V(e1)),XOR(f1,AND(ab_p15,ab_p14)));
    V t_p16 = ADD(ADD(ADD(c1,BS1V(h1)),CH(h1,a1,b1)),_mm256_set1_epi32((int)c[21]));
    g1 = ADD(g1,t_p16);
    V ab_p16 = XOR(d1,e1);
    c1 = ADD(ADD(t_p16,BS0V(d1)),XOR(e1,AND(ab_p16,ab_p15)));
    V t_p17 = ADD(ADD(ADD(b1,BS1V(g1)),CH(g1,h1,a1)),_mm256_set1_epi32((int)c[24]));
    f1 = ADD(f1,t_p17);
    V ab_p17 = XOR(c1,d1);
    b1 = ADD(ADD(t_p17,BS0V(c1)),XOR(d1,AND(ab_p17,ab_p16)));
    V t_p18 = ADD(ADD(ADD(a1,BS1V(f1)),CH(f1,g1,h1)),KW[18]);
    e1 = ADD(e1,t_p18);
    V ab_p18 = XOR(b1,c1);
    a1 = ADD(ADD(t_p18,BS0V(b1)),XOR(c1,AND(ab_p18,ab_p17)));
    V t_p19 = ADD(ADD(ADD(h1,BS1V(e1)),CH(e1,f1,g1)),KW[19]);
    d1 = ADD(d1,t_p19);
    V ab_p19 = XOR(a1,b1);
    h1 = ADD(ADD(t_p19,BS0V(a1)),XOR(b1,AND(ab_p19,ab_p18)));
    V t_p20 = ADD(ADD(ADD(g1,BS1V(d1)),CH(d1,e1,f1)),KW[20]);
    c1 = ADD(c1,t_p20);
    V ab_p20 = XOR(h1,a1);
    g1 = ADD(ADD(t_p20,BS0V(h1)),XOR(a1,AND(ab_p20,ab_p19)));
    V t_p21 = ADD(ADD(ADD(f1,BS1V(c1)),CH(c1,d1,e1)),KW[21]);
    b1 = ADD(b1,t_p21);
    V ab_p21 = XOR(g1,h1);
    f1 = ADD(ADD(t_p21,BS0V(g1)),XOR(h1,AND(ab_p21,ab_p20)));
    V t_p22 = ADD(ADD(ADD(e1,BS1V(b1)),CH(b1,c1,d1)),KW[22]);
    a1 = ADD(a1,t_p22);
    V ab_p22 = XOR(f1,g1);
    e1 = ADD(ADD(t_p22,BS0V(f1)),XOR(g1,AND(ab_p22,ab_p21)));
    V t_p23 = ADD(ADD(ADD(d1,BS1V(a1)),CH(a1,b1,c1)),KW[23]);
    h1 = ADD(h1,t_p23);
    V ab_p23 = XOR(e1,f1);
    d1 = ADD(ADD(t_p23,BS0V(e1)),XOR(f1,AND(ab_p23,ab_p22)));
    V t_p24 = ADD(ADD(ADD(c1,BS1V(h1)),CH(h1,a1,b1)),KW[24]);
    g1 = ADD(g1,t_p24);
    V ab_p24 = XOR(d1,e1);
    c1 = ADD(ADD(t_p24,BS0V(d1)),XOR(e1,AND(ab_p24,ab_p23)));
    V t_p25 = ADD(ADD(ADD(b1,BS1V(g1)),CH(g1,h1,a1)),KW[25]);
    f1 = ADD(f1,t_p25);
    V ab_p25 = XOR(c1,d1);
    b1 = ADD(ADD(t_p25,BS0V(c1)),XOR(d1,AND(ab_p25,ab_p24)));
    V t_p26 = ADD(ADD(ADD(a1,BS1V(f1)),CH(f1,g1,h1)),KW[26]);
    e1 = ADD(e1,t_p26);
    V ab_p26 = XOR(b1,c1);
    a1 = ADD(ADD(t_p26,BS0V(b1)),XOR(c1,AND(ab_p26,ab_p25)));
    V t_p27 = ADD(ADD(ADD(h1,BS1V(e1)),CH(e1,f1,g1)),KW[27]);
    d1 = ADD(d1,t_p27);
    V ab_p27 = XOR(a1,b1);
    h1 = ADD(ADD(t_p27,BS0V(a1)),XOR(b1,AND(ab_p27,ab_p26)));
    V t_p28 = ADD(ADD(ADD(g1,BS1V(d1)),CH(d1,e1,f1)),KW[28]);
    c1 = ADD(c1,t_p28);
    V ab_p28 = XOR(h1,a1);
    g1 = ADD(ADD(t_p28,BS0V(h1)),XOR(a1,AND(ab_p28,ab_p27)));
    V t_p29 = ADD(ADD(ADD(f1,BS1V(c1)),CH(c1,d1,e1)),KW[29]);
    b1 = ADD(b1,t_p29);
    V ab_p29 = XOR(g1,h1);
    f1 = ADD(ADD(t_p29,BS0V(g1)),XOR(h1,AND(ab_p29,ab_p28)));
    V t_p30 = ADD(ADD(ADD(e1,BS1V(b1)),CH(b1,c1,d1)),KW[30]);
    a1 = ADD(a1,t_p30);
    V ab_p30 = XOR(f1,g1);
    e1 = ADD(ADD(t_p30,BS0V(f1)),XOR(g1,AND(ab_p30,ab_p29)));
    V t_p31 = ADD(ADD(ADD(d1,BS1V(a1)),CH(a1,b1,c1)),KW[31]);
    h1 = ADD(h1,t_p31);
    V ab_p31 = XOR(e1,f1);
    d1 = ADD(ADD(t_p31,BS0V(e1)),XOR(f1,AND(ab_p31,ab_p30)));
    V t_p32 = ADD(ADD(ADD(c1,BS1V(h1)),CH(h1,a1,b1)),KW[32]);
    g1 = ADD(g1,t_p32);
    V ab_p32 = XOR(d1,e1);
    c1 = ADD(ADD(t_p32,BS0V(d1)),XOR(e1,AND(ab_p32,ab_p31)));
    V t_p33 = ADD(ADD(ADD(b1,BS1V(g1)),CH(g1,h1,a1)),KW[33]);
    f1 = ADD(f1,t_p33);
    V ab_p33 = XOR(c1,d1);
    b1 = ADD(ADD(t_p33,BS0V(c1)),XOR(d1,AND(ab_p33,ab_p32)));
    V t_p34 = ADD(ADD(ADD(a1,BS1V(f1)),CH(f1,g1,h1)),KW[34]);
    e1 = ADD(e1,t_p34);
    V ab_p34 = XOR(b1,c1);
    a1 = ADD(ADD(t_p34,BS0V(b1)),XOR(c1,AND(ab_p34,ab_p33)));
    V t_p35 = ADD(ADD(ADD(h1,BS1V(e1)),CH(e1,f1,g1)),KW[35]);
    d1 = ADD(d1,t_p35);
    V ab_p35 = XOR(a1,b1);
    h1 = ADD(ADD(t_p35,BS0V(a1)),XOR(b1,AND(ab_p35,ab_p34)));
    V t_p36 = ADD(ADD(ADD(g1,BS1V(d1)),CH(d1,e1,f1)),KW[36]);
    c1 = ADD(c1,t_p36);
    V ab_p36 = XOR(h1,a1);
    g1 = ADD(ADD(t_p36,BS0V(h1)),XOR(a1,AND(ab_p36,ab_p35)));
    V t_p37 = ADD(ADD(ADD(f1,BS1V(c1)),CH(c1,d1,e1)),KW[37]);
    b1 = ADD(b1,t_p37);
    V ab_p37 = XOR(g1,h1);
    f1 = ADD(ADD(t_p37,BS0V(g1)),XOR(h1,AND(ab_p37,ab_p36)));
    V t_p38 = ADD(ADD(ADD(e1,BS1V(b1)),CH(b1,c1,d1)),KW[38]);
    a1 = ADD(a1,t_p38);
    V ab_p38 = XOR(f1,g1);
    e1 = ADD(ADD(t_p38,BS0V(f1)),XOR(g1,AND(ab_p38,ab_p37)));
    V t_p39 = ADD(ADD(ADD(d1,BS1V(a1)),CH(a1,b1,c1)),KW[39]);
    h1 = ADD(h1,t_p39);
    V ab_p39 = XOR(e1,f1);
    d1 = ADD(ADD(t_p39,BS0V(e1)),XOR(f1,AND(ab_p39,ab_p38)));
    V t_p40 = ADD(ADD(ADD(c1,BS1V(h1)),CH(h1,a1,b1)),KW[40]);
    g1 = ADD(g1,t_p40);
    V ab_p40 = XOR(d1,e1);
    c1 = ADD(ADD(t_p40,BS0V(d1)),XOR(e1,AND(ab_p40,ab_p39)));
    V t_p41 = ADD(ADD(ADD(b1,BS1V(g1)),CH(g1,h1,a1)),KW[41]);
    f1 = ADD(f1,t_p41);
    V ab_p41 = XOR(c1,d1);
    b1 = ADD(ADD(t_p41,BS0V(c1)),XOR(d1,AND(ab_p41,ab_p40)));
    V t_p42 = ADD(ADD(ADD(a1,BS1V(f1)),CH(f1,g1,h1)),KW[42]);
    e1 = ADD(e1,t_p42);
    V ab_p42 = XOR(b1,c1);
    a1 = ADD(ADD(t_p42,BS0V(b1)),XOR(c1,AND(ab_p42,ab_p41)));
    V t_p43 = ADD(ADD(ADD(h1,BS1V(e1)),CH(e1,f1,g1)),KW[43]);
    d1 = ADD(d1,t_p43);
    V ab_p43 = XOR(a1,b1);
    h1 = ADD(ADD(t_p43,BS0V(a1)),XOR(b1,AND(ab_p43,ab_p42)));
    V t_p44 = ADD(ADD(ADD(g1,BS1V(d1)),CH(d1,e1,f1)),KW[44]);
    c1 = ADD(c1,t_p44);
    V ab_p44 = XOR(h1,a1);
    g1 = ADD(ADD(t_p44,BS0V(h1)),XOR(a1,AND(ab_p44,ab_p43)));
    V t_p45 = ADD(ADD(ADD(f1,BS1V(c1)),CH(c1,d1,e1)),KW[45]);
    b1 = ADD(b1,t_p45);
    V ab_p45 = XOR(g1,h1);
    f1 = ADD(ADD(t_p45,BS0V(g1)),XOR(h1,AND(ab_p45,ab_p44)));
    V t_p46 = ADD(ADD(ADD(e1,BS1V(b1)),CH(b1,c1,d1)),KW[46]);
    a1 = ADD(a1,t_p46);
    V ab_p46 = XOR(f1,g1);
    e1 = ADD(ADD(t_p46,BS0V(f1)),XOR(g1,AND(ab_p46,ab_p45)));
    V t_p47 = ADD(ADD(ADD(d1,BS1V(a1)),CH(a1,b1,c1)),KW[47]);
    h1 = ADD(h1,t_p47);
    V ab_p47 = XOR(e1,f1);
    d1 = ADD(ADD(t_p47,BS0V(e1)),XOR(f1,AND(ab_p47,ab_p46)));
    V t_p48 = ADD(ADD(ADD(c1,BS1V(h1)),CH(h1,a1,b1)),KW[48]);
    g1 = ADD(g1,t_p48);
    V ab_p48 = XOR(d1,e1);
    c1 = ADD(ADD(t_p48,BS0V(d1)),XOR(e1,AND(ab_p48,ab_p47)));
    V t_p49 = ADD(ADD(ADD(b1,BS1V(g1)),CH(g1,h1,a1)),KW[49]);
    f1 = ADD(f1,t_p49);
    V ab_p49 = XOR(c1,d1);
    b1 = ADD(ADD(t_p49,BS0V(c1)),XOR(d1,AND(ab_p49,ab_p48)));
    V t_p50 = ADD(ADD(ADD(a1,BS1V(f1)),CH(f1,g1,h1)),KW[50]);
    e1 = ADD(e1,t_p50);
    V ab_p50 = XOR(b1,c1);
    a1 = ADD(ADD(t_p50,BS0V(b1)),XOR(c1,AND(ab_p50,ab_p49)));
    V t_p51 = ADD(ADD(ADD(h1,BS1V(e1)),CH(e1,f1,g1)),KW[51]);
    d1 = ADD(d1,t_p51);
    V ab_p51 = XOR(a1,b1);
    h1 = ADD(ADD(t_p51,BS0V(a1)),XOR(b1,AND(ab_p51,ab_p50)));
    V t_p52 = ADD(ADD(ADD(g1,BS1V(d1)),CH(d1,e1,f1)),KW[52]);
    c1 = ADD(c1,t_p52);
    V ab_p52 = XOR(h1,a1);
    g1 = ADD(ADD(t_p52,BS0V(h1)),XOR(a1,AND(ab_p52,ab_p51)));
    V t_p53 = ADD(ADD(ADD(f1,BS1V(c1)),CH(c1,d1,e1)),KW[53]);
    b1 = ADD(b1,t_p53);
    V ab_p53 = XOR(g1,h1);
    f1 = ADD(ADD(t_p53,BS0V(g1)),XOR(h1,AND(ab_p53,ab_p52)));
    V t_p54 = ADD(ADD(ADD(e1,BS1V(b1)),CH(b1,c1,d1)),KW[54]);
    a1 = ADD(a1,t_p54);
    V ab_p54 = XOR(f1,g1);
    e1 = ADD(ADD(t_p54,BS0V(f1)),XOR(g1,AND(ab_p54,ab_p53)));
    V t_p55 = ADD(ADD(ADD(d1,BS1V(a1)),CH(a1,b1,c1)),KW[55]);
    h1 = ADD(h1,t_p55);
    V ab_p55 = XOR(e1,f1);
    d1 = ADD(ADD(t_p55,BS0V(e1)),XOR(f1,AND(ab_p55,ab_p54)));
    V t_p56 = ADD(ADD(ADD(c1,BS1V(h1)),CH(h1,a1,b1)),KW[56]);
    g1 = ADD(g1,t_p56);
    V ab_p56 = XOR(d1,e1);
    c1 = ADD(ADD(t_p56,BS0V(d1)),XOR(e1,AND(ab_p56,ab_p55)));
    V t_p57 = ADD(ADD(ADD(b1,BS1V(g1)),CH(g1,h1,a1)),KW[57]);
    f1 = ADD(f1,t_p57);
    V ab_p57 = XOR(c1,d1);
    b1 = ADD(ADD(t_p57,BS0V(c1)),XOR(d1,AND(ab_p57,ab_p56)));
    V t_p58 = ADD(ADD(ADD(a1,BS1V(f1)),CH(f1,g1,h1)),KW[58]);
    e1 = ADD(e1,t_p58);
    V ab_p58 = XOR(b1,c1);
    a1 = ADD(ADD(t_p58,BS0V(b1)),XOR(c1,AND(ab_p58,ab_p57)));
    V t_p59 = ADD(ADD(ADD(h1,BS1V(e1)),CH(e1,f1,g1)),KW[59]);
    d1 = ADD(d1,t_p59);
    V ab_p59 = XOR(a1,b1);
    h1 = ADD(ADD(t_p59,BS0V(a1)),XOR(b1,AND(ab_p59,ab_p58)));
    V t_p60 = ADD(ADD(ADD(g1,BS1V(d1)),CH(d1,e1,f1)),KW[60]);
    c1 = ADD(c1,t_p60);
    V ab_p60 = XOR(h1,a1);
    g1 = ADD(ADD(t_p60,BS0V(h1)),XOR(a1,AND(ab_p60,ab_p59)));
    V t_p61 = ADD(ADD(ADD(f1,BS1V(c1)),CH(c1,d1,e1)),KW[61]);
    b1 = ADD(b1,t_p61);
    V ab_p61 = XOR(g1,h1);
    f1 = ADD(ADD(t_p61,BS0V(g1)),XOR(h1,AND(ab_p61,ab_p60)));
    V t_p62 = ADD(ADD(ADD(e1,BS1V(b1)),CH(b1,c1,d1)),KW[62]);
    a1 = ADD(a1,t_p62);
    V ab_p62 = XOR(f1,g1);
    e1 = ADD(ADD(t_p62,BS0V(f1)),XOR(g1,AND(ab_p62,ab_p61)));
    V t_p63 = ADD(ADD(ADD(d1,BS1V(a1)),CH(a1,b1,c1)),KW[63]);
    h1 = ADD(h1,t_p63);
    V ab_p63 = XOR(e1,f1);
    d1 = ADD(ADD(t_p63,BS0V(e1)),XOR(f1,AND(ab_p63,ab_p62)));
    V v122 = ADD(d1,_mm256_set1_epi32((int)vs->mid[0]));
    V v123 = ADD(e1,_mm256_set1_epi32((int)vs->mid[1]));
    V v124 = ADD(f1,_mm256_set1_epi32((int)vs->mid[2]));
    V v125 = ADD(g1,_mm256_set1_epi32((int)vs->mid[3]));
    V v126 = ADD(h1,_mm256_set1_epi32((int)vs->mid[4]));
    V v127 = ADD(a1,_mm256_set1_epi32((int)vs->mid[5]));
    V v128 = ADD(b1,_mm256_set1_epi32((int)vs->mid[6]));
    V v129 = ADD(c1,_mm256_set1_epi32((int)vs->mid[7]));
    V t_q0 = ADD(v122,_mm256_set1_epi32((int)0xf377ed68u));
    V a2 = ADD(t_q0,_mm256_set1_epi32((int)0x08909ae5u));
    V e2 = ADD(t_q0,_mm256_set1_epi32((int)0xa54ff53au));
    V b2 = _mm256_set1_epi32((int)0x6a09e667u);
    V c2 = _mm256_set1_epi32((int)0xbb67ae85u);
    V d2 = _mm256_set1_epi32((int)0x3c6ef372u);
    V f2 = _mm256_set1_epi32((int)0x510e527fu);
    V g2 = _mm256_set1_epi32((int)0x9b05688cu);
    V h2 = _mm256_set1_epi32((int)0x1f83d9abu);
    V bc2 = _mm256_set1_epi32((int)0xd16e48e2u);
    V v130 = ADD(v123,_mm256_set1_epi32((int)0x71374491u));
    V t_q1 = ADD(ADD(ADD(h2,BS1V(e2)),CH(e2,f2,g2)),v130);
    d2 = ADD(d2,t_q1);
    V ab_q1 = XOR(a2,b2);
    h2 = ADD(ADD(t_q1,BS0V(a2)),XOR(b2,AND(ab_q1,bc2)));
    V v131 = ADD(v124,_mm256_set1_epi32((int)0xb5c0fbcfu));
    V t_q2 = ADD(ADD(ADD(g2,BS1V(d2)),CH(d2,e2,f2)),v131);
    c2 = ADD(c2,t_q2);
    V ab_q2 = XOR(h2,a2);
    g2 = ADD(ADD(t_q2,BS0V(h2)),XOR(a2,AND(ab_q2,ab_q1)));
    V v132 = ADD(v125,_mm256_set1_epi32((int)0xe9b5dba5u));
    V t_q3 = ADD(ADD(ADD(f2,BS1V(c2)),CH(c2,d2,e2)),v132);
    b2 = ADD(b2,t_q3);
    V ab_q3 = XOR(g2,h2);
    f2 = ADD(ADD(t_q3,BS0V(g2)),XOR(h2,AND(ab_q3,ab_q2)));
    V v133 = ADD(v126,_mm256_set1_epi32((int)0x3956c25bu));
    V t_q4 = ADD(ADD(ADD(e2,BS1V(b2)),CH(b2,c2,d2)),v133);
    a2 = ADD(a2,t_q4);
    V ab_q4 = XOR(f2,g2);
    e2 = ADD(ADD(t_q4,BS0V(f2)),XOR(g2,AND(ab_q4,ab_q3)));
    V v134 = ADD(v127,_mm256_set1_epi32((int)0x59f111f1u));
    V t_q5 = ADD(ADD(ADD(d2,BS1V(a2)),CH(a2,b2,c2)),v134);
    h2 = ADD(h2,t_q5);
    V ab_q5 = XOR(e2,f2);
    d2 = ADD(ADD(t_q5,BS0V(e2)),XOR(f2,AND(ab_q5,ab_q4)));
    V v135 = ADD(v128,_mm256_set1_epi32((int)0x923f82a4u));
    V t_q6 = ADD(ADD(ADD(c2,BS1V(h2)),CH(h2,a2,b2)),v135);
    g2 = ADD(g2,t_q6);
    V ab_q6 = XOR(d2,e2);
    c2 = ADD(ADD(t_q6,BS0V(d2)),XOR(e2,AND(ab_q6,ab_q5)));
    V v136 = ADD(v129,_mm256_set1_epi32((int)0xab1c5ed5u));
    V t_q7 = ADD(ADD(ADD(b2,BS1V(g2)),CH(g2,h2,a2)),v136);
    f2 = ADD(f2,t_q7);
    V ab_q7 = XOR(c2,d2);
    b2 = ADD(ADD(t_q7,BS0V(c2)),XOR(d2,AND(ab_q7,ab_q6)));
    V t_q8 = ADD(ADD(ADD(a2,BS1V(f2)),CH(f2,g2,h2)),_mm256_set1_epi32((int)0x5807aa98u));
    e2 = ADD(e2,t_q8);
    V ab_q8 = XOR(b2,c2);
    a2 = ADD(ADD(t_q8,BS0V(b2)),XOR(c2,AND(ab_q8,ab_q7)));
    V t_q9 = ADD(ADD(ADD(h2,BS1V(e2)),CH(e2,f2,g2)),_mm256_set1_epi32((int)0x12835b01u));
    d2 = ADD(d2,t_q9);
    V ab_q9 = XOR(a2,b2);
    h2 = ADD(ADD(t_q9,BS0V(a2)),XOR(b2,AND(ab_q9,ab_q8)));
    V t_q10 = ADD(ADD(ADD(g2,BS1V(d2)),CH(d2,e2,f2)),_mm256_set1_epi32((int)0x243185beu));
    c2 = ADD(c2,t_q10);
    V ab_q10 = XOR(h2,a2);
    g2 = ADD(ADD(t_q10,BS0V(h2)),XOR(a2,AND(ab_q10,ab_q9)));
    V t_q11 = ADD(ADD(ADD(f2,BS1V(c2)),CH(c2,d2,e2)),_mm256_set1_epi32((int)0x550c7dc3u));
    b2 = ADD(b2,t_q11);
    V ab_q11 = XOR(g2,h2);
    f2 = ADD(ADD(t_q11,BS0V(g2)),XOR(h2,AND(ab_q11,ab_q10)));
    V t_q12 = ADD(ADD(ADD(e2,BS1V(b2)),CH(b2,c2,d2)),_mm256_set1_epi32((int)0x72be5d74u));
    a2 = ADD(a2,t_q12);
    V ab_q12 = XOR(f2,g2);
    e2 = ADD(ADD(t_q12,BS0V(f2)),XOR(g2,AND(ab_q12,ab_q11)));
    V t_q13 = ADD(ADD(ADD(d2,BS1V(a2)),CH(a2,b2,c2)),_mm256_set1_epi32((int)0x80deb1feu));
    h2 = ADD(h2,t_q13);
    V ab_q13 = XOR(e2,f2);
    d2 = ADD(ADD(t_q13,BS0V(e2)),XOR(f2,AND(ab_q13,ab_q12)));
    V t_q14 = ADD(ADD(ADD(c2,BS1V(h2)),CH(h2,a2,b2)),_mm256_set1_epi32((int)0x9bdc06a7u));
    g2 = ADD(g2,t_q14);
    V ab_q14 = XOR(d2,e2);
    c2 = ADD(ADD(t_q14,BS0V(d2)),XOR(e2,AND(ab_q14,ab_q13)));
    V t_q15 = ADD(ADD(ADD(b2,BS1V(g2)),CH(g2,h2,a2)),_mm256_set1_epi32((int)0xc19bf274u));
    f2 = ADD(f2,t_q15);
    V ab_q15 = XOR(c2,d2);
    b2 = ADD(ADD(t_q15,BS0V(c2)),XOR(d2,AND(ab_q15,ab_q14)));
    V v137 = SIG0V(v123);
    V v138 = ADD(v122,v137);
    V v139 = ADD(v138,_mm256_set1_epi32((int)0xe49b69c1u));
    V t_q16 = ADD(ADD(ADD(a2,BS1V(f2)),CH(f2,g2,h2)),v139);
    e2 = ADD(e2,t_q16);
    V ab_q16 = XOR(b2,c2);
    a2 = ADD(ADD(t_q16,BS0V(b2)),XOR(c2,AND(ab_q16,ab_q15)));
    V v140 = SIG0V(v124);
    V v141 = ADD(ADD(v123,v140),_mm256_set1_epi32((int)0x00a00000u));
    V v142 = ADD(v141,_mm256_set1_epi32((int)0xefbe4786u));
    V t_q17 = ADD(ADD(ADD(h2,BS1V(e2)),CH(e2,f2,g2)),v142);
    d2 = ADD(d2,t_q17);
    V ab_q17 = XOR(a2,b2);
    h2 = ADD(ADD(t_q17,BS0V(a2)),XOR(b2,AND(ab_q17,ab_q16)));
    V v143 = SIG0V(v125);
    V v144 = SIG1V(v138);
    V v145 = ADD(ADD(v124,v143),v144);
    V v146 = ADD(v145,_mm256_set1_epi32((int)0x0fc19dc6u));
    V t_q18 = ADD(ADD(ADD(g2,BS1V(d2)),CH(d2,e2,f2)),v146);
    c2 = ADD(c2,t_q18);
    V ab_q18 = XOR(h2,a2);
    g2 = ADD(ADD(t_q18,BS0V(h2)),XOR(a2,AND(ab_q18,ab_q17)));
    V v147 = SIG0V(v126);
    V v148 = SIG1V(v141);
    V v149 = ADD(ADD(v125,v147),v148);
    V v150 = ADD(v149,_mm256_set1_epi32((int)0x240ca1ccu));
    V t_q19 = ADD(ADD(ADD(f2,BS1V(c2)),CH(c2,d2,e2)),v150);
    b2 = ADD(b2,t_q19);
    V ab_q19 = XOR(g2,h2);
    f2 = ADD(ADD(t_q19,BS0V(g2)),XOR(h2,AND(ab_q19,ab_q18)));
    V v151 = SIG0V(v127);
    V v152 = SIG1V(v145);
    V v153 = ADD(ADD(v126,v151),v152);
    V v154 = ADD(v153,_mm256_set1_epi32((int)0x2de92c6fu));
    V t_q20 = ADD(ADD(ADD(e2,BS1V(b2)),CH(b2,c2,d2)),v154);
    a2 = ADD(a2,t_q20);
    V ab_q20 = XOR(f2,g2);
    e2 = ADD(ADD(t_q20,BS0V(f2)),XOR(g2,AND(ab_q20,ab_q19)));
    V v155 = SIG0V(v128);
    V v156 = SIG1V(v149);
    V v157 = ADD(ADD(v127,v155),v156);
    V v158 = ADD(v157,_mm256_set1_epi32((int)0x4a7484aau));
    V t_q21 = ADD(ADD(ADD(d2,BS1V(a2)),CH(a2,b2,c2)),v158);
    h2 = ADD(h2,t_q21);
    V ab_q21 = XOR(e2,f2);
    d2 = ADD(ADD(t_q21,BS0V(e2)),XOR(f2,AND(ab_q21,ab_q20)));
    V v159 = SIG0V(v129);
    V v160 = SIG1V(v153);
    V v161 = ADD(ADD(ADD(v128,v159),v160),_mm256_set1_epi32((int)0x00000100u));
    V v162 = ADD(v161,_mm256_set1_epi32((int)0x5cb0a9dcu));
    V t_q22 = ADD(ADD(ADD(c2,BS1V(h2)),CH(h2,a2,b2)),v162);
    g2 = ADD(g2,t_q22);
    V ab_q22 = XOR(d2,e2);
    c2 = ADD(ADD(t_q22,BS0V(d2)),XOR(e2,AND(ab_q22,ab_q21)));
    V v163 = SIG1V(v157);
    V v164 = ADD(ADD(ADD(v129,v138),v163),_mm256_set1_epi32((int)0x11002000u));
    V v165 = ADD(v164,_mm256_set1_epi32((int)0x76f988dau));
    V t_q23 = ADD(ADD(ADD(b2,BS1V(g2)),CH(g2,h2,a2)),v165);
    f2 = ADD(f2,t_q23);
    V ab_q23 = XOR(c2,d2);
    b2 = ADD(ADD(t_q23,BS0V(c2)),XOR(d2,AND(ab_q23,ab_q22)));
    V v166 = SIG1V(v161);
    V v167 = ADD(ADD(v141,v166),_mm256_set1_epi32((int)0x80000000u));
    V v168 = ADD(v167,_mm256_set1_epi32((int)0x983e5152u));
    V t_q24 = ADD(ADD(ADD(a2,BS1V(f2)),CH(f2,g2,h2)),v168);
    e2 = ADD(e2,t_q24);
    V ab_q24 = XOR(b2,c2);
    a2 = ADD(ADD(t_q24,BS0V(b2)),XOR(c2,AND(ab_q24,ab_q23)));
    V v169 = SIG1V(v164);
    V v170 = ADD(v145,v169);
    V v171 = ADD(v170,_mm256_set1_epi32((int)0xa831c66du));
    V t_q25 = ADD(ADD(ADD(h2,BS1V(e2)),CH(e2,f2,g2)),v171);
    d2 = ADD(d2,t_q25);
    V ab_q25 = XOR(a2,b2);
    h2 = ADD(ADD(t_q25,BS0V(a2)),XOR(b2,AND(ab_q25,ab_q24)));
    V v172 = SIG1V(v167);
    V v173 = ADD(v149,v172);
    V v174 = ADD(v173,_mm256_set1_epi32((int)0xb00327c8u));
    V t_q26 = ADD(ADD(ADD(g2,BS1V(d2)),CH(d2,e2,f2)),v174);
    c2 = ADD(c2,t_q26);
    V ab_q26 = XOR(h2,a2);
    g2 = ADD(ADD(t_q26,BS0V(h2)),XOR(a2,AND(ab_q26,ab_q25)));
    V v175 = SIG1V(v170);
    V v176 = ADD(v153,v175);
    V v177 = ADD(v176,_mm256_set1_epi32((int)0xbf597fc7u));
    V t_q27 = ADD(ADD(ADD(f2,BS1V(c2)),CH(c2,d2,e2)),v177);
    b2 = ADD(b2,t_q27);
    V ab_q27 = XOR(g2,h2);
    f2 = ADD(ADD(t_q27,BS0V(g2)),XOR(h2,AND(ab_q27,ab_q26)));
    V v178 = SIG1V(v173);
    V v179 = ADD(v157,v178);
    V v180 = ADD(v179,_mm256_set1_epi32((int)0xc6e00bf3u));
    V t_q28 = ADD(ADD(ADD(e2,BS1V(b2)),CH(b2,c2,d2)),v180);
    a2 = ADD(a2,t_q28);
    V ab_q28 = XOR(f2,g2);
    e2 = ADD(ADD(t_q28,BS0V(f2)),XOR(g2,AND(ab_q28,ab_q27)));
    V v181 = SIG1V(v176);
    V v182 = ADD(v161,v181);
    V v183 = ADD(v182,_mm256_set1_epi32((int)0xd5a79147u));
    V t_q29 = ADD(ADD(ADD(d2,BS1V(a2)),CH(a2,b2,c2)),v183);
    h2 = ADD(h2,t_q29);
    V ab_q29 = XOR(e2,f2);
    d2 = ADD(ADD(t_q29,BS0V(e2)),XOR(f2,AND(ab_q29,ab_q28)));
    V v184 = SIG1V(v179);
    V v185 = ADD(ADD(v164,v184),_mm256_set1_epi32((int)0x00400022u));
    V v186 = ADD(v185,_mm256_set1_epi32((int)0x06ca6351u));
    V t_q30 = ADD(ADD(ADD(c2,BS1V(h2)),CH(h2,a2,b2)),v186);
    g2 = ADD(g2,t_q30);
    V ab_q30 = XOR(d2,e2);
    c2 = ADD(ADD(t_q30,BS0V(d2)),XOR(e2,AND(ab_q30,ab_q29)));
    V v187 = SIG0V(v138);
    V v188 = SIG1V(v182);
    V v189 = ADD(ADD(ADD(v187,v167),v188),_mm256_set1_epi32((int)0x00000100u));
    V v190 = ADD(v189,_mm256_set1_epi32((int)0x14292967u));
    V t_q31 = ADD(ADD(ADD(b2,BS1V(g2)),CH(g2,h2,a2)),v190);
    f2 = ADD(f2,t_q31);
    V ab_q31 = XOR(c2,d2);
    b2 = ADD(ADD(t_q31,BS0V(c2)),XOR(d2,AND(ab_q31,ab_q30)));
    V v191 = SIG0V(v141);
    V v192 = SIG1V(v185);
    V v193 = ADD(ADD(ADD(v138,v191),v170),v192);
    V v194 = ADD(v193,_mm256_set1_epi32((int)0x27b70a85u));
    V t_q32 = ADD(ADD(ADD(a2,BS1V(f2)),CH(f2,g2,h2)),v194);
    e2 = ADD(e2,t_q32);
    V ab_q32 = XOR(b2,c2);
    a2 = ADD(ADD(t_q32,BS0V(b2)),XOR(c2,AND(ab_q32,ab_q31)));
    V v195 = SIG0V(v145);
    V v196 = SIG1V(v189);
    V v197 = ADD(ADD(ADD(v141,v195),v173),v196);
    V v198 = ADD(v197,_mm256_set1_epi32((int)0x2e1b2138u));
    V t_q33 = ADD(ADD(ADD(h2,BS1V(e2)),CH(e2,f2,g2)),v198);
    d2 = ADD(d2,t_q33);
    V ab_q33 = XOR(a2,b2);
    h2 = ADD(ADD(t_q33,BS0V(a2)),XOR(b2,AND(ab_q33,ab_q32)));
    V v199 = SIG0V(v149);
    V v200 = SIG1V(v193);
    V v201 = ADD(ADD(ADD(v145,v199),v176),v200);
    V v202 = ADD(v201,_mm256_set1_epi32((int)0x4d2c6dfcu));
    V t_q34 = ADD(ADD(ADD(g2,BS1V(d2)),CH(d2,e2,f2)),v202);
    c2 = ADD(c2,t_q34);
    V ab_q34 = XOR(h2,a2);
    g2 = ADD(ADD(t_q34,BS0V(h2)),XOR(a2,AND(ab_q34,ab_q33)));
    V v203 = SIG0V(v153);
    V v204 = SIG1V(v197);
    V v205 = ADD(ADD(ADD(v149,v203),v179),v204);
    V v206 = ADD(v205,_mm256_set1_epi32((int)0x53380d13u));
    V t_q35 = ADD(ADD(ADD(f2,BS1V(c2)),CH(c2,d2,e2)),v206);
    b2 = ADD(b2,t_q35);
    V ab_q35 = XOR(g2,h2);
    f2 = ADD(ADD(t_q35,BS0V(g2)),XOR(h2,AND(ab_q35,ab_q34)));
    V v207 = SIG0V(v157);
    V v208 = SIG1V(v201);
    V v209 = ADD(ADD(ADD(v153,v207),v182),v208);
    V v210 = ADD(v209,_mm256_set1_epi32((int)0x650a7354u));
    V t_q36 = ADD(ADD(ADD(e2,BS1V(b2)),CH(b2,c2,d2)),v210);
    a2 = ADD(a2,t_q36);
    V ab_q36 = XOR(f2,g2);
    e2 = ADD(ADD(t_q36,BS0V(f2)),XOR(g2,AND(ab_q36,ab_q35)));
    V v211 = SIG0V(v161);
    V v212 = SIG1V(v205);
    V v213 = ADD(ADD(ADD(v157,v211),v185),v212);
    V v214 = ADD(v213,_mm256_set1_epi32((int)0x766a0abbu));
    V t_q37 = ADD(ADD(ADD(d2,BS1V(a2)),CH(a2,b2,c2)),v214);
    h2 = ADD(h2,t_q37);
    V ab_q37 = XOR(e2,f2);
    d2 = ADD(ADD(t_q37,BS0V(e2)),XOR(f2,AND(ab_q37,ab_q36)));
    V v215 = SIG0V(v164);
    V v216 = SIG1V(v209);
    V v217 = ADD(ADD(ADD(v161,v215),v189),v216);
    V v218 = ADD(v217,_mm256_set1_epi32((int)0x81c2c92eu));
    V t_q38 = ADD(ADD(ADD(c2,BS1V(h2)),CH(h2,a2,b2)),v218);
    g2 = ADD(g2,t_q38);
    V ab_q38 = XOR(d2,e2);
    c2 = ADD(ADD(t_q38,BS0V(d2)),XOR(e2,AND(ab_q38,ab_q37)));
    V v219 = SIG0V(v167);
    V v220 = SIG1V(v213);
    V v221 = ADD(ADD(ADD(v164,v219),v193),v220);
    V v222 = ADD(v221,_mm256_set1_epi32((int)0x92722c85u));
    V t_q39 = ADD(ADD(ADD(b2,BS1V(g2)),CH(g2,h2,a2)),v222);
    f2 = ADD(f2,t_q39);
    V ab_q39 = XOR(c2,d2);
    b2 = ADD(ADD(t_q39,BS0V(c2)),XOR(d2,AND(ab_q39,ab_q38)));
    V v223 = SIG0V(v170);
    V v224 = SIG1V(v217);
    V v225 = ADD(ADD(ADD(v167,v223),v197),v224);
    V v226 = ADD(v225,_mm256_set1_epi32((int)0xa2bfe8a1u));
    V t_q40 = ADD(ADD(ADD(a2,BS1V(f2)),CH(f2,g2,h2)),v226);
    e2 = ADD(e2,t_q40);
    V ab_q40 = XOR(b2,c2);
    a2 = ADD(ADD(t_q40,BS0V(b2)),XOR(c2,AND(ab_q40,ab_q39)));
    V v227 = SIG0V(v173);
    V v228 = SIG1V(v221);
    V v229 = ADD(ADD(ADD(v170,v227),v201),v228);
    V v230 = ADD(v229,_mm256_set1_epi32((int)0xa81a664bu));
    V t_q41 = ADD(ADD(ADD(h2,BS1V(e2)),CH(e2,f2,g2)),v230);
    d2 = ADD(d2,t_q41);
    V ab_q41 = XOR(a2,b2);
    h2 = ADD(ADD(t_q41,BS0V(a2)),XOR(b2,AND(ab_q41,ab_q40)));
    V v231 = SIG0V(v176);
    V v232 = SIG1V(v225);
    V v233 = ADD(ADD(ADD(v173,v231),v205),v232);
    V v234 = ADD(v233,_mm256_set1_epi32((int)0xc24b8b70u));
    V t_q42 = ADD(ADD(ADD(g2,BS1V(d2)),CH(d2,e2,f2)),v234);
    c2 = ADD(c2,t_q42);
    V ab_q42 = XOR(h2,a2);
    g2 = ADD(ADD(t_q42,BS0V(h2)),XOR(a2,AND(ab_q42,ab_q41)));
    V v235 = SIG0V(v179);
    V v236 = SIG1V(v229);
    V v237 = ADD(ADD(ADD(v176,v235),v209),v236);
    V v238 = ADD(v237,_mm256_set1_epi32((int)0xc76c51a3u));
    V t_q43 = ADD(ADD(ADD(f2,BS1V(c2)),CH(c2,d2,e2)),v238);
    b2 = ADD(b2,t_q43);
    V ab_q43 = XOR(g2,h2);
    f2 = ADD(ADD(t_q43,BS0V(g2)),XOR(h2,AND(ab_q43,ab_q42)));
    V v239 = SIG0V(v182);
    V v240 = SIG1V(v233);
    V v241 = ADD(ADD(ADD(v179,v239),v213),v240);
    V v242 = ADD(v241,_mm256_set1_epi32((int)0xd192e819u));
    V t_q44 = ADD(ADD(ADD(e2,BS1V(b2)),CH(b2,c2,d2)),v242);
    a2 = ADD(a2,t_q44);
    V ab_q44 = XOR(f2,g2);
    e2 = ADD(ADD(t_q44,BS0V(f2)),XOR(g2,AND(ab_q44,ab_q43)));
    V v243 = SIG0V(v185);
    V v244 = SIG1V(v237);
    V v245 = ADD(ADD(ADD(v182,v243),v217),v244);
    V v246 = ADD(v245,_mm256_set1_epi32((int)0xd6990624u));
    V t_q45 = ADD(ADD(ADD(d2,BS1V(a2)),CH(a2,b2,c2)),v246);
    h2 = ADD(h2,t_q45);
    V ab_q45 = XOR(e2,f2);
    d2 = ADD(ADD(t_q45,BS0V(e2)),XOR(f2,AND(ab_q45,ab_q44)));
    V v247 = SIG0V(v189);
    V v248 = SIG1V(v241);
    V v249 = ADD(ADD(ADD(v185,v247),v221),v248);
    V v250 = ADD(v249,_mm256_set1_epi32((int)0xf40e3585u));
    V t_q46 = ADD(ADD(ADD(c2,BS1V(h2)),CH(h2,a2,b2)),v250);
    g2 = ADD(g2,t_q46);
    V ab_q46 = XOR(d2,e2);
    c2 = ADD(ADD(t_q46,BS0V(d2)),XOR(e2,AND(ab_q46,ab_q45)));
    V v251 = SIG0V(v193);
    V v252 = SIG1V(v245);
    V v253 = ADD(ADD(ADD(v189,v251),v225),v252);
    V v254 = ADD(v253,_mm256_set1_epi32((int)0x106aa070u));
    V t_q47 = ADD(ADD(ADD(b2,BS1V(g2)),CH(g2,h2,a2)),v254);
    f2 = ADD(f2,t_q47);
    V ab_q47 = XOR(c2,d2);
    b2 = ADD(ADD(t_q47,BS0V(c2)),XOR(d2,AND(ab_q47,ab_q46)));
    V v255 = SIG0V(v197);
    V v256 = SIG1V(v249);
    V v257 = ADD(ADD(ADD(v193,v255),v229),v256);
    V v258 = ADD(v257,_mm256_set1_epi32((int)0x19a4c116u));
    V t_q48 = ADD(ADD(ADD(a2,BS1V(f2)),CH(f2,g2,h2)),v258);
    e2 = ADD(e2,t_q48);
    V ab_q48 = XOR(b2,c2);
    a2 = ADD(ADD(t_q48,BS0V(b2)),XOR(c2,AND(ab_q48,ab_q47)));
    V v259 = SIG0V(v201);
    V v260 = SIG1V(v253);
    V v261 = ADD(ADD(ADD(v197,v259),v233),v260);
    V v262 = ADD(v261,_mm256_set1_epi32((int)0x1e376c08u));
    V t_q49 = ADD(ADD(ADD(h2,BS1V(e2)),CH(e2,f2,g2)),v262);
    d2 = ADD(d2,t_q49);
    V ab_q49 = XOR(a2,b2);
    h2 = ADD(ADD(t_q49,BS0V(a2)),XOR(b2,AND(ab_q49,ab_q48)));
    V v263 = SIG0V(v205);
    V v264 = SIG1V(v257);
    V v265 = ADD(ADD(ADD(v201,v263),v237),v264);
    V v266 = ADD(v265,_mm256_set1_epi32((int)0x2748774cu));
    V t_q50 = ADD(ADD(ADD(g2,BS1V(d2)),CH(d2,e2,f2)),v266);
    c2 = ADD(c2,t_q50);
    V ab_q50 = XOR(h2,a2);
    g2 = ADD(ADD(t_q50,BS0V(h2)),XOR(a2,AND(ab_q50,ab_q49)));
    V v267 = SIG0V(v209);
    V v268 = SIG1V(v261);
    V v269 = ADD(ADD(ADD(v205,v267),v241),v268);
    V v270 = ADD(v269,_mm256_set1_epi32((int)0x34b0bcb5u));
    V t_q51 = ADD(ADD(ADD(f2,BS1V(c2)),CH(c2,d2,e2)),v270);
    b2 = ADD(b2,t_q51);
    V ab_q51 = XOR(g2,h2);
    f2 = ADD(ADD(t_q51,BS0V(g2)),XOR(h2,AND(ab_q51,ab_q50)));
    V v271 = SIG0V(v213);
    V v272 = SIG1V(v265);
    V v273 = ADD(ADD(ADD(v209,v271),v245),v272);
    V v274 = ADD(v273,_mm256_set1_epi32((int)0x391c0cb3u));
    V t_q52 = ADD(ADD(ADD(e2,BS1V(b2)),CH(b2,c2,d2)),v274);
    a2 = ADD(a2,t_q52);
    V ab_q52 = XOR(f2,g2);
    e2 = ADD(ADD(t_q52,BS0V(f2)),XOR(g2,AND(ab_q52,ab_q51)));
    V v275 = SIG0V(v217);
    V v276 = SIG1V(v269);
    V v277 = ADD(ADD(ADD(v213,v275),v249),v276);
    V v278 = ADD(v277,_mm256_set1_epi32((int)0x4ed8aa4au));
    V t_q53 = ADD(ADD(ADD(d2,BS1V(a2)),CH(a2,b2,c2)),v278);
    h2 = ADD(h2,t_q53);
    V ab_q53 = XOR(e2,f2);
    d2 = ADD(ADD(t_q53,BS0V(e2)),XOR(f2,AND(ab_q53,ab_q52)));
    V v279 = SIG0V(v221);
    V v280 = SIG1V(v273);
    V v281 = ADD(ADD(ADD(v217,v279),v253),v280);
    V v282 = ADD(v281,_mm256_set1_epi32((int)0x5b9cca4fu));
    V t_q54 = ADD(ADD(ADD(c2,BS1V(h2)),CH(h2,a2,b2)),v282);
    g2 = ADD(g2,t_q54);
    V ab_q54 = XOR(d2,e2);
    c2 = ADD(ADD(t_q54,BS0V(d2)),XOR(e2,AND(ab_q54,ab_q53)));
    V v283 = SIG0V(v225);
    V v284 = SIG1V(v277);
    V v285 = ADD(ADD(ADD(v221,v283),v257),v284);
    V v286 = ADD(v285,_mm256_set1_epi32((int)0x682e6ff3u));
    V t_q55 = ADD(ADD(ADD(b2,BS1V(g2)),CH(g2,h2,a2)),v286);
    f2 = ADD(f2,t_q55);
    V ab_q55 = XOR(c2,d2);
    b2 = ADD(ADD(t_q55,BS0V(c2)),XOR(d2,AND(ab_q55,ab_q54)));
    V v287 = SIG0V(v229);
    V v288 = SIG1V(v281);
    V v289 = ADD(ADD(ADD(v225,v287),v261),v288);
    V v290 = ADD(v289,_mm256_set1_epi32((int)0x748f82eeu));
    V t_q56 = ADD(ADD(ADD(a2,BS1V(f2)),CH(f2,g2,h2)),v290);
    e2 = ADD(e2,t_q56);
    V ab_q56 = XOR(b2,c2);
    a2 = ADD(ADD(t_q56,BS0V(b2)),XOR(c2,AND(ab_q56,ab_q55)));
    V v291 = SIG0V(v233);
    V v292 = SIG1V(v285);
    V v293 = ADD(ADD(ADD(v229,v291),v265),v292);
    V v294 = ADD(v293,_mm256_set1_epi32((int)0x78a5636fu));
    V t_q57 = ADD(ADD(ADD(h2,BS1V(e2)),CH(e2,f2,g2)),v294);
    d2 = ADD(d2,t_q57);
    V v295 = SIG0V(v237);
    V v296 = SIG1V(v289);
    V v297 = ADD(ADD(ADD(v233,v295),v269),v296);
    V v298 = ADD(v297,_mm256_set1_epi32((int)0x84c87814u));
    V t_q58 = ADD(ADD(ADD(g2,BS1V(d2)),CH(d2,e2,f2)),v298);
    c2 = ADD(c2,t_q58);
    V v299 = SIG0V(v241);
    V v300 = SIG1V(v293);
    V v301 = ADD(ADD(ADD(v237,v299),v273),v300);
    V v302 = ADD(v301,_mm256_set1_epi32((int)0x8cc70208u));
    V t_q59 = ADD(ADD(ADD(f2,BS1V(c2)),CH(c2,d2,e2)),v302);
    b2 = ADD(b2,t_q59);
    V v303 = SIG0V(v245);
    V v304 = SIG1V(v297);
    V v305 = ADD(ADD(ADD(v241,v303),v277),v304);
    V v306 = ADD(v305,_mm256_set1_epi32((int)0x90befffau));
    V t_q60 = ADD(ADD(ADD(e2,BS1V(b2)),CH(b2,c2,d2)),v306);
    a2 = ADD(a2,t_q60);
    return ADD(a2,_mm256_set1_epi32((int)0x5be0cd19u));
}

static uint32_t deposit(uint32_t j,uint32_t mask){ uint32_t r=0; for(uint32_t bit=1;bit&&mask&&j;bit<<=1) if(mask&bit){ if(j&1) r|=bit; j>>=1; } return r; }
static int setup_versions(const uint8_t *hdr,uint32_t mask,int M,uint8_t hdrv[][76],uint32_t *ver){
  uint32_t base=(uint32_t)hdr[0]|((uint32_t)hdr[1]<<8)|((uint32_t)hdr[2]<<16)|((uint32_t)hdr[3]<<24);
  int pc=__builtin_popcount(mask); int maxm=pc>=6?64:(1<<pc); if(M<1)M=1; if(M>maxm)M=maxm; if(M>MAXM)M=MAXM; if(!mask)M=1;
  for(int j=0;j<M;j++){
    uint32_t v=(M==1&&!mask)?base:((base&~mask)|deposit((uint32_t)j,mask)); ver[j]=v;
    memcpy(hdrv[j],hdr,76); hdrv[j][0]=v&255;hdrv[j][1]=(v>>8)&255;hdrv[j][2]=(v>>16)&255;hdrv[j][3]=v>>24;
  }
  return M;
}

static uint64_t scan(const uint8_t *hdr, uint32_t start, uint64_t count, uint32_t mask, int M){
  uint32_t c[NC]; uint8_t hdrv[MAXM][76]; uint32_t ver[MAXM]; VS vs[MAXM];
  M=setup_versions(hdr,mask,M,hdrv,ver);
  prepare_shared(hdr,c); for(int j=0;j<M;j++) prepare_ver(hdrv[j],&vs[j]);
  const V bsw=_mm256_setr_epi8(3,2,1,0,7,6,5,4,11,10,9,8,15,14,13,12,3,2,1,0,7,6,5,4,11,10,9,8,15,14,13,12);
  const V zero=_mm256_setzero_si256(), step=_mm256_set1_epi32(8);
  V nv=ADD(_mm256_set1_epi32((int)start),_mm256_setr_epi32(0,1,2,3,4,5,6,7)); V KW[64];
  uint64_t hits=0;
  for(uint64_t base=0;base<count;base+=8){
    sched8(c,_mm256_shuffle_epi8(nv,bsw),KW);
    for(int j=0;j<M;j++){
      V h7=hash8v(c,&vs[j],KW);
#ifdef LOOSE
      h7=SHR(h7,20);
#endif
      int mk=_mm256_movemask_ps(_mm256_castsi256_ps(_mm256_cmpeq_epi32(h7,zero)));
      if(mk) for(int lane=0;lane<8;lane++) if(((mk>>lane)&1) && base+(uint64_t)lane<count){
        uint32_t nonce=start+(uint32_t)(base+(uint64_t)lane), s[8];
        scalar_hash(hdrv[j],nonce,s);
#ifdef LOOSE
        if((s[7]>>20)!=0){ fprintf(stderr,"UYUSMAZLIK nonce=%u v=%08x\n",nonce,ver[j]); continue; }
#else
        if(s[7]!=0){ fprintf(stderr,"UYUSMAZLIK nonce=%u v=%08x\n",nonce,ver[j]); continue; }
#endif
        printf("%u %08x ",nonce,nonce);
        for(int k=7;k>=0;k--){uint32_t x=s[k];printf("%02x%02x%02x%02x",x&255,(x>>8)&255,(x>>16)&255,x>>24);}
        printf(" %08x\n",ver[j]);hits++;
      }
    }
    nv=ADD(nv,step);
  }
  return hits;
}

/* tam dogrulama: her nonce ve her versiyon icin h7'yi skaler referansla karsilastirir */
static int selftest(void){
  uint64_t x=88172645463325252ULL; long checked=0, bad=0;
  for(int trial=0;trial<6;trial++){
    uint8_t hdr[76]; for(int i=0;i<76;i++){x^=x<<13;x^=x>>7;x^=x<<17;hdr[i]=(uint8_t)x;}
    uint32_t mask=0x1fffe000u, start=(uint32_t)x; int M=(trial%2)?16:8;
    uint32_t c[NC]; uint8_t hdrv[MAXM][76]; uint32_t ver[MAXM]; VS vs[MAXM];
    M=setup_versions(hdr,mask,M,hdrv,ver); prepare_shared(hdr,c); for(int j=0;j<M;j++) prepare_ver(hdrv[j],&vs[j]);
    const V bsw=_mm256_setr_epi8(3,2,1,0,7,6,5,4,11,10,9,8,15,14,13,12,3,2,1,0,7,6,5,4,11,10,9,8,15,14,13,12); V KW[64];
    for(uint32_t base=0;base<4096;base+=8){
      uint32_t ns[8]; for(int l=0;l<8;l++) ns[l]=start+base+l;
      sched8(c,_mm256_shuffle_epi8(_mm256_loadu_si256((const V*)ns),bsw),KW);
      for(int j=0;j<M;j++){
        uint32_t out[8]; _mm256_storeu_si256((V*)out,hash8v(c,&vs[j],KW));
        for(int l=0;l<8;l++){ uint32_t s[8]; scalar_hash(hdrv[j],ns[l],s); checked++; if(s[7]!=out[l]) bad++; }
      }
    }
  }
  /* versiyon degisince header (ve hash) gercekten degisiyor mu? */
  uint8_t h0[76]={0}; uint8_t h1[76]={0}; h1[1]=0x20; uint32_t s0[8],s1[8]; scalar_hash(h0,5,s0); scalar_hash(h1,5,s1);
  if(!memcmp(s0,s1,32)) bad++;
  if(bad){ printf("TEST FAIL checked=%ld bad=%ld\n",checked,bad); return 1; }
  printf("TEST OK checked=%ld\n",checked); return 0;
}

int main(int argc,char**argv){
  if(argc>=2&&!strcmp(argv[1],"--info")){ printf("sha256d_scan v4 asicboost\n"); return 0; }
  if(argc>=2&&!strcmp(argv[1],"--test")) return selftest();
  if(argc>=2&&!strcmp(argv[1],"--bench")){
    int M=argc>=3?atoi(argv[2]):16; uint8_t h[76];memset(h,1,sizeof h);
    uint64_t N=(M>1?40000000ULL/M:40000000ULL); struct timespec a,b;
    clock_gettime(CLOCK_MONOTONIC,&a);scan(h,0,N,M>1?0x1fffe000u:0,M);clock_gettime(CLOCK_MONOTONIC,&b);
    double t=(b.tv_sec-a.tv_sec)+(b.tv_nsec-a.tv_nsec)/1e9; if(M<1)M=1;
    fprintf(stderr,"v4 AVX2 M=%d: %.2f MH/s (tek thread)\n",M,N*(double)M/t/1e6);return 0;}
  if(argc<4){fprintf(stderr,"kullanim: %s <header76hex> <start> <count> [mask_hex M]\n",argv[0]);return 1;}
  if(strlen(argv[1])!=152){fprintf(stderr,"header 152 hex karakter olmali\n");return 1;}
  uint8_t h[76];for(int i=0;i<76;i++){int a=hexv(argv[1][2*i]),b=hexv(argv[1][2*i+1]);if(a<0||b<0){fprintf(stderr,"gecersiz hex\n");return 1;}h[i]=(uint8_t)((a<<4)|b);}
  uint32_t mask=argc>=6?(uint32_t)strtoul(argv[4],NULL,16):0; int M=argc>=6?atoi(argv[5]):1;
  scan(h,(uint32_t)strtoul(argv[2],NULL,10),strtoull(argv[3],NULL,10),mask,M);return 0;}
