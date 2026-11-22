/* avx2-solo-miner: sha256d_scan v5 - cok motorlu Bitcoin header nonce tarayici
 *
 * Motorlar (calisma aninda islemciye gore secilir):
 *   avx512    AVX-512 (16 serit, vprord + vpternlog)
 *   avx512vl  AVX-512VL (8 serit ymm, vprord + vpternlog)
 *   shani     Intel SHA uzantilari (sha256rnds2), birden cok akis ic ice
 *   avx2      AVX2 (8 serit)
 *   scalar    yedek (her islemcide calisir, yavas)
 * Hepsi overt AsicBoost (BIP 310/320 version rolling) destekler: 2. blok mesaj genisletmesi surumler arasinda paylasilir.
 *
 * Derle (ek bayrak gerekmez):  gcc -O3 -o sha256d_scan sha256d_scan.c
 * Kullanim: sha256d_scan <76 bayt header hex> <start_nonce> <count> [version_mask_hex M]
 *           sha256d_scan --info | --test | --tune | --bench [M [motor]]
 * Motor secimi: ortam degiskeni SHA256D_ENGINE=<ad> (yoksa otomatik varsayilan)
 * Cikti: "nonce_dec nonce_hex hash_display_hex version_hex"  (>=32 sifir bitli hash'ler)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <immintrin.h>
#include <cpuid.h>
#define ROR32(x,n) (((x)>>(n))|((x)<<(32-(n))))
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
static uint32_t bswap32(uint32_t n){return ((n&0xff)<<24)|((n&0xff00)<<8)|((n>>8)&0xff00)|(n>>24);}
static int hexv(char c){ if(c>='0'&&c<='9')return c-'0'; c=(char)(c|32); return c>='a'&&c<='f'?c-'a'+10:-1; }
static void scalar_hash(const uint8_t*hdr,uint32_t nonce,uint32_t out[8]){
  uint32_t mid[8],blk[16],blk2[16]={0},i;
  memcpy(mid,IV,32);{uint32_t b0[16];for(i=0;i<16;i++)b0[i]=be32(hdr+4*i);compress(mid,b0);}
  blk[0]=be32(hdr+64);blk[1]=be32(hdr+68);blk[2]=be32(hdr+72);blk[3]=bswap32(nonce);
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
/* aday isabet: skaler referansla tam dogrula ve yazdir. 1 = gecerli */
static int report_hit(const uint8_t *hdrv, uint32_t nonce, uint32_t ver){
  uint32_t s[8]; scalar_hash(hdrv,nonce,s);
  if(s[7]!=0){ fprintf(stderr,"UYUSMAZLIK nonce=%u v=%08x\n",nonce,ver); return 0; }
  printf("%u %08x ",nonce,nonce);
  for(int k=7;k>=0;k--){uint32_t x=s[k];printf("%02x%02x%02x%02x",x&255,(x>>8)&255,(x>>16)&255,x>>24);}
  printf(" %08x\n",ver); return 1;
}

/* ===== motor scalar (yedek) ===== */
static uint64_t scan_scalar(const uint8_t *hdr, uint32_t start, uint64_t count, uint32_t mask, int M){
  uint8_t hdrv[MAXM][76]; uint32_t ver[MAXM]; uint64_t hits=0;
  M=setup_versions(hdr,mask,M,hdrv,ver);
  for(uint64_t b=0;b<count;b++) for(int j=0;j<M;j++){
    uint32_t s[8]; uint32_t n=start+(uint32_t)b; scalar_hash(hdrv[j],n,s);
    if(s[7]==0) hits+=report_hit(hdrv[j],n,ver[j]);
  }
  return hits;
}
static int test_scalar(void){ printf("scalar: OK (referans)\n"); return 0; }


/* ===== motor avx2 (8 serit) ===== */
#pragma GCC push_options
#pragma GCC target("avx2")
#define V __m256i
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
#define SET1(x) _mm256_set1_epi32(x)
#define BSWAP(x) _mm256_shuffle_epi8(x,_mm256_setr_epi8(3,2,1,0,7,6,5,4,11,10,9,8,15,14,13,12,3,2,1,0,7,6,5,4,11,10,9,8,15,14,13,12))
#define LANEIDX _mm256_setr_epi32(0,1,2,3,4,5,6,7)
#define LOADU(p) _mm256_loadu_si256((const __m256i*)(p))
#define STOREU(p,x) _mm256_storeu_si256((__m256i*)(p),x)
#define CMPZ(x) ((unsigned)_mm256_movemask_ps(_mm256_castsi256_ps(_mm256_cmpeq_epi32(x,_mm256_setzero_si256()))))
static inline void sched_avx2(const uint32_t *c, V nonce, V *KW){
    V nonce_w3 = nonce;
    KW[3] = ADD(nonce_w3,SET1((int)0xe9b5dba5u));
    V v0 = SIG0V(nonce_w3);
    V v1 = ADD(v0,SET1((int)c[26]));
    KW[18] = ADD(v1,SET1((int)0x0fc19dc6u));
    V v2 = ADD(nonce_w3,SET1((int)c[28]));
    KW[19] = ADD(v2,SET1((int)0x240ca1ccu));
    V v3 = SIG1V(v1);
    V v4 = ADD(v3,SET1((int)0x80000000u));
    KW[20] = ADD(v4,SET1((int)0x2de92c6fu));
    V v5 = SIG1V(v2);
    V v6 = v5;
    KW[21] = ADD(v6,SET1((int)0x4a7484aau));
    V v7 = SIG1V(v4);
    V v8 = ADD(v7,SET1((int)0x00000280u));
    KW[22] = ADD(v8,SET1((int)0x5cb0a9dcu));
    V v9 = SIG1V(v6);
    V v10 = ADD(v9,SET1((int)c[20]));
    KW[23] = ADD(v10,SET1((int)0x76f988dau));
    V v11 = SIG1V(v8);
    V v12 = ADD(v11,SET1((int)c[23]));
    KW[24] = ADD(v12,SET1((int)0x983e5152u));
    V v13 = SIG1V(v10);
    V v14 = ADD(v1,v13);
    KW[25] = ADD(v14,SET1((int)0xa831c66du));
    V v15 = SIG1V(v12);
    V v16 = ADD(v2,v15);
    KW[26] = ADD(v16,SET1((int)0xb00327c8u));
    V v17 = SIG1V(v14);
    V v18 = ADD(v4,v17);
    KW[27] = ADD(v18,SET1((int)0xbf597fc7u));
    V v19 = SIG1V(v16);
    V v20 = ADD(v6,v19);
    KW[28] = ADD(v20,SET1((int)0xc6e00bf3u));
    V v21 = SIG1V(v18);
    V v22 = ADD(v8,v21);
    KW[29] = ADD(v22,SET1((int)0xd5a79147u));
    V v23 = SIG1V(v20);
    V v24 = ADD(ADD(v10,v23),SET1((int)0x00a00055u));
    KW[30] = ADD(v24,SET1((int)0x06ca6351u));
    V v25 = SIG1V(v22);
    V v26 = ADD(ADD(v12,v25),SET1((int)c[30]));
    KW[31] = ADD(v26,SET1((int)0x14292967u));
    V v27 = SIG1V(v24);
    V v28 = ADD(ADD(v14,v27),SET1((int)c[32]));
    KW[32] = ADD(v28,SET1((int)0x27b70a85u));
    V v29 = SIG0V(v1);
    V v30 = SIG1V(v26);
    V v31 = ADD(ADD(ADD(v29,v16),v30),SET1((int)c[23]));
    KW[33] = ADD(v31,SET1((int)0x2e1b2138u));
    V v32 = SIG0V(v2);
    V v33 = SIG1V(v28);
    V v34 = ADD(ADD(ADD(v1,v32),v18),v33);
    KW[34] = ADD(v34,SET1((int)0x4d2c6dfcu));
    V v35 = SIG0V(v4);
    V v36 = SIG1V(v31);
    V v37 = ADD(ADD(ADD(v2,v35),v20),v36);
    KW[35] = ADD(v37,SET1((int)0x53380d13u));
    V v38 = SIG0V(v6);
    V v39 = SIG1V(v34);
    V v40 = ADD(ADD(ADD(v4,v38),v22),v39);
    KW[36] = ADD(v40,SET1((int)0x650a7354u));
    V v41 = SIG0V(v8);
    V v42 = SIG1V(v37);
    V v43 = ADD(ADD(ADD(v6,v41),v24),v42);
    KW[37] = ADD(v43,SET1((int)0x766a0abbu));
    V v44 = SIG0V(v10);
    V v45 = SIG1V(v40);
    V v46 = ADD(ADD(ADD(v8,v44),v26),v45);
    KW[38] = ADD(v46,SET1((int)0x81c2c92eu));
    V v47 = SIG0V(v12);
    V v48 = SIG1V(v43);
    V v49 = ADD(ADD(ADD(v10,v47),v28),v48);
    KW[39] = ADD(v49,SET1((int)0x92722c85u));
    V v50 = SIG0V(v14);
    V v51 = SIG1V(v46);
    V v52 = ADD(ADD(ADD(v12,v50),v31),v51);
    KW[40] = ADD(v52,SET1((int)0xa2bfe8a1u));
    V v53 = SIG0V(v16);
    V v54 = SIG1V(v49);
    V v55 = ADD(ADD(ADD(v14,v53),v34),v54);
    KW[41] = ADD(v55,SET1((int)0xa81a664bu));
    V v56 = SIG0V(v18);
    V v57 = SIG1V(v52);
    V v58 = ADD(ADD(ADD(v16,v56),v37),v57);
    KW[42] = ADD(v58,SET1((int)0xc24b8b70u));
    V v59 = SIG0V(v20);
    V v60 = SIG1V(v55);
    V v61 = ADD(ADD(ADD(v18,v59),v40),v60);
    KW[43] = ADD(v61,SET1((int)0xc76c51a3u));
    V v62 = SIG0V(v22);
    V v63 = SIG1V(v58);
    V v64 = ADD(ADD(ADD(v20,v62),v43),v63);
    KW[44] = ADD(v64,SET1((int)0xd192e819u));
    V v65 = SIG0V(v24);
    V v66 = SIG1V(v61);
    V v67 = ADD(ADD(ADD(v22,v65),v46),v66);
    KW[45] = ADD(v67,SET1((int)0xd6990624u));
    V v68 = SIG0V(v26);
    V v69 = SIG1V(v64);
    V v70 = ADD(ADD(ADD(v24,v68),v49),v69);
    KW[46] = ADD(v70,SET1((int)0xf40e3585u));
    V v71 = SIG0V(v28);
    V v72 = SIG1V(v67);
    V v73 = ADD(ADD(ADD(v26,v71),v52),v72);
    KW[47] = ADD(v73,SET1((int)0x106aa070u));
    V v74 = SIG0V(v31);
    V v75 = SIG1V(v70);
    V v76 = ADD(ADD(ADD(v28,v74),v55),v75);
    KW[48] = ADD(v76,SET1((int)0x19a4c116u));
    V v77 = SIG0V(v34);
    V v78 = SIG1V(v73);
    V v79 = ADD(ADD(ADD(v31,v77),v58),v78);
    KW[49] = ADD(v79,SET1((int)0x1e376c08u));
    V v80 = SIG0V(v37);
    V v81 = SIG1V(v76);
    V v82 = ADD(ADD(ADD(v34,v80),v61),v81);
    KW[50] = ADD(v82,SET1((int)0x2748774cu));
    V v83 = SIG0V(v40);
    V v84 = SIG1V(v79);
    V v85 = ADD(ADD(ADD(v37,v83),v64),v84);
    KW[51] = ADD(v85,SET1((int)0x34b0bcb5u));
    V v86 = SIG0V(v43);
    V v87 = SIG1V(v82);
    V v88 = ADD(ADD(ADD(v40,v86),v67),v87);
    KW[52] = ADD(v88,SET1((int)0x391c0cb3u));
    V v89 = SIG0V(v46);
    V v90 = SIG1V(v85);
    V v91 = ADD(ADD(ADD(v43,v89),v70),v90);
    KW[53] = ADD(v91,SET1((int)0x4ed8aa4au));
    V v92 = SIG0V(v49);
    V v93 = SIG1V(v88);
    V v94 = ADD(ADD(ADD(v46,v92),v73),v93);
    KW[54] = ADD(v94,SET1((int)0x5b9cca4fu));
    V v95 = SIG0V(v52);
    V v96 = SIG1V(v91);
    V v97 = ADD(ADD(ADD(v49,v95),v76),v96);
    KW[55] = ADD(v97,SET1((int)0x682e6ff3u));
    V v98 = SIG0V(v55);
    V v99 = SIG1V(v94);
    V v100 = ADD(ADD(ADD(v52,v98),v79),v99);
    KW[56] = ADD(v100,SET1((int)0x748f82eeu));
    V v101 = SIG0V(v58);
    V v102 = SIG1V(v97);
    V v103 = ADD(ADD(ADD(v55,v101),v82),v102);
    KW[57] = ADD(v103,SET1((int)0x78a5636fu));
    V v104 = SIG0V(v61);
    V v105 = SIG1V(v100);
    V v106 = ADD(ADD(ADD(v58,v104),v85),v105);
    KW[58] = ADD(v106,SET1((int)0x84c87814u));
    V v107 = SIG0V(v64);
    V v108 = SIG1V(v103);
    V v109 = ADD(ADD(ADD(v61,v107),v88),v108);
    KW[59] = ADD(v109,SET1((int)0x8cc70208u));
    V v110 = SIG0V(v67);
    V v111 = SIG1V(v106);
    V v112 = ADD(ADD(ADD(v64,v110),v91),v111);
    KW[60] = ADD(v112,SET1((int)0x90befffau));
    V v113 = SIG0V(v70);
    V v114 = SIG1V(v109);
    V v115 = ADD(ADD(ADD(v67,v113),v94),v114);
    KW[61] = ADD(v115,SET1((int)0xa4506cebu));
    V v116 = SIG0V(v73);
    V v117 = SIG1V(v112);
    V v118 = ADD(ADD(ADD(v70,v116),v97),v117);
    KW[62] = ADD(v118,SET1((int)0xbef9a3f7u));
    V v119 = SIG0V(v76);
    V v120 = SIG1V(v115);
    V v121 = ADD(ADD(ADD(v73,v119),v100),v120);
    KW[63] = ADD(v121,SET1((int)0xc67178f2u));
}
static inline V hash_avx2(const uint32_t *c, const VS *vs, const V *KW){
    V a1 = SET1((int)vs->st3[0]);
    V b1 = SET1((int)vs->st3[1]);
    V c1 = SET1((int)vs->st3[2]);
    V d1 = SET1((int)vs->st3[3]);
    V e1 = SET1((int)vs->st3[4]);
    V f1 = SET1((int)vs->st3[5]);
    V g1 = SET1((int)vs->st3[6]);
    V h1 = SET1((int)vs->st3[7]);
    V bc1 = XOR(b1,c1);
    V t_p3 = ADD(ADD(ADD(h1,BS1V(e1)),CH(e1,f1,g1)),KW[3]);
    d1 = ADD(d1,t_p3);
    V ab_p3 = XOR(a1,b1);
    h1 = ADD(ADD(t_p3,BS0V(a1)),XOR(b1,AND(ab_p3,bc1)));
    V t_p4 = ADD(ADD(ADD(g1,BS1V(d1)),CH(d1,e1,f1)),SET1((int)0xb956c25bu));
    c1 = ADD(c1,t_p4);
    V ab_p4 = XOR(h1,a1);
    g1 = ADD(ADD(t_p4,BS0V(h1)),XOR(a1,AND(ab_p4,ab_p3)));
    V t_p5 = ADD(ADD(ADD(f1,BS1V(c1)),CH(c1,d1,e1)),SET1((int)0x59f111f1u));
    b1 = ADD(b1,t_p5);
    V ab_p5 = XOR(g1,h1);
    f1 = ADD(ADD(t_p5,BS0V(g1)),XOR(h1,AND(ab_p5,ab_p4)));
    V t_p6 = ADD(ADD(ADD(e1,BS1V(b1)),CH(b1,c1,d1)),SET1((int)0x923f82a4u));
    a1 = ADD(a1,t_p6);
    V ab_p6 = XOR(f1,g1);
    e1 = ADD(ADD(t_p6,BS0V(f1)),XOR(g1,AND(ab_p6,ab_p5)));
    V t_p7 = ADD(ADD(ADD(d1,BS1V(a1)),CH(a1,b1,c1)),SET1((int)0xab1c5ed5u));
    h1 = ADD(h1,t_p7);
    V ab_p7 = XOR(e1,f1);
    d1 = ADD(ADD(t_p7,BS0V(e1)),XOR(f1,AND(ab_p7,ab_p6)));
    V t_p8 = ADD(ADD(ADD(c1,BS1V(h1)),CH(h1,a1,b1)),SET1((int)0xd807aa98u));
    g1 = ADD(g1,t_p8);
    V ab_p8 = XOR(d1,e1);
    c1 = ADD(ADD(t_p8,BS0V(d1)),XOR(e1,AND(ab_p8,ab_p7)));
    V t_p9 = ADD(ADD(ADD(b1,BS1V(g1)),CH(g1,h1,a1)),SET1((int)0x12835b01u));
    f1 = ADD(f1,t_p9);
    V ab_p9 = XOR(c1,d1);
    b1 = ADD(ADD(t_p9,BS0V(c1)),XOR(d1,AND(ab_p9,ab_p8)));
    V t_p10 = ADD(ADD(ADD(a1,BS1V(f1)),CH(f1,g1,h1)),SET1((int)0x243185beu));
    e1 = ADD(e1,t_p10);
    V ab_p10 = XOR(b1,c1);
    a1 = ADD(ADD(t_p10,BS0V(b1)),XOR(c1,AND(ab_p10,ab_p9)));
    V t_p11 = ADD(ADD(ADD(h1,BS1V(e1)),CH(e1,f1,g1)),SET1((int)0x550c7dc3u));
    d1 = ADD(d1,t_p11);
    V ab_p11 = XOR(a1,b1);
    h1 = ADD(ADD(t_p11,BS0V(a1)),XOR(b1,AND(ab_p11,ab_p10)));
    V t_p12 = ADD(ADD(ADD(g1,BS1V(d1)),CH(d1,e1,f1)),SET1((int)0x72be5d74u));
    c1 = ADD(c1,t_p12);
    V ab_p12 = XOR(h1,a1);
    g1 = ADD(ADD(t_p12,BS0V(h1)),XOR(a1,AND(ab_p12,ab_p11)));
    V t_p13 = ADD(ADD(ADD(f1,BS1V(c1)),CH(c1,d1,e1)),SET1((int)0x80deb1feu));
    b1 = ADD(b1,t_p13);
    V ab_p13 = XOR(g1,h1);
    f1 = ADD(ADD(t_p13,BS0V(g1)),XOR(h1,AND(ab_p13,ab_p12)));
    V t_p14 = ADD(ADD(ADD(e1,BS1V(b1)),CH(b1,c1,d1)),SET1((int)0x9bdc06a7u));
    a1 = ADD(a1,t_p14);
    V ab_p14 = XOR(f1,g1);
    e1 = ADD(ADD(t_p14,BS0V(f1)),XOR(g1,AND(ab_p14,ab_p13)));
    V t_p15 = ADD(ADD(ADD(d1,BS1V(a1)),CH(a1,b1,c1)),SET1((int)0xc19bf3f4u));
    h1 = ADD(h1,t_p15);
    V ab_p15 = XOR(e1,f1);
    d1 = ADD(ADD(t_p15,BS0V(e1)),XOR(f1,AND(ab_p15,ab_p14)));
    V t_p16 = ADD(ADD(ADD(c1,BS1V(h1)),CH(h1,a1,b1)),SET1((int)c[21]));
    g1 = ADD(g1,t_p16);
    V ab_p16 = XOR(d1,e1);
    c1 = ADD(ADD(t_p16,BS0V(d1)),XOR(e1,AND(ab_p16,ab_p15)));
    V t_p17 = ADD(ADD(ADD(b1,BS1V(g1)),CH(g1,h1,a1)),SET1((int)c[24]));
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
    V v122 = ADD(d1,SET1((int)vs->mid[0]));
    V v123 = ADD(e1,SET1((int)vs->mid[1]));
    V v124 = ADD(f1,SET1((int)vs->mid[2]));
    V v125 = ADD(g1,SET1((int)vs->mid[3]));
    V v126 = ADD(h1,SET1((int)vs->mid[4]));
    V v127 = ADD(a1,SET1((int)vs->mid[5]));
    V v128 = ADD(b1,SET1((int)vs->mid[6]));
    V v129 = ADD(c1,SET1((int)vs->mid[7]));
    V t_q0 = ADD(v122,SET1((int)0xf377ed68u));
    V a2 = ADD(t_q0,SET1((int)0x08909ae5u));
    V e2 = ADD(t_q0,SET1((int)0xa54ff53au));
    V b2 = SET1((int)0x6a09e667u);
    V c2 = SET1((int)0xbb67ae85u);
    V d2 = SET1((int)0x3c6ef372u);
    V f2 = SET1((int)0x510e527fu);
    V g2 = SET1((int)0x9b05688cu);
    V h2 = SET1((int)0x1f83d9abu);
    V bc2 = SET1((int)0xd16e48e2u);
    V v130 = ADD(v123,SET1((int)0x71374491u));
    V t_q1 = ADD(ADD(ADD(h2,BS1V(e2)),CH(e2,f2,g2)),v130);
    d2 = ADD(d2,t_q1);
    V ab_q1 = XOR(a2,b2);
    h2 = ADD(ADD(t_q1,BS0V(a2)),XOR(b2,AND(ab_q1,bc2)));
    V v131 = ADD(v124,SET1((int)0xb5c0fbcfu));
    V t_q2 = ADD(ADD(ADD(g2,BS1V(d2)),CH(d2,e2,f2)),v131);
    c2 = ADD(c2,t_q2);
    V ab_q2 = XOR(h2,a2);
    g2 = ADD(ADD(t_q2,BS0V(h2)),XOR(a2,AND(ab_q2,ab_q1)));
    V v132 = ADD(v125,SET1((int)0xe9b5dba5u));
    V t_q3 = ADD(ADD(ADD(f2,BS1V(c2)),CH(c2,d2,e2)),v132);
    b2 = ADD(b2,t_q3);
    V ab_q3 = XOR(g2,h2);
    f2 = ADD(ADD(t_q3,BS0V(g2)),XOR(h2,AND(ab_q3,ab_q2)));
    V v133 = ADD(v126,SET1((int)0x3956c25bu));
    V t_q4 = ADD(ADD(ADD(e2,BS1V(b2)),CH(b2,c2,d2)),v133);
    a2 = ADD(a2,t_q4);
    V ab_q4 = XOR(f2,g2);
    e2 = ADD(ADD(t_q4,BS0V(f2)),XOR(g2,AND(ab_q4,ab_q3)));
    V v134 = ADD(v127,SET1((int)0x59f111f1u));
    V t_q5 = ADD(ADD(ADD(d2,BS1V(a2)),CH(a2,b2,c2)),v134);
    h2 = ADD(h2,t_q5);
    V ab_q5 = XOR(e2,f2);
    d2 = ADD(ADD(t_q5,BS0V(e2)),XOR(f2,AND(ab_q5,ab_q4)));
    V v135 = ADD(v128,SET1((int)0x923f82a4u));
    V t_q6 = ADD(ADD(ADD(c2,BS1V(h2)),CH(h2,a2,b2)),v135);
    g2 = ADD(g2,t_q6);
    V ab_q6 = XOR(d2,e2);
    c2 = ADD(ADD(t_q6,BS0V(d2)),XOR(e2,AND(ab_q6,ab_q5)));
    V v136 = ADD(v129,SET1((int)0xab1c5ed5u));
    V t_q7 = ADD(ADD(ADD(b2,BS1V(g2)),CH(g2,h2,a2)),v136);
    f2 = ADD(f2,t_q7);
    V ab_q7 = XOR(c2,d2);
    b2 = ADD(ADD(t_q7,BS0V(c2)),XOR(d2,AND(ab_q7,ab_q6)));
    V t_q8 = ADD(ADD(ADD(a2,BS1V(f2)),CH(f2,g2,h2)),SET1((int)0x5807aa98u));
    e2 = ADD(e2,t_q8);
    V ab_q8 = XOR(b2,c2);
    a2 = ADD(ADD(t_q8,BS0V(b2)),XOR(c2,AND(ab_q8,ab_q7)));
    V t_q9 = ADD(ADD(ADD(h2,BS1V(e2)),CH(e2,f2,g2)),SET1((int)0x12835b01u));
    d2 = ADD(d2,t_q9);
    V ab_q9 = XOR(a2,b2);
    h2 = ADD(ADD(t_q9,BS0V(a2)),XOR(b2,AND(ab_q9,ab_q8)));
    V t_q10 = ADD(ADD(ADD(g2,BS1V(d2)),CH(d2,e2,f2)),SET1((int)0x243185beu));
    c2 = ADD(c2,t_q10);
    V ab_q10 = XOR(h2,a2);
    g2 = ADD(ADD(t_q10,BS0V(h2)),XOR(a2,AND(ab_q10,ab_q9)));
    V t_q11 = ADD(ADD(ADD(f2,BS1V(c2)),CH(c2,d2,e2)),SET1((int)0x550c7dc3u));
    b2 = ADD(b2,t_q11);
    V ab_q11 = XOR(g2,h2);
    f2 = ADD(ADD(t_q11,BS0V(g2)),XOR(h2,AND(ab_q11,ab_q10)));
    V t_q12 = ADD(ADD(ADD(e2,BS1V(b2)),CH(b2,c2,d2)),SET1((int)0x72be5d74u));
    a2 = ADD(a2,t_q12);
    V ab_q12 = XOR(f2,g2);
    e2 = ADD(ADD(t_q12,BS0V(f2)),XOR(g2,AND(ab_q12,ab_q11)));
    V t_q13 = ADD(ADD(ADD(d2,BS1V(a2)),CH(a2,b2,c2)),SET1((int)0x80deb1feu));
    h2 = ADD(h2,t_q13);
    V ab_q13 = XOR(e2,f2);
    d2 = ADD(ADD(t_q13,BS0V(e2)),XOR(f2,AND(ab_q13,ab_q12)));
    V t_q14 = ADD(ADD(ADD(c2,BS1V(h2)),CH(h2,a2,b2)),SET1((int)0x9bdc06a7u));
    g2 = ADD(g2,t_q14);
    V ab_q14 = XOR(d2,e2);
    c2 = ADD(ADD(t_q14,BS0V(d2)),XOR(e2,AND(ab_q14,ab_q13)));
    V t_q15 = ADD(ADD(ADD(b2,BS1V(g2)),CH(g2,h2,a2)),SET1((int)0xc19bf274u));
    f2 = ADD(f2,t_q15);
    V ab_q15 = XOR(c2,d2);
    b2 = ADD(ADD(t_q15,BS0V(c2)),XOR(d2,AND(ab_q15,ab_q14)));
    V v137 = SIG0V(v123);
    V v138 = ADD(v122,v137);
    V v139 = ADD(v138,SET1((int)0xe49b69c1u));
    V t_q16 = ADD(ADD(ADD(a2,BS1V(f2)),CH(f2,g2,h2)),v139);
    e2 = ADD(e2,t_q16);
    V ab_q16 = XOR(b2,c2);
    a2 = ADD(ADD(t_q16,BS0V(b2)),XOR(c2,AND(ab_q16,ab_q15)));
    V v140 = SIG0V(v124);
    V v141 = ADD(ADD(v123,v140),SET1((int)0x00a00000u));
    V v142 = ADD(v141,SET1((int)0xefbe4786u));
    V t_q17 = ADD(ADD(ADD(h2,BS1V(e2)),CH(e2,f2,g2)),v142);
    d2 = ADD(d2,t_q17);
    V ab_q17 = XOR(a2,b2);
    h2 = ADD(ADD(t_q17,BS0V(a2)),XOR(b2,AND(ab_q17,ab_q16)));
    V v143 = SIG0V(v125);
    V v144 = SIG1V(v138);
    V v145 = ADD(ADD(v124,v143),v144);
    V v146 = ADD(v145,SET1((int)0x0fc19dc6u));
    V t_q18 = ADD(ADD(ADD(g2,BS1V(d2)),CH(d2,e2,f2)),v146);
    c2 = ADD(c2,t_q18);
    V ab_q18 = XOR(h2,a2);
    g2 = ADD(ADD(t_q18,BS0V(h2)),XOR(a2,AND(ab_q18,ab_q17)));
    V v147 = SIG0V(v126);
    V v148 = SIG1V(v141);
    V v149 = ADD(ADD(v125,v147),v148);
    V v150 = ADD(v149,SET1((int)0x240ca1ccu));
    V t_q19 = ADD(ADD(ADD(f2,BS1V(c2)),CH(c2,d2,e2)),v150);
    b2 = ADD(b2,t_q19);
    V ab_q19 = XOR(g2,h2);
    f2 = ADD(ADD(t_q19,BS0V(g2)),XOR(h2,AND(ab_q19,ab_q18)));
    V v151 = SIG0V(v127);
    V v152 = SIG1V(v145);
    V v153 = ADD(ADD(v126,v151),v152);
    V v154 = ADD(v153,SET1((int)0x2de92c6fu));
    V t_q20 = ADD(ADD(ADD(e2,BS1V(b2)),CH(b2,c2,d2)),v154);
    a2 = ADD(a2,t_q20);
    V ab_q20 = XOR(f2,g2);
    e2 = ADD(ADD(t_q20,BS0V(f2)),XOR(g2,AND(ab_q20,ab_q19)));
    V v155 = SIG0V(v128);
    V v156 = SIG1V(v149);
    V v157 = ADD(ADD(v127,v155),v156);
    V v158 = ADD(v157,SET1((int)0x4a7484aau));
    V t_q21 = ADD(ADD(ADD(d2,BS1V(a2)),CH(a2,b2,c2)),v158);
    h2 = ADD(h2,t_q21);
    V ab_q21 = XOR(e2,f2);
    d2 = ADD(ADD(t_q21,BS0V(e2)),XOR(f2,AND(ab_q21,ab_q20)));
    V v159 = SIG0V(v129);
    V v160 = SIG1V(v153);
    V v161 = ADD(ADD(ADD(v128,v159),v160),SET1((int)0x00000100u));
    V v162 = ADD(v161,SET1((int)0x5cb0a9dcu));
    V t_q22 = ADD(ADD(ADD(c2,BS1V(h2)),CH(h2,a2,b2)),v162);
    g2 = ADD(g2,t_q22);
    V ab_q22 = XOR(d2,e2);
    c2 = ADD(ADD(t_q22,BS0V(d2)),XOR(e2,AND(ab_q22,ab_q21)));
    V v163 = SIG1V(v157);
    V v164 = ADD(ADD(ADD(v129,v138),v163),SET1((int)0x11002000u));
    V v165 = ADD(v164,SET1((int)0x76f988dau));
    V t_q23 = ADD(ADD(ADD(b2,BS1V(g2)),CH(g2,h2,a2)),v165);
    f2 = ADD(f2,t_q23);
    V ab_q23 = XOR(c2,d2);
    b2 = ADD(ADD(t_q23,BS0V(c2)),XOR(d2,AND(ab_q23,ab_q22)));
    V v166 = SIG1V(v161);
    V v167 = ADD(ADD(v141,v166),SET1((int)0x80000000u));
    V v168 = ADD(v167,SET1((int)0x983e5152u));
    V t_q24 = ADD(ADD(ADD(a2,BS1V(f2)),CH(f2,g2,h2)),v168);
    e2 = ADD(e2,t_q24);
    V ab_q24 = XOR(b2,c2);
    a2 = ADD(ADD(t_q24,BS0V(b2)),XOR(c2,AND(ab_q24,ab_q23)));
    V v169 = SIG1V(v164);
    V v170 = ADD(v145,v169);
    V v171 = ADD(v170,SET1((int)0xa831c66du));
    V t_q25 = ADD(ADD(ADD(h2,BS1V(e2)),CH(e2,f2,g2)),v171);
    d2 = ADD(d2,t_q25);
    V ab_q25 = XOR(a2,b2);
    h2 = ADD(ADD(t_q25,BS0V(a2)),XOR(b2,AND(ab_q25,ab_q24)));
    V v172 = SIG1V(v167);
    V v173 = ADD(v149,v172);
    V v174 = ADD(v173,SET1((int)0xb00327c8u));
    V t_q26 = ADD(ADD(ADD(g2,BS1V(d2)),CH(d2,e2,f2)),v174);
    c2 = ADD(c2,t_q26);
    V ab_q26 = XOR(h2,a2);
    g2 = ADD(ADD(t_q26,BS0V(h2)),XOR(a2,AND(ab_q26,ab_q25)));
    V v175 = SIG1V(v170);
    V v176 = ADD(v153,v175);
    V v177 = ADD(v176,SET1((int)0xbf597fc7u));
    V t_q27 = ADD(ADD(ADD(f2,BS1V(c2)),CH(c2,d2,e2)),v177);
    b2 = ADD(b2,t_q27);
    V ab_q27 = XOR(g2,h2);
    f2 = ADD(ADD(t_q27,BS0V(g2)),XOR(h2,AND(ab_q27,ab_q26)));
    V v178 = SIG1V(v173);
    V v179 = ADD(v157,v178);
    V v180 = ADD(v179,SET1((int)0xc6e00bf3u));
    V t_q28 = ADD(ADD(ADD(e2,BS1V(b2)),CH(b2,c2,d2)),v180);
    a2 = ADD(a2,t_q28);
    V ab_q28 = XOR(f2,g2);
    e2 = ADD(ADD(t_q28,BS0V(f2)),XOR(g2,AND(ab_q28,ab_q27)));
    V v181 = SIG1V(v176);
    V v182 = ADD(v161,v181);
    V v183 = ADD(v182,SET1((int)0xd5a79147u));
    V t_q29 = ADD(ADD(ADD(d2,BS1V(a2)),CH(a2,b2,c2)),v183);
    h2 = ADD(h2,t_q29);
    V ab_q29 = XOR(e2,f2);
    d2 = ADD(ADD(t_q29,BS0V(e2)),XOR(f2,AND(ab_q29,ab_q28)));
    V v184 = SIG1V(v179);
    V v185 = ADD(ADD(v164,v184),SET1((int)0x00400022u));
    V v186 = ADD(v185,SET1((int)0x06ca6351u));
    V t_q30 = ADD(ADD(ADD(c2,BS1V(h2)),CH(h2,a2,b2)),v186);
    g2 = ADD(g2,t_q30);
    V ab_q30 = XOR(d2,e2);
    c2 = ADD(ADD(t_q30,BS0V(d2)),XOR(e2,AND(ab_q30,ab_q29)));
    V v187 = SIG0V(v138);
    V v188 = SIG1V(v182);
    V v189 = ADD(ADD(ADD(v187,v167),v188),SET1((int)0x00000100u));
    V v190 = ADD(v189,SET1((int)0x14292967u));
    V t_q31 = ADD(ADD(ADD(b2,BS1V(g2)),CH(g2,h2,a2)),v190);
    f2 = ADD(f2,t_q31);
    V ab_q31 = XOR(c2,d2);
    b2 = ADD(ADD(t_q31,BS0V(c2)),XOR(d2,AND(ab_q31,ab_q30)));
    V v191 = SIG0V(v141);
    V v192 = SIG1V(v185);
    V v193 = ADD(ADD(ADD(v138,v191),v170),v192);
    V v194 = ADD(v193,SET1((int)0x27b70a85u));
    V t_q32 = ADD(ADD(ADD(a2,BS1V(f2)),CH(f2,g2,h2)),v194);
    e2 = ADD(e2,t_q32);
    V ab_q32 = XOR(b2,c2);
    a2 = ADD(ADD(t_q32,BS0V(b2)),XOR(c2,AND(ab_q32,ab_q31)));
    V v195 = SIG0V(v145);
    V v196 = SIG1V(v189);
    V v197 = ADD(ADD(ADD(v141,v195),v173),v196);
    V v198 = ADD(v197,SET1((int)0x2e1b2138u));
    V t_q33 = ADD(ADD(ADD(h2,BS1V(e2)),CH(e2,f2,g2)),v198);
    d2 = ADD(d2,t_q33);
    V ab_q33 = XOR(a2,b2);
    h2 = ADD(ADD(t_q33,BS0V(a2)),XOR(b2,AND(ab_q33,ab_q32)));
    V v199 = SIG0V(v149);
    V v200 = SIG1V(v193);
    V v201 = ADD(ADD(ADD(v145,v199),v176),v200);
    V v202 = ADD(v201,SET1((int)0x4d2c6dfcu));
    V t_q34 = ADD(ADD(ADD(g2,BS1V(d2)),CH(d2,e2,f2)),v202);
    c2 = ADD(c2,t_q34);
    V ab_q34 = XOR(h2,a2);
    g2 = ADD(ADD(t_q34,BS0V(h2)),XOR(a2,AND(ab_q34,ab_q33)));
    V v203 = SIG0V(v153);
    V v204 = SIG1V(v197);
    V v205 = ADD(ADD(ADD(v149,v203),v179),v204);
    V v206 = ADD(v205,SET1((int)0x53380d13u));
    V t_q35 = ADD(ADD(ADD(f2,BS1V(c2)),CH(c2,d2,e2)),v206);
    b2 = ADD(b2,t_q35);
    V ab_q35 = XOR(g2,h2);
    f2 = ADD(ADD(t_q35,BS0V(g2)),XOR(h2,AND(ab_q35,ab_q34)));
    V v207 = SIG0V(v157);
    V v208 = SIG1V(v201);
    V v209 = ADD(ADD(ADD(v153,v207),v182),v208);
    V v210 = ADD(v209,SET1((int)0x650a7354u));
    V t_q36 = ADD(ADD(ADD(e2,BS1V(b2)),CH(b2,c2,d2)),v210);
    a2 = ADD(a2,t_q36);
    V ab_q36 = XOR(f2,g2);
    e2 = ADD(ADD(t_q36,BS0V(f2)),XOR(g2,AND(ab_q36,ab_q35)));
    V v211 = SIG0V(v161);
    V v212 = SIG1V(v205);
    V v213 = ADD(ADD(ADD(v157,v211),v185),v212);
    V v214 = ADD(v213,SET1((int)0x766a0abbu));
    V t_q37 = ADD(ADD(ADD(d2,BS1V(a2)),CH(a2,b2,c2)),v214);
    h2 = ADD(h2,t_q37);
    V ab_q37 = XOR(e2,f2);
    d2 = ADD(ADD(t_q37,BS0V(e2)),XOR(f2,AND(ab_q37,ab_q36)));
    V v215 = SIG0V(v164);
    V v216 = SIG1V(v209);
    V v217 = ADD(ADD(ADD(v161,v215),v189),v216);
    V v218 = ADD(v217,SET1((int)0x81c2c92eu));
    V t_q38 = ADD(ADD(ADD(c2,BS1V(h2)),CH(h2,a2,b2)),v218);
    g2 = ADD(g2,t_q38);
    V ab_q38 = XOR(d2,e2);
    c2 = ADD(ADD(t_q38,BS0V(d2)),XOR(e2,AND(ab_q38,ab_q37)));
    V v219 = SIG0V(v167);
    V v220 = SIG1V(v213);
    V v221 = ADD(ADD(ADD(v164,v219),v193),v220);
    V v222 = ADD(v221,SET1((int)0x92722c85u));
    V t_q39 = ADD(ADD(ADD(b2,BS1V(g2)),CH(g2,h2,a2)),v222);
    f2 = ADD(f2,t_q39);
    V ab_q39 = XOR(c2,d2);
    b2 = ADD(ADD(t_q39,BS0V(c2)),XOR(d2,AND(ab_q39,ab_q38)));
    V v223 = SIG0V(v170);
    V v224 = SIG1V(v217);
    V v225 = ADD(ADD(ADD(v167,v223),v197),v224);
    V v226 = ADD(v225,SET1((int)0xa2bfe8a1u));
    V t_q40 = ADD(ADD(ADD(a2,BS1V(f2)),CH(f2,g2,h2)),v226);
    e2 = ADD(e2,t_q40);
    V ab_q40 = XOR(b2,c2);
    a2 = ADD(ADD(t_q40,BS0V(b2)),XOR(c2,AND(ab_q40,ab_q39)));
    V v227 = SIG0V(v173);
    V v228 = SIG1V(v221);
    V v229 = ADD(ADD(ADD(v170,v227),v201),v228);
    V v230 = ADD(v229,SET1((int)0xa81a664bu));
    V t_q41 = ADD(ADD(ADD(h2,BS1V(e2)),CH(e2,f2,g2)),v230);
    d2 = ADD(d2,t_q41);
    V ab_q41 = XOR(a2,b2);
    h2 = ADD(ADD(t_q41,BS0V(a2)),XOR(b2,AND(ab_q41,ab_q40)));
    V v231 = SIG0V(v176);
    V v232 = SIG1V(v225);
    V v233 = ADD(ADD(ADD(v173,v231),v205),v232);
    V v234 = ADD(v233,SET1((int)0xc24b8b70u));
    V t_q42 = ADD(ADD(ADD(g2,BS1V(d2)),CH(d2,e2,f2)),v234);
    c2 = ADD(c2,t_q42);
    V ab_q42 = XOR(h2,a2);
    g2 = ADD(ADD(t_q42,BS0V(h2)),XOR(a2,AND(ab_q42,ab_q41)));
    V v235 = SIG0V(v179);
    V v236 = SIG1V(v229);
    V v237 = ADD(ADD(ADD(v176,v235),v209),v236);
    V v238 = ADD(v237,SET1((int)0xc76c51a3u));
    V t_q43 = ADD(ADD(ADD(f2,BS1V(c2)),CH(c2,d2,e2)),v238);
    b2 = ADD(b2,t_q43);
    V ab_q43 = XOR(g2,h2);
    f2 = ADD(ADD(t_q43,BS0V(g2)),XOR(h2,AND(ab_q43,ab_q42)));
    V v239 = SIG0V(v182);
    V v240 = SIG1V(v233);
    V v241 = ADD(ADD(ADD(v179,v239),v213),v240);
    V v242 = ADD(v241,SET1((int)0xd192e819u));
    V t_q44 = ADD(ADD(ADD(e2,BS1V(b2)),CH(b2,c2,d2)),v242);
    a2 = ADD(a2,t_q44);
    V ab_q44 = XOR(f2,g2);
    e2 = ADD(ADD(t_q44,BS0V(f2)),XOR(g2,AND(ab_q44,ab_q43)));
    V v243 = SIG0V(v185);
    V v244 = SIG1V(v237);
    V v245 = ADD(ADD(ADD(v182,v243),v217),v244);
    V v246 = ADD(v245,SET1((int)0xd6990624u));
    V t_q45 = ADD(ADD(ADD(d2,BS1V(a2)),CH(a2,b2,c2)),v246);
    h2 = ADD(h2,t_q45);
    V ab_q45 = XOR(e2,f2);
    d2 = ADD(ADD(t_q45,BS0V(e2)),XOR(f2,AND(ab_q45,ab_q44)));
    V v247 = SIG0V(v189);
    V v248 = SIG1V(v241);
    V v249 = ADD(ADD(ADD(v185,v247),v221),v248);
    V v250 = ADD(v249,SET1((int)0xf40e3585u));
    V t_q46 = ADD(ADD(ADD(c2,BS1V(h2)),CH(h2,a2,b2)),v250);
    g2 = ADD(g2,t_q46);
    V ab_q46 = XOR(d2,e2);
    c2 = ADD(ADD(t_q46,BS0V(d2)),XOR(e2,AND(ab_q46,ab_q45)));
    V v251 = SIG0V(v193);
    V v252 = SIG1V(v245);
    V v253 = ADD(ADD(ADD(v189,v251),v225),v252);
    V v254 = ADD(v253,SET1((int)0x106aa070u));
    V t_q47 = ADD(ADD(ADD(b2,BS1V(g2)),CH(g2,h2,a2)),v254);
    f2 = ADD(f2,t_q47);
    V ab_q47 = XOR(c2,d2);
    b2 = ADD(ADD(t_q47,BS0V(c2)),XOR(d2,AND(ab_q47,ab_q46)));
    V v255 = SIG0V(v197);
    V v256 = SIG1V(v249);
    V v257 = ADD(ADD(ADD(v193,v255),v229),v256);
    V v258 = ADD(v257,SET1((int)0x19a4c116u));
    V t_q48 = ADD(ADD(ADD(a2,BS1V(f2)),CH(f2,g2,h2)),v258);
    e2 = ADD(e2,t_q48);
    V ab_q48 = XOR(b2,c2);
    a2 = ADD(ADD(t_q48,BS0V(b2)),XOR(c2,AND(ab_q48,ab_q47)));
    V v259 = SIG0V(v201);
    V v260 = SIG1V(v253);
    V v261 = ADD(ADD(ADD(v197,v259),v233),v260);
    V v262 = ADD(v261,SET1((int)0x1e376c08u));
    V t_q49 = ADD(ADD(ADD(h2,BS1V(e2)),CH(e2,f2,g2)),v262);
    d2 = ADD(d2,t_q49);
    V ab_q49 = XOR(a2,b2);
    h2 = ADD(ADD(t_q49,BS0V(a2)),XOR(b2,AND(ab_q49,ab_q48)));
    V v263 = SIG0V(v205);
    V v264 = SIG1V(v257);
    V v265 = ADD(ADD(ADD(v201,v263),v237),v264);
    V v266 = ADD(v265,SET1((int)0x2748774cu));
    V t_q50 = ADD(ADD(ADD(g2,BS1V(d2)),CH(d2,e2,f2)),v266);
    c2 = ADD(c2,t_q50);
    V ab_q50 = XOR(h2,a2);
    g2 = ADD(ADD(t_q50,BS0V(h2)),XOR(a2,AND(ab_q50,ab_q49)));
    V v267 = SIG0V(v209);
    V v268 = SIG1V(v261);
    V v269 = ADD(ADD(ADD(v205,v267),v241),v268);
    V v270 = ADD(v269,SET1((int)0x34b0bcb5u));
    V t_q51 = ADD(ADD(ADD(f2,BS1V(c2)),CH(c2,d2,e2)),v270);
    b2 = ADD(b2,t_q51);
    V ab_q51 = XOR(g2,h2);
    f2 = ADD(ADD(t_q51,BS0V(g2)),XOR(h2,AND(ab_q51,ab_q50)));
    V v271 = SIG0V(v213);
    V v272 = SIG1V(v265);
    V v273 = ADD(ADD(ADD(v209,v271),v245),v272);
    V v274 = ADD(v273,SET1((int)0x391c0cb3u));
    V t_q52 = ADD(ADD(ADD(e2,BS1V(b2)),CH(b2,c2,d2)),v274);
    a2 = ADD(a2,t_q52);
    V ab_q52 = XOR(f2,g2);
    e2 = ADD(ADD(t_q52,BS0V(f2)),XOR(g2,AND(ab_q52,ab_q51)));
    V v275 = SIG0V(v217);
    V v276 = SIG1V(v269);
    V v277 = ADD(ADD(ADD(v213,v275),v249),v276);
    V v278 = ADD(v277,SET1((int)0x4ed8aa4au));
    V t_q53 = ADD(ADD(ADD(d2,BS1V(a2)),CH(a2,b2,c2)),v278);
    h2 = ADD(h2,t_q53);
    V ab_q53 = XOR(e2,f2);
    d2 = ADD(ADD(t_q53,BS0V(e2)),XOR(f2,AND(ab_q53,ab_q52)));
    V v279 = SIG0V(v221);
    V v280 = SIG1V(v273);
    V v281 = ADD(ADD(ADD(v217,v279),v253),v280);
    V v282 = ADD(v281,SET1((int)0x5b9cca4fu));
    V t_q54 = ADD(ADD(ADD(c2,BS1V(h2)),CH(h2,a2,b2)),v282);
    g2 = ADD(g2,t_q54);
    V ab_q54 = XOR(d2,e2);
    c2 = ADD(ADD(t_q54,BS0V(d2)),XOR(e2,AND(ab_q54,ab_q53)));
    V v283 = SIG0V(v225);
    V v284 = SIG1V(v277);
    V v285 = ADD(ADD(ADD(v221,v283),v257),v284);
    V v286 = ADD(v285,SET1((int)0x682e6ff3u));
    V t_q55 = ADD(ADD(ADD(b2,BS1V(g2)),CH(g2,h2,a2)),v286);
    f2 = ADD(f2,t_q55);
    V ab_q55 = XOR(c2,d2);
    b2 = ADD(ADD(t_q55,BS0V(c2)),XOR(d2,AND(ab_q55,ab_q54)));
    V v287 = SIG0V(v229);
    V v288 = SIG1V(v281);
    V v289 = ADD(ADD(ADD(v225,v287),v261),v288);
    V v290 = ADD(v289,SET1((int)0x748f82eeu));
    V t_q56 = ADD(ADD(ADD(a2,BS1V(f2)),CH(f2,g2,h2)),v290);
    e2 = ADD(e2,t_q56);
    V ab_q56 = XOR(b2,c2);
    a2 = ADD(ADD(t_q56,BS0V(b2)),XOR(c2,AND(ab_q56,ab_q55)));
    V v291 = SIG0V(v233);
    V v292 = SIG1V(v285);
    V v293 = ADD(ADD(ADD(v229,v291),v265),v292);
    V v294 = ADD(v293,SET1((int)0x78a5636fu));
    V t_q57 = ADD(ADD(ADD(h2,BS1V(e2)),CH(e2,f2,g2)),v294);
    d2 = ADD(d2,t_q57);
    V v295 = SIG0V(v237);
    V v296 = SIG1V(v289);
    V v297 = ADD(ADD(ADD(v233,v295),v269),v296);
    V v298 = ADD(v297,SET1((int)0x84c87814u));
    V t_q58 = ADD(ADD(ADD(g2,BS1V(d2)),CH(d2,e2,f2)),v298);
    c2 = ADD(c2,t_q58);
    V v299 = SIG0V(v241);
    V v300 = SIG1V(v293);
    V v301 = ADD(ADD(ADD(v237,v299),v273),v300);
    V v302 = ADD(v301,SET1((int)0x8cc70208u));
    V t_q59 = ADD(ADD(ADD(f2,BS1V(c2)),CH(c2,d2,e2)),v302);
    b2 = ADD(b2,t_q59);
    V v303 = SIG0V(v245);
    V v304 = SIG1V(v297);
    V v305 = ADD(ADD(ADD(v241,v303),v277),v304);
    V v306 = ADD(v305,SET1((int)0x90befffau));
    V t_q60 = ADD(ADD(ADD(e2,BS1V(b2)),CH(b2,c2,d2)),v306);
    a2 = ADD(a2,t_q60);
    return ADD(a2,SET1((int)0x5be0cd19u));
}
static uint64_t scan_avx2(const uint8_t *hdr, uint32_t start, uint64_t count, uint32_t mask, int M){
  uint32_t c[NC]; uint8_t hdrv[MAXM][76]; uint32_t ver[MAXM]; VS vs[MAXM];
  M=setup_versions(hdr,mask,M,hdrv,ver);
  prepare_shared(hdr,c); for(int j=0;j<M;j++) prepare_ver(hdrv[j],&vs[j]);
  V nv=ADD(SET1((int)start),LANEIDX); const V step=SET1(8); V KW[64];
  uint64_t hits=0;
  for(uint64_t base=0;base<count;base+=8){
    sched_avx2(c,BSWAP(nv),KW);
    for(int j=0;j<M;j++){
      unsigned mk=CMPZ(hash_avx2(c,&vs[j],KW));
      if(mk) for(int lane=0;lane<8;lane++) if(((mk>>lane)&1) && base+(uint64_t)lane<count)
        hits+=report_hit(hdrv[j],start+(uint32_t)(base+(uint64_t)lane),ver[j]);
    }
    nv=ADD(nv,step);
  }
  return hits;
}
static int test_avx2(void){
  uint64_t x=88172645463325252ULL; long checked=0,bad=0;
  for(int trial=0;trial<6;trial++){
    uint8_t hdr[76]; for(int i=0;i<76;i++){x^=x<<13;x^=x>>7;x^=x<<17;hdr[i]=(uint8_t)x;}
    uint32_t mask=0x1fffe000u,start=(uint32_t)x; int M=(trial%2)?16:8;
    uint32_t c[NC]; uint8_t hdrv[MAXM][76]; uint32_t ver[MAXM]; VS vs[MAXM];
    M=setup_versions(hdr,mask,M,hdrv,ver); prepare_shared(hdr,c); for(int j=0;j<M;j++) prepare_ver(hdrv[j],&vs[j]);
    V KW[64];
    for(uint32_t base=0;base<4096;base+=8){
      uint32_t ns[8]; for(int l=0;l<8;l++) ns[l]=start+base+l;
      sched_avx2(c,BSWAP(LOADU(ns)),KW);
      for(int j=0;j<M;j++){
        uint32_t out[8]; STOREU(out,hash_avx2(c,&vs[j],KW));
        for(int l=0;l<8;l++){ uint32_t s[8]; scalar_hash(hdrv[j],ns[l],s); checked++; if(s[7]!=out[l]) bad++; }
      }
    }
  }
  if(bad){ printf("%s: HATA checked=%ld bad=%ld\n","avx2",checked,bad); return 1; }
  printf("%s: OK checked=%ld\n","avx2",checked); return 0;
}
#undef V
#undef ADD
#undef XOR
#undef AND
#undef OR
#undef SHR
#undef SHL
#undef ROR
#undef T3
#undef SIG0V
#undef SIG1V
#undef BS0V
#undef BS1V
#undef CH
#undef MAJ
#undef SET1
#undef BSWAP
#undef LANEIDX
#undef LOADU
#undef STOREU
#undef CMPZ
#pragma GCC pop_options

/* ===== motor avx512vl (8 serit) ===== */
#pragma GCC push_options
#pragma GCC target("avx2,avx512f,avx512vl")
#define V __m256i
#define ADD(a,b) _mm256_add_epi32(a,b)
#define XOR(a,b) _mm256_xor_si256(a,b)
#define SHR(x,n) _mm256_srli_epi32(x,n)
#define ROR(x,n) _mm256_ror_epi32(x,n)
#define T3(a,b,c,i) _mm256_ternarylogic_epi32(a,b,c,i)
#define SIG0V(x) T3(ROR(x,7),ROR(x,18),SHR(x,3),0x96)
#define SIG1V(x) T3(ROR(x,17),ROR(x,19),SHR(x,10),0x96)
#define BS0V(x) T3(ROR(x,2),ROR(x,13),ROR(x,22),0x96)
#define BS1V(x) T3(ROR(x,6),ROR(x,11),ROR(x,25),0x96)
#define CH(e,f,g) T3(e,f,g,0xCA)
#define MAJ(a,b,c) T3(a,b,c,0xE8)
#define SET1(x) _mm256_set1_epi32(x)
#define BSWAP(x) _mm256_shuffle_epi8(x,_mm256_setr_epi8(3,2,1,0,7,6,5,4,11,10,9,8,15,14,13,12,3,2,1,0,7,6,5,4,11,10,9,8,15,14,13,12))
#define LANEIDX _mm256_setr_epi32(0,1,2,3,4,5,6,7)
#define LOADU(p) _mm256_loadu_si256((const __m256i*)(p))
#define STOREU(p,x) _mm256_storeu_si256((__m256i*)(p),x)
#define CMPZ(x) ((unsigned)_mm256_cmpeq_epi32_mask(x,_mm256_setzero_si256()))
static inline void sched_avx512vl(const uint32_t *c, V nonce, V *KW){
    V nonce_w3 = nonce;
    KW[3] = ADD(nonce_w3,SET1((int)0xe9b5dba5u));
    V v0 = SIG0V(nonce_w3);
    V v1 = ADD(v0,SET1((int)c[26]));
    KW[18] = ADD(v1,SET1((int)0x0fc19dc6u));
    V v2 = ADD(nonce_w3,SET1((int)c[28]));
    KW[19] = ADD(v2,SET1((int)0x240ca1ccu));
    V v3 = SIG1V(v1);
    V v4 = ADD(v3,SET1((int)0x80000000u));
    KW[20] = ADD(v4,SET1((int)0x2de92c6fu));
    V v5 = SIG1V(v2);
    V v6 = v5;
    KW[21] = ADD(v6,SET1((int)0x4a7484aau));
    V v7 = SIG1V(v4);
    V v8 = ADD(v7,SET1((int)0x00000280u));
    KW[22] = ADD(v8,SET1((int)0x5cb0a9dcu));
    V v9 = SIG1V(v6);
    V v10 = ADD(v9,SET1((int)c[20]));
    KW[23] = ADD(v10,SET1((int)0x76f988dau));
    V v11 = SIG1V(v8);
    V v12 = ADD(v11,SET1((int)c[23]));
    KW[24] = ADD(v12,SET1((int)0x983e5152u));
    V v13 = SIG1V(v10);
    V v14 = ADD(v1,v13);
    KW[25] = ADD(v14,SET1((int)0xa831c66du));
    V v15 = SIG1V(v12);
    V v16 = ADD(v2,v15);
    KW[26] = ADD(v16,SET1((int)0xb00327c8u));
    V v17 = SIG1V(v14);
    V v18 = ADD(v4,v17);
    KW[27] = ADD(v18,SET1((int)0xbf597fc7u));
    V v19 = SIG1V(v16);
    V v20 = ADD(v6,v19);
    KW[28] = ADD(v20,SET1((int)0xc6e00bf3u));
    V v21 = SIG1V(v18);
    V v22 = ADD(v8,v21);
    KW[29] = ADD(v22,SET1((int)0xd5a79147u));
    V v23 = SIG1V(v20);
    V v24 = ADD(ADD(v10,v23),SET1((int)0x00a00055u));
    KW[30] = ADD(v24,SET1((int)0x06ca6351u));
    V v25 = SIG1V(v22);
    V v26 = ADD(ADD(v12,v25),SET1((int)c[30]));
    KW[31] = ADD(v26,SET1((int)0x14292967u));
    V v27 = SIG1V(v24);
    V v28 = ADD(ADD(v14,v27),SET1((int)c[32]));
    KW[32] = ADD(v28,SET1((int)0x27b70a85u));
    V v29 = SIG0V(v1);
    V v30 = SIG1V(v26);
    V v31 = ADD(ADD(ADD(v29,v16),v30),SET1((int)c[23]));
    KW[33] = ADD(v31,SET1((int)0x2e1b2138u));
    V v32 = SIG0V(v2);
    V v33 = SIG1V(v28);
    V v34 = ADD(ADD(ADD(v1,v32),v18),v33);
    KW[34] = ADD(v34,SET1((int)0x4d2c6dfcu));
    V v35 = SIG0V(v4);
    V v36 = SIG1V(v31);
    V v37 = ADD(ADD(ADD(v2,v35),v20),v36);
    KW[35] = ADD(v37,SET1((int)0x53380d13u));
    V v38 = SIG0V(v6);
    V v39 = SIG1V(v34);
    V v40 = ADD(ADD(ADD(v4,v38),v22),v39);
    KW[36] = ADD(v40,SET1((int)0x650a7354u));
    V v41 = SIG0V(v8);
    V v42 = SIG1V(v37);
    V v43 = ADD(ADD(ADD(v6,v41),v24),v42);
    KW[37] = ADD(v43,SET1((int)0x766a0abbu));
    V v44 = SIG0V(v10);
    V v45 = SIG1V(v40);
    V v46 = ADD(ADD(ADD(v8,v44),v26),v45);
    KW[38] = ADD(v46,SET1((int)0x81c2c92eu));
    V v47 = SIG0V(v12);
    V v48 = SIG1V(v43);
    V v49 = ADD(ADD(ADD(v10,v47),v28),v48);
    KW[39] = ADD(v49,SET1((int)0x92722c85u));
    V v50 = SIG0V(v14);
    V v51 = SIG1V(v46);
    V v52 = ADD(ADD(ADD(v12,v50),v31),v51);
    KW[40] = ADD(v52,SET1((int)0xa2bfe8a1u));
    V v53 = SIG0V(v16);
    V v54 = SIG1V(v49);
    V v55 = ADD(ADD(ADD(v14,v53),v34),v54);
    KW[41] = ADD(v55,SET1((int)0xa81a664bu));
    V v56 = SIG0V(v18);
    V v57 = SIG1V(v52);
    V v58 = ADD(ADD(ADD(v16,v56),v37),v57);
    KW[42] = ADD(v58,SET1((int)0xc24b8b70u));
    V v59 = SIG0V(v20);
    V v60 = SIG1V(v55);
    V v61 = ADD(ADD(ADD(v18,v59),v40),v60);
    KW[43] = ADD(v61,SET1((int)0xc76c51a3u));
    V v62 = SIG0V(v22);
    V v63 = SIG1V(v58);
    V v64 = ADD(ADD(ADD(v20,v62),v43),v63);
    KW[44] = ADD(v64,SET1((int)0xd192e819u));
    V v65 = SIG0V(v24);
    V v66 = SIG1V(v61);
    V v67 = ADD(ADD(ADD(v22,v65),v46),v66);
    KW[45] = ADD(v67,SET1((int)0xd6990624u));
    V v68 = SIG0V(v26);
    V v69 = SIG1V(v64);
    V v70 = ADD(ADD(ADD(v24,v68),v49),v69);
    KW[46] = ADD(v70,SET1((int)0xf40e3585u));
    V v71 = SIG0V(v28);
    V v72 = SIG1V(v67);
    V v73 = ADD(ADD(ADD(v26,v71),v52),v72);
    KW[47] = ADD(v73,SET1((int)0x106aa070u));
    V v74 = SIG0V(v31);
    V v75 = SIG1V(v70);
    V v76 = ADD(ADD(ADD(v28,v74),v55),v75);
    KW[48] = ADD(v76,SET1((int)0x19a4c116u));
    V v77 = SIG0V(v34);
    V v78 = SIG1V(v73);
    V v79 = ADD(ADD(ADD(v31,v77),v58),v78);
    KW[49] = ADD(v79,SET1((int)0x1e376c08u));
    V v80 = SIG0V(v37);
    V v81 = SIG1V(v76);
    V v82 = ADD(ADD(ADD(v34,v80),v61),v81);
    KW[50] = ADD(v82,SET1((int)0x2748774cu));
    V v83 = SIG0V(v40);
    V v84 = SIG1V(v79);
    V v85 = ADD(ADD(ADD(v37,v83),v64),v84);
    KW[51] = ADD(v85,SET1((int)0x34b0bcb5u));
    V v86 = SIG0V(v43);
    V v87 = SIG1V(v82);
    V v88 = ADD(ADD(ADD(v40,v86),v67),v87);
    KW[52] = ADD(v88,SET1((int)0x391c0cb3u));
    V v89 = SIG0V(v46);
    V v90 = SIG1V(v85);
    V v91 = ADD(ADD(ADD(v43,v89),v70),v90);
    KW[53] = ADD(v91,SET1((int)0x4ed8aa4au));
    V v92 = SIG0V(v49);
    V v93 = SIG1V(v88);
    V v94 = ADD(ADD(ADD(v46,v92),v73),v93);
    KW[54] = ADD(v94,SET1((int)0x5b9cca4fu));
    V v95 = SIG0V(v52);
    V v96 = SIG1V(v91);
    V v97 = ADD(ADD(ADD(v49,v95),v76),v96);
    KW[55] = ADD(v97,SET1((int)0x682e6ff3u));
    V v98 = SIG0V(v55);
    V v99 = SIG1V(v94);
    V v100 = ADD(ADD(ADD(v52,v98),v79),v99);
    KW[56] = ADD(v100,SET1((int)0x748f82eeu));
    V v101 = SIG0V(v58);
    V v102 = SIG1V(v97);
    V v103 = ADD(ADD(ADD(v55,v101),v82),v102);
    KW[57] = ADD(v103,SET1((int)0x78a5636fu));
    V v104 = SIG0V(v61);
    V v105 = SIG1V(v100);
    V v106 = ADD(ADD(ADD(v58,v104),v85),v105);
    KW[58] = ADD(v106,SET1((int)0x84c87814u));
    V v107 = SIG0V(v64);
    V v108 = SIG1V(v103);
    V v109 = ADD(ADD(ADD(v61,v107),v88),v108);
    KW[59] = ADD(v109,SET1((int)0x8cc70208u));
    V v110 = SIG0V(v67);
    V v111 = SIG1V(v106);
    V v112 = ADD(ADD(ADD(v64,v110),v91),v111);
    KW[60] = ADD(v112,SET1((int)0x90befffau));
    V v113 = SIG0V(v70);
    V v114 = SIG1V(v109);
    V v115 = ADD(ADD(ADD(v67,v113),v94),v114);
    KW[61] = ADD(v115,SET1((int)0xa4506cebu));
    V v116 = SIG0V(v73);
    V v117 = SIG1V(v112);
    V v118 = ADD(ADD(ADD(v70,v116),v97),v117);
    KW[62] = ADD(v118,SET1((int)0xbef9a3f7u));
    V v119 = SIG0V(v76);
    V v120 = SIG1V(v115);
    V v121 = ADD(ADD(ADD(v73,v119),v100),v120);
    KW[63] = ADD(v121,SET1((int)0xc67178f2u));
}
static inline V hash_avx512vl(const uint32_t *c, const VS *vs, const V *KW){
    V a1 = SET1((int)vs->st3[0]);
    V b1 = SET1((int)vs->st3[1]);
    V c1 = SET1((int)vs->st3[2]);
    V d1 = SET1((int)vs->st3[3]);
    V e1 = SET1((int)vs->st3[4]);
    V f1 = SET1((int)vs->st3[5]);
    V g1 = SET1((int)vs->st3[6]);
    V h1 = SET1((int)vs->st3[7]);
    V t_p3 = ADD(ADD(ADD(h1,BS1V(e1)),CH(e1,f1,g1)),KW[3]);
    d1 = ADD(d1,t_p3);
    h1 = ADD(ADD(t_p3,BS0V(a1)),MAJ(a1,b1,c1));
    V t_p4 = ADD(ADD(ADD(g1,BS1V(d1)),CH(d1,e1,f1)),SET1((int)0xb956c25bu));
    c1 = ADD(c1,t_p4);
    g1 = ADD(ADD(t_p4,BS0V(h1)),MAJ(h1,a1,b1));
    V t_p5 = ADD(ADD(ADD(f1,BS1V(c1)),CH(c1,d1,e1)),SET1((int)0x59f111f1u));
    b1 = ADD(b1,t_p5);
    f1 = ADD(ADD(t_p5,BS0V(g1)),MAJ(g1,h1,a1));
    V t_p6 = ADD(ADD(ADD(e1,BS1V(b1)),CH(b1,c1,d1)),SET1((int)0x923f82a4u));
    a1 = ADD(a1,t_p6);
    e1 = ADD(ADD(t_p6,BS0V(f1)),MAJ(f1,g1,h1));
    V t_p7 = ADD(ADD(ADD(d1,BS1V(a1)),CH(a1,b1,c1)),SET1((int)0xab1c5ed5u));
    h1 = ADD(h1,t_p7);
    d1 = ADD(ADD(t_p7,BS0V(e1)),MAJ(e1,f1,g1));
    V t_p8 = ADD(ADD(ADD(c1,BS1V(h1)),CH(h1,a1,b1)),SET1((int)0xd807aa98u));
    g1 = ADD(g1,t_p8);
    c1 = ADD(ADD(t_p8,BS0V(d1)),MAJ(d1,e1,f1));
    V t_p9 = ADD(ADD(ADD(b1,BS1V(g1)),CH(g1,h1,a1)),SET1((int)0x12835b01u));
    f1 = ADD(f1,t_p9);
    b1 = ADD(ADD(t_p9,BS0V(c1)),MAJ(c1,d1,e1));
    V t_p10 = ADD(ADD(ADD(a1,BS1V(f1)),CH(f1,g1,h1)),SET1((int)0x243185beu));
    e1 = ADD(e1,t_p10);
    a1 = ADD(ADD(t_p10,BS0V(b1)),MAJ(b1,c1,d1));
    V t_p11 = ADD(ADD(ADD(h1,BS1V(e1)),CH(e1,f1,g1)),SET1((int)0x550c7dc3u));
    d1 = ADD(d1,t_p11);
    h1 = ADD(ADD(t_p11,BS0V(a1)),MAJ(a1,b1,c1));
    V t_p12 = ADD(ADD(ADD(g1,BS1V(d1)),CH(d1,e1,f1)),SET1((int)0x72be5d74u));
    c1 = ADD(c1,t_p12);
    g1 = ADD(ADD(t_p12,BS0V(h1)),MAJ(h1,a1,b1));
    V t_p13 = ADD(ADD(ADD(f1,BS1V(c1)),CH(c1,d1,e1)),SET1((int)0x80deb1feu));
    b1 = ADD(b1,t_p13);
    f1 = ADD(ADD(t_p13,BS0V(g1)),MAJ(g1,h1,a1));
    V t_p14 = ADD(ADD(ADD(e1,BS1V(b1)),CH(b1,c1,d1)),SET1((int)0x9bdc06a7u));
    a1 = ADD(a1,t_p14);
    e1 = ADD(ADD(t_p14,BS0V(f1)),MAJ(f1,g1,h1));
    V t_p15 = ADD(ADD(ADD(d1,BS1V(a1)),CH(a1,b1,c1)),SET1((int)0xc19bf3f4u));
    h1 = ADD(h1,t_p15);
    d1 = ADD(ADD(t_p15,BS0V(e1)),MAJ(e1,f1,g1));
    V t_p16 = ADD(ADD(ADD(c1,BS1V(h1)),CH(h1,a1,b1)),SET1((int)c[21]));
    g1 = ADD(g1,t_p16);
    c1 = ADD(ADD(t_p16,BS0V(d1)),MAJ(d1,e1,f1));
    V t_p17 = ADD(ADD(ADD(b1,BS1V(g1)),CH(g1,h1,a1)),SET1((int)c[24]));
    f1 = ADD(f1,t_p17);
    b1 = ADD(ADD(t_p17,BS0V(c1)),MAJ(c1,d1,e1));
    V t_p18 = ADD(ADD(ADD(a1,BS1V(f1)),CH(f1,g1,h1)),KW[18]);
    e1 = ADD(e1,t_p18);
    a1 = ADD(ADD(t_p18,BS0V(b1)),MAJ(b1,c1,d1));
    V t_p19 = ADD(ADD(ADD(h1,BS1V(e1)),CH(e1,f1,g1)),KW[19]);
    d1 = ADD(d1,t_p19);
    h1 = ADD(ADD(t_p19,BS0V(a1)),MAJ(a1,b1,c1));
    V t_p20 = ADD(ADD(ADD(g1,BS1V(d1)),CH(d1,e1,f1)),KW[20]);
    c1 = ADD(c1,t_p20);
    g1 = ADD(ADD(t_p20,BS0V(h1)),MAJ(h1,a1,b1));
    V t_p21 = ADD(ADD(ADD(f1,BS1V(c1)),CH(c1,d1,e1)),KW[21]);
    b1 = ADD(b1,t_p21);
    f1 = ADD(ADD(t_p21,BS0V(g1)),MAJ(g1,h1,a1));
    V t_p22 = ADD(ADD(ADD(e1,BS1V(b1)),CH(b1,c1,d1)),KW[22]);
    a1 = ADD(a1,t_p22);
    e1 = ADD(ADD(t_p22,BS0V(f1)),MAJ(f1,g1,h1));
    V t_p23 = ADD(ADD(ADD(d1,BS1V(a1)),CH(a1,b1,c1)),KW[23]);
    h1 = ADD(h1,t_p23);
    d1 = ADD(ADD(t_p23,BS0V(e1)),MAJ(e1,f1,g1));
    V t_p24 = ADD(ADD(ADD(c1,BS1V(h1)),CH(h1,a1,b1)),KW[24]);
    g1 = ADD(g1,t_p24);
    c1 = ADD(ADD(t_p24,BS0V(d1)),MAJ(d1,e1,f1));
    V t_p25 = ADD(ADD(ADD(b1,BS1V(g1)),CH(g1,h1,a1)),KW[25]);
    f1 = ADD(f1,t_p25);
    b1 = ADD(ADD(t_p25,BS0V(c1)),MAJ(c1,d1,e1));
    V t_p26 = ADD(ADD(ADD(a1,BS1V(f1)),CH(f1,g1,h1)),KW[26]);
    e1 = ADD(e1,t_p26);
    a1 = ADD(ADD(t_p26,BS0V(b1)),MAJ(b1,c1,d1));
    V t_p27 = ADD(ADD(ADD(h1,BS1V(e1)),CH(e1,f1,g1)),KW[27]);
    d1 = ADD(d1,t_p27);
    h1 = ADD(ADD(t_p27,BS0V(a1)),MAJ(a1,b1,c1));
    V t_p28 = ADD(ADD(ADD(g1,BS1V(d1)),CH(d1,e1,f1)),KW[28]);
    c1 = ADD(c1,t_p28);
    g1 = ADD(ADD(t_p28,BS0V(h1)),MAJ(h1,a1,b1));
    V t_p29 = ADD(ADD(ADD(f1,BS1V(c1)),CH(c1,d1,e1)),KW[29]);
    b1 = ADD(b1,t_p29);
    f1 = ADD(ADD(t_p29,BS0V(g1)),MAJ(g1,h1,a1));
    V t_p30 = ADD(ADD(ADD(e1,BS1V(b1)),CH(b1,c1,d1)),KW[30]);
    a1 = ADD(a1,t_p30);
    e1 = ADD(ADD(t_p30,BS0V(f1)),MAJ(f1,g1,h1));
    V t_p31 = ADD(ADD(ADD(d1,BS1V(a1)),CH(a1,b1,c1)),KW[31]);
    h1 = ADD(h1,t_p31);
    d1 = ADD(ADD(t_p31,BS0V(e1)),MAJ(e1,f1,g1));
    V t_p32 = ADD(ADD(ADD(c1,BS1V(h1)),CH(h1,a1,b1)),KW[32]);
    g1 = ADD(g1,t_p32);
    c1 = ADD(ADD(t_p32,BS0V(d1)),MAJ(d1,e1,f1));
    V t_p33 = ADD(ADD(ADD(b1,BS1V(g1)),CH(g1,h1,a1)),KW[33]);
    f1 = ADD(f1,t_p33);
    b1 = ADD(ADD(t_p33,BS0V(c1)),MAJ(c1,d1,e1));
    V t_p34 = ADD(ADD(ADD(a1,BS1V(f1)),CH(f1,g1,h1)),KW[34]);
    e1 = ADD(e1,t_p34);
    a1 = ADD(ADD(t_p34,BS0V(b1)),MAJ(b1,c1,d1));
    V t_p35 = ADD(ADD(ADD(h1,BS1V(e1)),CH(e1,f1,g1)),KW[35]);
    d1 = ADD(d1,t_p35);
    h1 = ADD(ADD(t_p35,BS0V(a1)),MAJ(a1,b1,c1));
    V t_p36 = ADD(ADD(ADD(g1,BS1V(d1)),CH(d1,e1,f1)),KW[36]);
    c1 = ADD(c1,t_p36);
    g1 = ADD(ADD(t_p36,BS0V(h1)),MAJ(h1,a1,b1));
    V t_p37 = ADD(ADD(ADD(f1,BS1V(c1)),CH(c1,d1,e1)),KW[37]);
    b1 = ADD(b1,t_p37);
    f1 = ADD(ADD(t_p37,BS0V(g1)),MAJ(g1,h1,a1));
    V t_p38 = ADD(ADD(ADD(e1,BS1V(b1)),CH(b1,c1,d1)),KW[38]);
    a1 = ADD(a1,t_p38);
    e1 = ADD(ADD(t_p38,BS0V(f1)),MAJ(f1,g1,h1));
    V t_p39 = ADD(ADD(ADD(d1,BS1V(a1)),CH(a1,b1,c1)),KW[39]);
    h1 = ADD(h1,t_p39);
    d1 = ADD(ADD(t_p39,BS0V(e1)),MAJ(e1,f1,g1));
    V t_p40 = ADD(ADD(ADD(c1,BS1V(h1)),CH(h1,a1,b1)),KW[40]);
    g1 = ADD(g1,t_p40);
    c1 = ADD(ADD(t_p40,BS0V(d1)),MAJ(d1,e1,f1));
    V t_p41 = ADD(ADD(ADD(b1,BS1V(g1)),CH(g1,h1,a1)),KW[41]);
    f1 = ADD(f1,t_p41);
    b1 = ADD(ADD(t_p41,BS0V(c1)),MAJ(c1,d1,e1));
    V t_p42 = ADD(ADD(ADD(a1,BS1V(f1)),CH(f1,g1,h1)),KW[42]);
    e1 = ADD(e1,t_p42);
    a1 = ADD(ADD(t_p42,BS0V(b1)),MAJ(b1,c1,d1));
    V t_p43 = ADD(ADD(ADD(h1,BS1V(e1)),CH(e1,f1,g1)),KW[43]);
    d1 = ADD(d1,t_p43);
    h1 = ADD(ADD(t_p43,BS0V(a1)),MAJ(a1,b1,c1));
    V t_p44 = ADD(ADD(ADD(g1,BS1V(d1)),CH(d1,e1,f1)),KW[44]);
    c1 = ADD(c1,t_p44);
    g1 = ADD(ADD(t_p44,BS0V(h1)),MAJ(h1,a1,b1));
    V t_p45 = ADD(ADD(ADD(f1,BS1V(c1)),CH(c1,d1,e1)),KW[45]);
    b1 = ADD(b1,t_p45);
    f1 = ADD(ADD(t_p45,BS0V(g1)),MAJ(g1,h1,a1));
    V t_p46 = ADD(ADD(ADD(e1,BS1V(b1)),CH(b1,c1,d1)),KW[46]);
    a1 = ADD(a1,t_p46);
    e1 = ADD(ADD(t_p46,BS0V(f1)),MAJ(f1,g1,h1));
    V t_p47 = ADD(ADD(ADD(d1,BS1V(a1)),CH(a1,b1,c1)),KW[47]);
    h1 = ADD(h1,t_p47);
    d1 = ADD(ADD(t_p47,BS0V(e1)),MAJ(e1,f1,g1));
    V t_p48 = ADD(ADD(ADD(c1,BS1V(h1)),CH(h1,a1,b1)),KW[48]);
    g1 = ADD(g1,t_p48);
    c1 = ADD(ADD(t_p48,BS0V(d1)),MAJ(d1,e1,f1));
    V t_p49 = ADD(ADD(ADD(b1,BS1V(g1)),CH(g1,h1,a1)),KW[49]);
    f1 = ADD(f1,t_p49);
    b1 = ADD(ADD(t_p49,BS0V(c1)),MAJ(c1,d1,e1));
    V t_p50 = ADD(ADD(ADD(a1,BS1V(f1)),CH(f1,g1,h1)),KW[50]);
    e1 = ADD(e1,t_p50);
    a1 = ADD(ADD(t_p50,BS0V(b1)),MAJ(b1,c1,d1));
    V t_p51 = ADD(ADD(ADD(h1,BS1V(e1)),CH(e1,f1,g1)),KW[51]);
    d1 = ADD(d1,t_p51);
    h1 = ADD(ADD(t_p51,BS0V(a1)),MAJ(a1,b1,c1));
    V t_p52 = ADD(ADD(ADD(g1,BS1V(d1)),CH(d1,e1,f1)),KW[52]);
    c1 = ADD(c1,t_p52);
    g1 = ADD(ADD(t_p52,BS0V(h1)),MAJ(h1,a1,b1));
    V t_p53 = ADD(ADD(ADD(f1,BS1V(c1)),CH(c1,d1,e1)),KW[53]);
    b1 = ADD(b1,t_p53);
    f1 = ADD(ADD(t_p53,BS0V(g1)),MAJ(g1,h1,a1));
    V t_p54 = ADD(ADD(ADD(e1,BS1V(b1)),CH(b1,c1,d1)),KW[54]);
    a1 = ADD(a1,t_p54);
    e1 = ADD(ADD(t_p54,BS0V(f1)),MAJ(f1,g1,h1));
    V t_p55 = ADD(ADD(ADD(d1,BS1V(a1)),CH(a1,b1,c1)),KW[55]);
    h1 = ADD(h1,t_p55);
    d1 = ADD(ADD(t_p55,BS0V(e1)),MAJ(e1,f1,g1));
    V t_p56 = ADD(ADD(ADD(c1,BS1V(h1)),CH(h1,a1,b1)),KW[56]);
    g1 = ADD(g1,t_p56);
    c1 = ADD(ADD(t_p56,BS0V(d1)),MAJ(d1,e1,f1));
    V t_p57 = ADD(ADD(ADD(b1,BS1V(g1)),CH(g1,h1,a1)),KW[57]);
    f1 = ADD(f1,t_p57);
    b1 = ADD(ADD(t_p57,BS0V(c1)),MAJ(c1,d1,e1));
    V t_p58 = ADD(ADD(ADD(a1,BS1V(f1)),CH(f1,g1,h1)),KW[58]);
    e1 = ADD(e1,t_p58);
    a1 = ADD(ADD(t_p58,BS0V(b1)),MAJ(b1,c1,d1));
    V t_p59 = ADD(ADD(ADD(h1,BS1V(e1)),CH(e1,f1,g1)),KW[59]);
    d1 = ADD(d1,t_p59);
    h1 = ADD(ADD(t_p59,BS0V(a1)),MAJ(a1,b1,c1));
    V t_p60 = ADD(ADD(ADD(g1,BS1V(d1)),CH(d1,e1,f1)),KW[60]);
    c1 = ADD(c1,t_p60);
    g1 = ADD(ADD(t_p60,BS0V(h1)),MAJ(h1,a1,b1));
    V t_p61 = ADD(ADD(ADD(f1,BS1V(c1)),CH(c1,d1,e1)),KW[61]);
    b1 = ADD(b1,t_p61);
    f1 = ADD(ADD(t_p61,BS0V(g1)),MAJ(g1,h1,a1));
    V t_p62 = ADD(ADD(ADD(e1,BS1V(b1)),CH(b1,c1,d1)),KW[62]);
    a1 = ADD(a1,t_p62);
    e1 = ADD(ADD(t_p62,BS0V(f1)),MAJ(f1,g1,h1));
    V t_p63 = ADD(ADD(ADD(d1,BS1V(a1)),CH(a1,b1,c1)),KW[63]);
    h1 = ADD(h1,t_p63);
    d1 = ADD(ADD(t_p63,BS0V(e1)),MAJ(e1,f1,g1));
    V v122 = ADD(d1,SET1((int)vs->mid[0]));
    V v123 = ADD(e1,SET1((int)vs->mid[1]));
    V v124 = ADD(f1,SET1((int)vs->mid[2]));
    V v125 = ADD(g1,SET1((int)vs->mid[3]));
    V v126 = ADD(h1,SET1((int)vs->mid[4]));
    V v127 = ADD(a1,SET1((int)vs->mid[5]));
    V v128 = ADD(b1,SET1((int)vs->mid[6]));
    V v129 = ADD(c1,SET1((int)vs->mid[7]));
    V t_q0 = ADD(v122,SET1((int)0xf377ed68u));
    V a2 = ADD(t_q0,SET1((int)0x08909ae5u));
    V e2 = ADD(t_q0,SET1((int)0xa54ff53au));
    V b2 = SET1((int)0x6a09e667u);
    V c2 = SET1((int)0xbb67ae85u);
    V d2 = SET1((int)0x3c6ef372u);
    V f2 = SET1((int)0x510e527fu);
    V g2 = SET1((int)0x9b05688cu);
    V h2 = SET1((int)0x1f83d9abu);
    V v130 = ADD(v123,SET1((int)0x71374491u));
    V t_q1 = ADD(ADD(ADD(h2,BS1V(e2)),CH(e2,f2,g2)),v130);
    d2 = ADD(d2,t_q1);
    h2 = ADD(ADD(t_q1,BS0V(a2)),MAJ(a2,b2,c2));
    V v131 = ADD(v124,SET1((int)0xb5c0fbcfu));
    V t_q2 = ADD(ADD(ADD(g2,BS1V(d2)),CH(d2,e2,f2)),v131);
    c2 = ADD(c2,t_q2);
    g2 = ADD(ADD(t_q2,BS0V(h2)),MAJ(h2,a2,b2));
    V v132 = ADD(v125,SET1((int)0xe9b5dba5u));
    V t_q3 = ADD(ADD(ADD(f2,BS1V(c2)),CH(c2,d2,e2)),v132);
    b2 = ADD(b2,t_q3);
    f2 = ADD(ADD(t_q3,BS0V(g2)),MAJ(g2,h2,a2));
    V v133 = ADD(v126,SET1((int)0x3956c25bu));
    V t_q4 = ADD(ADD(ADD(e2,BS1V(b2)),CH(b2,c2,d2)),v133);
    a2 = ADD(a2,t_q4);
    e2 = ADD(ADD(t_q4,BS0V(f2)),MAJ(f2,g2,h2));
    V v134 = ADD(v127,SET1((int)0x59f111f1u));
    V t_q5 = ADD(ADD(ADD(d2,BS1V(a2)),CH(a2,b2,c2)),v134);
    h2 = ADD(h2,t_q5);
    d2 = ADD(ADD(t_q5,BS0V(e2)),MAJ(e2,f2,g2));
    V v135 = ADD(v128,SET1((int)0x923f82a4u));
    V t_q6 = ADD(ADD(ADD(c2,BS1V(h2)),CH(h2,a2,b2)),v135);
    g2 = ADD(g2,t_q6);
    c2 = ADD(ADD(t_q6,BS0V(d2)),MAJ(d2,e2,f2));
    V v136 = ADD(v129,SET1((int)0xab1c5ed5u));
    V t_q7 = ADD(ADD(ADD(b2,BS1V(g2)),CH(g2,h2,a2)),v136);
    f2 = ADD(f2,t_q7);
    b2 = ADD(ADD(t_q7,BS0V(c2)),MAJ(c2,d2,e2));
    V t_q8 = ADD(ADD(ADD(a2,BS1V(f2)),CH(f2,g2,h2)),SET1((int)0x5807aa98u));
    e2 = ADD(e2,t_q8);
    a2 = ADD(ADD(t_q8,BS0V(b2)),MAJ(b2,c2,d2));
    V t_q9 = ADD(ADD(ADD(h2,BS1V(e2)),CH(e2,f2,g2)),SET1((int)0x12835b01u));
    d2 = ADD(d2,t_q9);
    h2 = ADD(ADD(t_q9,BS0V(a2)),MAJ(a2,b2,c2));
    V t_q10 = ADD(ADD(ADD(g2,BS1V(d2)),CH(d2,e2,f2)),SET1((int)0x243185beu));
    c2 = ADD(c2,t_q10);
    g2 = ADD(ADD(t_q10,BS0V(h2)),MAJ(h2,a2,b2));
    V t_q11 = ADD(ADD(ADD(f2,BS1V(c2)),CH(c2,d2,e2)),SET1((int)0x550c7dc3u));
    b2 = ADD(b2,t_q11);
    f2 = ADD(ADD(t_q11,BS0V(g2)),MAJ(g2,h2,a2));
    V t_q12 = ADD(ADD(ADD(e2,BS1V(b2)),CH(b2,c2,d2)),SET1((int)0x72be5d74u));
    a2 = ADD(a2,t_q12);
    e2 = ADD(ADD(t_q12,BS0V(f2)),MAJ(f2,g2,h2));
    V t_q13 = ADD(ADD(ADD(d2,BS1V(a2)),CH(a2,b2,c2)),SET1((int)0x80deb1feu));
    h2 = ADD(h2,t_q13);
    d2 = ADD(ADD(t_q13,BS0V(e2)),MAJ(e2,f2,g2));
    V t_q14 = ADD(ADD(ADD(c2,BS1V(h2)),CH(h2,a2,b2)),SET1((int)0x9bdc06a7u));
    g2 = ADD(g2,t_q14);
    c2 = ADD(ADD(t_q14,BS0V(d2)),MAJ(d2,e2,f2));
    V t_q15 = ADD(ADD(ADD(b2,BS1V(g2)),CH(g2,h2,a2)),SET1((int)0xc19bf274u));
    f2 = ADD(f2,t_q15);
    b2 = ADD(ADD(t_q15,BS0V(c2)),MAJ(c2,d2,e2));
    V v137 = SIG0V(v123);
    V v138 = ADD(v122,v137);
    V v139 = ADD(v138,SET1((int)0xe49b69c1u));
    V t_q16 = ADD(ADD(ADD(a2,BS1V(f2)),CH(f2,g2,h2)),v139);
    e2 = ADD(e2,t_q16);
    a2 = ADD(ADD(t_q16,BS0V(b2)),MAJ(b2,c2,d2));
    V v140 = SIG0V(v124);
    V v141 = ADD(ADD(v123,v140),SET1((int)0x00a00000u));
    V v142 = ADD(v141,SET1((int)0xefbe4786u));
    V t_q17 = ADD(ADD(ADD(h2,BS1V(e2)),CH(e2,f2,g2)),v142);
    d2 = ADD(d2,t_q17);
    h2 = ADD(ADD(t_q17,BS0V(a2)),MAJ(a2,b2,c2));
    V v143 = SIG0V(v125);
    V v144 = SIG1V(v138);
    V v145 = ADD(ADD(v124,v143),v144);
    V v146 = ADD(v145,SET1((int)0x0fc19dc6u));
    V t_q18 = ADD(ADD(ADD(g2,BS1V(d2)),CH(d2,e2,f2)),v146);
    c2 = ADD(c2,t_q18);
    g2 = ADD(ADD(t_q18,BS0V(h2)),MAJ(h2,a2,b2));
    V v147 = SIG0V(v126);
    V v148 = SIG1V(v141);
    V v149 = ADD(ADD(v125,v147),v148);
    V v150 = ADD(v149,SET1((int)0x240ca1ccu));
    V t_q19 = ADD(ADD(ADD(f2,BS1V(c2)),CH(c2,d2,e2)),v150);
    b2 = ADD(b2,t_q19);
    f2 = ADD(ADD(t_q19,BS0V(g2)),MAJ(g2,h2,a2));
    V v151 = SIG0V(v127);
    V v152 = SIG1V(v145);
    V v153 = ADD(ADD(v126,v151),v152);
    V v154 = ADD(v153,SET1((int)0x2de92c6fu));
    V t_q20 = ADD(ADD(ADD(e2,BS1V(b2)),CH(b2,c2,d2)),v154);
    a2 = ADD(a2,t_q20);
    e2 = ADD(ADD(t_q20,BS0V(f2)),MAJ(f2,g2,h2));
    V v155 = SIG0V(v128);
    V v156 = SIG1V(v149);
    V v157 = ADD(ADD(v127,v155),v156);
    V v158 = ADD(v157,SET1((int)0x4a7484aau));
    V t_q21 = ADD(ADD(ADD(d2,BS1V(a2)),CH(a2,b2,c2)),v158);
    h2 = ADD(h2,t_q21);
    d2 = ADD(ADD(t_q21,BS0V(e2)),MAJ(e2,f2,g2));
    V v159 = SIG0V(v129);
    V v160 = SIG1V(v153);
    V v161 = ADD(ADD(ADD(v128,v159),v160),SET1((int)0x00000100u));
    V v162 = ADD(v161,SET1((int)0x5cb0a9dcu));
    V t_q22 = ADD(ADD(ADD(c2,BS1V(h2)),CH(h2,a2,b2)),v162);
    g2 = ADD(g2,t_q22);
    c2 = ADD(ADD(t_q22,BS0V(d2)),MAJ(d2,e2,f2));
    V v163 = SIG1V(v157);
    V v164 = ADD(ADD(ADD(v129,v138),v163),SET1((int)0x11002000u));
    V v165 = ADD(v164,SET1((int)0x76f988dau));
    V t_q23 = ADD(ADD(ADD(b2,BS1V(g2)),CH(g2,h2,a2)),v165);
    f2 = ADD(f2,t_q23);
    b2 = ADD(ADD(t_q23,BS0V(c2)),MAJ(c2,d2,e2));
    V v166 = SIG1V(v161);
    V v167 = ADD(ADD(v141,v166),SET1((int)0x80000000u));
    V v168 = ADD(v167,SET1((int)0x983e5152u));
    V t_q24 = ADD(ADD(ADD(a2,BS1V(f2)),CH(f2,g2,h2)),v168);
    e2 = ADD(e2,t_q24);
    a2 = ADD(ADD(t_q24,BS0V(b2)),MAJ(b2,c2,d2));
    V v169 = SIG1V(v164);
    V v170 = ADD(v145,v169);
    V v171 = ADD(v170,SET1((int)0xa831c66du));
    V t_q25 = ADD(ADD(ADD(h2,BS1V(e2)),CH(e2,f2,g2)),v171);
    d2 = ADD(d2,t_q25);
    h2 = ADD(ADD(t_q25,BS0V(a2)),MAJ(a2,b2,c2));
    V v172 = SIG1V(v167);
    V v173 = ADD(v149,v172);
    V v174 = ADD(v173,SET1((int)0xb00327c8u));
    V t_q26 = ADD(ADD(ADD(g2,BS1V(d2)),CH(d2,e2,f2)),v174);
    c2 = ADD(c2,t_q26);
    g2 = ADD(ADD(t_q26,BS0V(h2)),MAJ(h2,a2,b2));
    V v175 = SIG1V(v170);
    V v176 = ADD(v153,v175);
    V v177 = ADD(v176,SET1((int)0xbf597fc7u));
    V t_q27 = ADD(ADD(ADD(f2,BS1V(c2)),CH(c2,d2,e2)),v177);
    b2 = ADD(b2,t_q27);
    f2 = ADD(ADD(t_q27,BS0V(g2)),MAJ(g2,h2,a2));
    V v178 = SIG1V(v173);
    V v179 = ADD(v157,v178);
    V v180 = ADD(v179,SET1((int)0xc6e00bf3u));
    V t_q28 = ADD(ADD(ADD(e2,BS1V(b2)),CH(b2,c2,d2)),v180);
    a2 = ADD(a2,t_q28);
    e2 = ADD(ADD(t_q28,BS0V(f2)),MAJ(f2,g2,h2));
    V v181 = SIG1V(v176);
    V v182 = ADD(v161,v181);
    V v183 = ADD(v182,SET1((int)0xd5a79147u));
    V t_q29 = ADD(ADD(ADD(d2,BS1V(a2)),CH(a2,b2,c2)),v183);
    h2 = ADD(h2,t_q29);
    d2 = ADD(ADD(t_q29,BS0V(e2)),MAJ(e2,f2,g2));
    V v184 = SIG1V(v179);
    V v185 = ADD(ADD(v164,v184),SET1((int)0x00400022u));
    V v186 = ADD(v185,SET1((int)0x06ca6351u));
    V t_q30 = ADD(ADD(ADD(c2,BS1V(h2)),CH(h2,a2,b2)),v186);
    g2 = ADD(g2,t_q30);
    c2 = ADD(ADD(t_q30,BS0V(d2)),MAJ(d2,e2,f2));
    V v187 = SIG0V(v138);
    V v188 = SIG1V(v182);
    V v189 = ADD(ADD(ADD(v187,v167),v188),SET1((int)0x00000100u));
    V v190 = ADD(v189,SET1((int)0x14292967u));
    V t_q31 = ADD(ADD(ADD(b2,BS1V(g2)),CH(g2,h2,a2)),v190);
    f2 = ADD(f2,t_q31);
    b2 = ADD(ADD(t_q31,BS0V(c2)),MAJ(c2,d2,e2));
    V v191 = SIG0V(v141);
    V v192 = SIG1V(v185);
    V v193 = ADD(ADD(ADD(v138,v191),v170),v192);
    V v194 = ADD(v193,SET1((int)0x27b70a85u));
    V t_q32 = ADD(ADD(ADD(a2,BS1V(f2)),CH(f2,g2,h2)),v194);
    e2 = ADD(e2,t_q32);
    a2 = ADD(ADD(t_q32,BS0V(b2)),MAJ(b2,c2,d2));
    V v195 = SIG0V(v145);
    V v196 = SIG1V(v189);
    V v197 = ADD(ADD(ADD(v141,v195),v173),v196);
    V v198 = ADD(v197,SET1((int)0x2e1b2138u));
    V t_q33 = ADD(ADD(ADD(h2,BS1V(e2)),CH(e2,f2,g2)),v198);
    d2 = ADD(d2,t_q33);
    h2 = ADD(ADD(t_q33,BS0V(a2)),MAJ(a2,b2,c2));
    V v199 = SIG0V(v149);
    V v200 = SIG1V(v193);
    V v201 = ADD(ADD(ADD(v145,v199),v176),v200);
    V v202 = ADD(v201,SET1((int)0x4d2c6dfcu));
    V t_q34 = ADD(ADD(ADD(g2,BS1V(d2)),CH(d2,e2,f2)),v202);
    c2 = ADD(c2,t_q34);
    g2 = ADD(ADD(t_q34,BS0V(h2)),MAJ(h2,a2,b2));
    V v203 = SIG0V(v153);
    V v204 = SIG1V(v197);
    V v205 = ADD(ADD(ADD(v149,v203),v179),v204);
    V v206 = ADD(v205,SET1((int)0x53380d13u));
    V t_q35 = ADD(ADD(ADD(f2,BS1V(c2)),CH(c2,d2,e2)),v206);
    b2 = ADD(b2,t_q35);
    f2 = ADD(ADD(t_q35,BS0V(g2)),MAJ(g2,h2,a2));
    V v207 = SIG0V(v157);
    V v208 = SIG1V(v201);
    V v209 = ADD(ADD(ADD(v153,v207),v182),v208);
    V v210 = ADD(v209,SET1((int)0x650a7354u));
    V t_q36 = ADD(ADD(ADD(e2,BS1V(b2)),CH(b2,c2,d2)),v210);
    a2 = ADD(a2,t_q36);
    e2 = ADD(ADD(t_q36,BS0V(f2)),MAJ(f2,g2,h2));
    V v211 = SIG0V(v161);
    V v212 = SIG1V(v205);
    V v213 = ADD(ADD(ADD(v157,v211),v185),v212);
    V v214 = ADD(v213,SET1((int)0x766a0abbu));
    V t_q37 = ADD(ADD(ADD(d2,BS1V(a2)),CH(a2,b2,c2)),v214);
    h2 = ADD(h2,t_q37);
    d2 = ADD(ADD(t_q37,BS0V(e2)),MAJ(e2,f2,g2));
    V v215 = SIG0V(v164);
    V v216 = SIG1V(v209);
    V v217 = ADD(ADD(ADD(v161,v215),v189),v216);
    V v218 = ADD(v217,SET1((int)0x81c2c92eu));
    V t_q38 = ADD(ADD(ADD(c2,BS1V(h2)),CH(h2,a2,b2)),v218);
    g2 = ADD(g2,t_q38);
    c2 = ADD(ADD(t_q38,BS0V(d2)),MAJ(d2,e2,f2));
    V v219 = SIG0V(v167);
    V v220 = SIG1V(v213);
    V v221 = ADD(ADD(ADD(v164,v219),v193),v220);
    V v222 = ADD(v221,SET1((int)0x92722c85u));
    V t_q39 = ADD(ADD(ADD(b2,BS1V(g2)),CH(g2,h2,a2)),v222);
    f2 = ADD(f2,t_q39);
    b2 = ADD(ADD(t_q39,BS0V(c2)),MAJ(c2,d2,e2));
    V v223 = SIG0V(v170);
    V v224 = SIG1V(v217);
    V v225 = ADD(ADD(ADD(v167,v223),v197),v224);
    V v226 = ADD(v225,SET1((int)0xa2bfe8a1u));
    V t_q40 = ADD(ADD(ADD(a2,BS1V(f2)),CH(f2,g2,h2)),v226);
    e2 = ADD(e2,t_q40);
    a2 = ADD(ADD(t_q40,BS0V(b2)),MAJ(b2,c2,d2));
    V v227 = SIG0V(v173);
    V v228 = SIG1V(v221);
    V v229 = ADD(ADD(ADD(v170,v227),v201),v228);
    V v230 = ADD(v229,SET1((int)0xa81a664bu));
    V t_q41 = ADD(ADD(ADD(h2,BS1V(e2)),CH(e2,f2,g2)),v230);
    d2 = ADD(d2,t_q41);
    h2 = ADD(ADD(t_q41,BS0V(a2)),MAJ(a2,b2,c2));
    V v231 = SIG0V(v176);
    V v232 = SIG1V(v225);
    V v233 = ADD(ADD(ADD(v173,v231),v205),v232);
    V v234 = ADD(v233,SET1((int)0xc24b8b70u));
    V t_q42 = ADD(ADD(ADD(g2,BS1V(d2)),CH(d2,e2,f2)),v234);
    c2 = ADD(c2,t_q42);
    g2 = ADD(ADD(t_q42,BS0V(h2)),MAJ(h2,a2,b2));
    V v235 = SIG0V(v179);
    V v236 = SIG1V(v229);
    V v237 = ADD(ADD(ADD(v176,v235),v209),v236);
    V v238 = ADD(v237,SET1((int)0xc76c51a3u));
    V t_q43 = ADD(ADD(ADD(f2,BS1V(c2)),CH(c2,d2,e2)),v238);
    b2 = ADD(b2,t_q43);
    f2 = ADD(ADD(t_q43,BS0V(g2)),MAJ(g2,h2,a2));
    V v239 = SIG0V(v182);
    V v240 = SIG1V(v233);
    V v241 = ADD(ADD(ADD(v179,v239),v213),v240);
    V v242 = ADD(v241,SET1((int)0xd192e819u));
    V t_q44 = ADD(ADD(ADD(e2,BS1V(b2)),CH(b2,c2,d2)),v242);
    a2 = ADD(a2,t_q44);
    e2 = ADD(ADD(t_q44,BS0V(f2)),MAJ(f2,g2,h2));
    V v243 = SIG0V(v185);
    V v244 = SIG1V(v237);
    V v245 = ADD(ADD(ADD(v182,v243),v217),v244);
    V v246 = ADD(v245,SET1((int)0xd6990624u));
    V t_q45 = ADD(ADD(ADD(d2,BS1V(a2)),CH(a2,b2,c2)),v246);
    h2 = ADD(h2,t_q45);
    d2 = ADD(ADD(t_q45,BS0V(e2)),MAJ(e2,f2,g2));
    V v247 = SIG0V(v189);
    V v248 = SIG1V(v241);
    V v249 = ADD(ADD(ADD(v185,v247),v221),v248);
    V v250 = ADD(v249,SET1((int)0xf40e3585u));
    V t_q46 = ADD(ADD(ADD(c2,BS1V(h2)),CH(h2,a2,b2)),v250);
    g2 = ADD(g2,t_q46);
    c2 = ADD(ADD(t_q46,BS0V(d2)),MAJ(d2,e2,f2));
    V v251 = SIG0V(v193);
    V v252 = SIG1V(v245);
    V v253 = ADD(ADD(ADD(v189,v251),v225),v252);
    V v254 = ADD(v253,SET1((int)0x106aa070u));
    V t_q47 = ADD(ADD(ADD(b2,BS1V(g2)),CH(g2,h2,a2)),v254);
    f2 = ADD(f2,t_q47);
    b2 = ADD(ADD(t_q47,BS0V(c2)),MAJ(c2,d2,e2));
    V v255 = SIG0V(v197);
    V v256 = SIG1V(v249);
    V v257 = ADD(ADD(ADD(v193,v255),v229),v256);
    V v258 = ADD(v257,SET1((int)0x19a4c116u));
    V t_q48 = ADD(ADD(ADD(a2,BS1V(f2)),CH(f2,g2,h2)),v258);
    e2 = ADD(e2,t_q48);
    a2 = ADD(ADD(t_q48,BS0V(b2)),MAJ(b2,c2,d2));
    V v259 = SIG0V(v201);
    V v260 = SIG1V(v253);
    V v261 = ADD(ADD(ADD(v197,v259),v233),v260);
    V v262 = ADD(v261,SET1((int)0x1e376c08u));
    V t_q49 = ADD(ADD(ADD(h2,BS1V(e2)),CH(e2,f2,g2)),v262);
    d2 = ADD(d2,t_q49);
    h2 = ADD(ADD(t_q49,BS0V(a2)),MAJ(a2,b2,c2));
    V v263 = SIG0V(v205);
    V v264 = SIG1V(v257);
    V v265 = ADD(ADD(ADD(v201,v263),v237),v264);
    V v266 = ADD(v265,SET1((int)0x2748774cu));
    V t_q50 = ADD(ADD(ADD(g2,BS1V(d2)),CH(d2,e2,f2)),v266);
    c2 = ADD(c2,t_q50);
    g2 = ADD(ADD(t_q50,BS0V(h2)),MAJ(h2,a2,b2));
    V v267 = SIG0V(v209);
    V v268 = SIG1V(v261);
    V v269 = ADD(ADD(ADD(v205,v267),v241),v268);
    V v270 = ADD(v269,SET1((int)0x34b0bcb5u));
    V t_q51 = ADD(ADD(ADD(f2,BS1V(c2)),CH(c2,d2,e2)),v270);
    b2 = ADD(b2,t_q51);
    f2 = ADD(ADD(t_q51,BS0V(g2)),MAJ(g2,h2,a2));
    V v271 = SIG0V(v213);
    V v272 = SIG1V(v265);
    V v273 = ADD(ADD(ADD(v209,v271),v245),v272);
    V v274 = ADD(v273,SET1((int)0x391c0cb3u));
    V t_q52 = ADD(ADD(ADD(e2,BS1V(b2)),CH(b2,c2,d2)),v274);
    a2 = ADD(a2,t_q52);
    e2 = ADD(ADD(t_q52,BS0V(f2)),MAJ(f2,g2,h2));
    V v275 = SIG0V(v217);
    V v276 = SIG1V(v269);
    V v277 = ADD(ADD(ADD(v213,v275),v249),v276);
    V v278 = ADD(v277,SET1((int)0x4ed8aa4au));
    V t_q53 = ADD(ADD(ADD(d2,BS1V(a2)),CH(a2,b2,c2)),v278);
    h2 = ADD(h2,t_q53);
    d2 = ADD(ADD(t_q53,BS0V(e2)),MAJ(e2,f2,g2));
    V v279 = SIG0V(v221);
    V v280 = SIG1V(v273);
    V v281 = ADD(ADD(ADD(v217,v279),v253),v280);
    V v282 = ADD(v281,SET1((int)0x5b9cca4fu));
    V t_q54 = ADD(ADD(ADD(c2,BS1V(h2)),CH(h2,a2,b2)),v282);
    g2 = ADD(g2,t_q54);
    c2 = ADD(ADD(t_q54,BS0V(d2)),MAJ(d2,e2,f2));
    V v283 = SIG0V(v225);
    V v284 = SIG1V(v277);
    V v285 = ADD(ADD(ADD(v221,v283),v257),v284);
    V v286 = ADD(v285,SET1((int)0x682e6ff3u));
    V t_q55 = ADD(ADD(ADD(b2,BS1V(g2)),CH(g2,h2,a2)),v286);
    f2 = ADD(f2,t_q55);
    b2 = ADD(ADD(t_q55,BS0V(c2)),MAJ(c2,d2,e2));
    V v287 = SIG0V(v229);
    V v288 = SIG1V(v281);
    V v289 = ADD(ADD(ADD(v225,v287),v261),v288);
    V v290 = ADD(v289,SET1((int)0x748f82eeu));
    V t_q56 = ADD(ADD(ADD(a2,BS1V(f2)),CH(f2,g2,h2)),v290);
    e2 = ADD(e2,t_q56);
    a2 = ADD(ADD(t_q56,BS0V(b2)),MAJ(b2,c2,d2));
    V v291 = SIG0V(v233);
    V v292 = SIG1V(v285);
    V v293 = ADD(ADD(ADD(v229,v291),v265),v292);
    V v294 = ADD(v293,SET1((int)0x78a5636fu));
    V t_q57 = ADD(ADD(ADD(h2,BS1V(e2)),CH(e2,f2,g2)),v294);
    d2 = ADD(d2,t_q57);
    V v295 = SIG0V(v237);
    V v296 = SIG1V(v289);
    V v297 = ADD(ADD(ADD(v233,v295),v269),v296);
    V v298 = ADD(v297,SET1((int)0x84c87814u));
    V t_q58 = ADD(ADD(ADD(g2,BS1V(d2)),CH(d2,e2,f2)),v298);
    c2 = ADD(c2,t_q58);
    V v299 = SIG0V(v241);
    V v300 = SIG1V(v293);
    V v301 = ADD(ADD(ADD(v237,v299),v273),v300);
    V v302 = ADD(v301,SET1((int)0x8cc70208u));
    V t_q59 = ADD(ADD(ADD(f2,BS1V(c2)),CH(c2,d2,e2)),v302);
    b2 = ADD(b2,t_q59);
    V v303 = SIG0V(v245);
    V v304 = SIG1V(v297);
    V v305 = ADD(ADD(ADD(v241,v303),v277),v304);
    V v306 = ADD(v305,SET1((int)0x90befffau));
    V t_q60 = ADD(ADD(ADD(e2,BS1V(b2)),CH(b2,c2,d2)),v306);
    a2 = ADD(a2,t_q60);
    return ADD(a2,SET1((int)0x5be0cd19u));
}
static uint64_t scan_avx512vl(const uint8_t *hdr, uint32_t start, uint64_t count, uint32_t mask, int M){
  uint32_t c[NC]; uint8_t hdrv[MAXM][76]; uint32_t ver[MAXM]; VS vs[MAXM];
  M=setup_versions(hdr,mask,M,hdrv,ver);
  prepare_shared(hdr,c); for(int j=0;j<M;j++) prepare_ver(hdrv[j],&vs[j]);
  V nv=ADD(SET1((int)start),LANEIDX); const V step=SET1(8); V KW[64];
  uint64_t hits=0;
  for(uint64_t base=0;base<count;base+=8){
    sched_avx512vl(c,BSWAP(nv),KW);
    for(int j=0;j<M;j++){
      unsigned mk=CMPZ(hash_avx512vl(c,&vs[j],KW));
      if(mk) for(int lane=0;lane<8;lane++) if(((mk>>lane)&1) && base+(uint64_t)lane<count)
        hits+=report_hit(hdrv[j],start+(uint32_t)(base+(uint64_t)lane),ver[j]);
    }
    nv=ADD(nv,step);
  }
  return hits;
}
static int test_avx512vl(void){
  uint64_t x=88172645463325252ULL; long checked=0,bad=0;
  for(int trial=0;trial<6;trial++){
    uint8_t hdr[76]; for(int i=0;i<76;i++){x^=x<<13;x^=x>>7;x^=x<<17;hdr[i]=(uint8_t)x;}
    uint32_t mask=0x1fffe000u,start=(uint32_t)x; int M=(trial%2)?16:8;
    uint32_t c[NC]; uint8_t hdrv[MAXM][76]; uint32_t ver[MAXM]; VS vs[MAXM];
    M=setup_versions(hdr,mask,M,hdrv,ver); prepare_shared(hdr,c); for(int j=0;j<M;j++) prepare_ver(hdrv[j],&vs[j]);
    V KW[64];
    for(uint32_t base=0;base<4096;base+=8){
      uint32_t ns[8]; for(int l=0;l<8;l++) ns[l]=start+base+l;
      sched_avx512vl(c,BSWAP(LOADU(ns)),KW);
      for(int j=0;j<M;j++){
        uint32_t out[8]; STOREU(out,hash_avx512vl(c,&vs[j],KW));
        for(int l=0;l<8;l++){ uint32_t s[8]; scalar_hash(hdrv[j],ns[l],s); checked++; if(s[7]!=out[l]) bad++; }
      }
    }
  }
  if(bad){ printf("%s: HATA checked=%ld bad=%ld\n","avx512vl",checked,bad); return 1; }
  printf("%s: OK checked=%ld\n","avx512vl",checked); return 0;
}
#undef V
#undef ADD
#undef XOR
#undef AND
#undef OR
#undef SHR
#undef SHL
#undef ROR
#undef T3
#undef SIG0V
#undef SIG1V
#undef BS0V
#undef BS1V
#undef CH
#undef MAJ
#undef SET1
#undef BSWAP
#undef LANEIDX
#undef LOADU
#undef STOREU
#undef CMPZ
#pragma GCC pop_options

/* ===== motor avx512 (16 serit) ===== */
#pragma GCC push_options
#pragma GCC target("avx2,avx512f,avx512bw,avx512vl")
#define V __m512i
#define ADD(a,b) _mm512_add_epi32(a,b)
#define XOR(a,b) _mm512_xor_si512(a,b)
#define SHR(x,n) _mm512_srli_epi32(x,n)
#define ROR(x,n) _mm512_ror_epi32(x,n)
#define T3(a,b,c,i) _mm512_ternarylogic_epi32(a,b,c,i)
#define SIG0V(x) T3(ROR(x,7),ROR(x,18),SHR(x,3),0x96)
#define SIG1V(x) T3(ROR(x,17),ROR(x,19),SHR(x,10),0x96)
#define BS0V(x) T3(ROR(x,2),ROR(x,13),ROR(x,22),0x96)
#define BS1V(x) T3(ROR(x,6),ROR(x,11),ROR(x,25),0x96)
#define CH(e,f,g) T3(e,f,g,0xCA)
#define MAJ(a,b,c) T3(a,b,c,0xE8)
#define SET1(x) _mm512_set1_epi32(x)
#define BSWAP(x) _mm512_shuffle_epi8(x,_mm512_broadcast_i32x4(_mm_setr_epi8(3,2,1,0,7,6,5,4,11,10,9,8,15,14,13,12)))
#define LANEIDX _mm512_setr_epi32(0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15)
#define LOADU(p) _mm512_loadu_si512((const void*)(p))
#define STOREU(p,x) _mm512_storeu_si512((void*)(p),x)
#define CMPZ(x) ((unsigned)_mm512_cmpeq_epi32_mask(x,_mm512_setzero_si512()))
static inline void sched_avx512(const uint32_t *c, V nonce, V *KW){
    V nonce_w3 = nonce;
    KW[3] = ADD(nonce_w3,SET1((int)0xe9b5dba5u));
    V v0 = SIG0V(nonce_w3);
    V v1 = ADD(v0,SET1((int)c[26]));
    KW[18] = ADD(v1,SET1((int)0x0fc19dc6u));
    V v2 = ADD(nonce_w3,SET1((int)c[28]));
    KW[19] = ADD(v2,SET1((int)0x240ca1ccu));
    V v3 = SIG1V(v1);
    V v4 = ADD(v3,SET1((int)0x80000000u));
    KW[20] = ADD(v4,SET1((int)0x2de92c6fu));
    V v5 = SIG1V(v2);
    V v6 = v5;
    KW[21] = ADD(v6,SET1((int)0x4a7484aau));
    V v7 = SIG1V(v4);
    V v8 = ADD(v7,SET1((int)0x00000280u));
    KW[22] = ADD(v8,SET1((int)0x5cb0a9dcu));
    V v9 = SIG1V(v6);
    V v10 = ADD(v9,SET1((int)c[20]));
    KW[23] = ADD(v10,SET1((int)0x76f988dau));
    V v11 = SIG1V(v8);
    V v12 = ADD(v11,SET1((int)c[23]));
    KW[24] = ADD(v12,SET1((int)0x983e5152u));
    V v13 = SIG1V(v10);
    V v14 = ADD(v1,v13);
    KW[25] = ADD(v14,SET1((int)0xa831c66du));
    V v15 = SIG1V(v12);
    V v16 = ADD(v2,v15);
    KW[26] = ADD(v16,SET1((int)0xb00327c8u));
    V v17 = SIG1V(v14);
    V v18 = ADD(v4,v17);
    KW[27] = ADD(v18,SET1((int)0xbf597fc7u));
    V v19 = SIG1V(v16);
    V v20 = ADD(v6,v19);
    KW[28] = ADD(v20,SET1((int)0xc6e00bf3u));
    V v21 = SIG1V(v18);
    V v22 = ADD(v8,v21);
    KW[29] = ADD(v22,SET1((int)0xd5a79147u));
    V v23 = SIG1V(v20);
    V v24 = ADD(ADD(v10,v23),SET1((int)0x00a00055u));
    KW[30] = ADD(v24,SET1((int)0x06ca6351u));
    V v25 = SIG1V(v22);
    V v26 = ADD(ADD(v12,v25),SET1((int)c[30]));
    KW[31] = ADD(v26,SET1((int)0x14292967u));
    V v27 = SIG1V(v24);
    V v28 = ADD(ADD(v14,v27),SET1((int)c[32]));
    KW[32] = ADD(v28,SET1((int)0x27b70a85u));
    V v29 = SIG0V(v1);
    V v30 = SIG1V(v26);
    V v31 = ADD(ADD(ADD(v29,v16),v30),SET1((int)c[23]));
    KW[33] = ADD(v31,SET1((int)0x2e1b2138u));
    V v32 = SIG0V(v2);
    V v33 = SIG1V(v28);
    V v34 = ADD(ADD(ADD(v1,v32),v18),v33);
    KW[34] = ADD(v34,SET1((int)0x4d2c6dfcu));
    V v35 = SIG0V(v4);
    V v36 = SIG1V(v31);
    V v37 = ADD(ADD(ADD(v2,v35),v20),v36);
    KW[35] = ADD(v37,SET1((int)0x53380d13u));
    V v38 = SIG0V(v6);
    V v39 = SIG1V(v34);
    V v40 = ADD(ADD(ADD(v4,v38),v22),v39);
    KW[36] = ADD(v40,SET1((int)0x650a7354u));
    V v41 = SIG0V(v8);
    V v42 = SIG1V(v37);
    V v43 = ADD(ADD(ADD(v6,v41),v24),v42);
    KW[37] = ADD(v43,SET1((int)0x766a0abbu));
    V v44 = SIG0V(v10);
    V v45 = SIG1V(v40);
    V v46 = ADD(ADD(ADD(v8,v44),v26),v45);
    KW[38] = ADD(v46,SET1((int)0x81c2c92eu));
    V v47 = SIG0V(v12);
    V v48 = SIG1V(v43);
    V v49 = ADD(ADD(ADD(v10,v47),v28),v48);
    KW[39] = ADD(v49,SET1((int)0x92722c85u));
    V v50 = SIG0V(v14);
    V v51 = SIG1V(v46);
    V v52 = ADD(ADD(ADD(v12,v50),v31),v51);
    KW[40] = ADD(v52,SET1((int)0xa2bfe8a1u));
    V v53 = SIG0V(v16);
    V v54 = SIG1V(v49);
    V v55 = ADD(ADD(ADD(v14,v53),v34),v54);
    KW[41] = ADD(v55,SET1((int)0xa81a664bu));
    V v56 = SIG0V(v18);
    V v57 = SIG1V(v52);
    V v58 = ADD(ADD(ADD(v16,v56),v37),v57);
    KW[42] = ADD(v58,SET1((int)0xc24b8b70u));
    V v59 = SIG0V(v20);
    V v60 = SIG1V(v55);
    V v61 = ADD(ADD(ADD(v18,v59),v40),v60);
    KW[43] = ADD(v61,SET1((int)0xc76c51a3u));
    V v62 = SIG0V(v22);
    V v63 = SIG1V(v58);
    V v64 = ADD(ADD(ADD(v20,v62),v43),v63);
    KW[44] = ADD(v64,SET1((int)0xd192e819u));
    V v65 = SIG0V(v24);
    V v66 = SIG1V(v61);
    V v67 = ADD(ADD(ADD(v22,v65),v46),v66);
    KW[45] = ADD(v67,SET1((int)0xd6990624u));
    V v68 = SIG0V(v26);
    V v69 = SIG1V(v64);
    V v70 = ADD(ADD(ADD(v24,v68),v49),v69);
    KW[46] = ADD(v70,SET1((int)0xf40e3585u));
    V v71 = SIG0V(v28);
    V v72 = SIG1V(v67);
    V v73 = ADD(ADD(ADD(v26,v71),v52),v72);
    KW[47] = ADD(v73,SET1((int)0x106aa070u));
    V v74 = SIG0V(v31);
    V v75 = SIG1V(v70);
    V v76 = ADD(ADD(ADD(v28,v74),v55),v75);
    KW[48] = ADD(v76,SET1((int)0x19a4c116u));
    V v77 = SIG0V(v34);
    V v78 = SIG1V(v73);
    V v79 = ADD(ADD(ADD(v31,v77),v58),v78);
    KW[49] = ADD(v79,SET1((int)0x1e376c08u));
    V v80 = SIG0V(v37);
    V v81 = SIG1V(v76);
    V v82 = ADD(ADD(ADD(v34,v80),v61),v81);
    KW[50] = ADD(v82,SET1((int)0x2748774cu));
    V v83 = SIG0V(v40);
    V v84 = SIG1V(v79);
    V v85 = ADD(ADD(ADD(v37,v83),v64),v84);
    KW[51] = ADD(v85,SET1((int)0x34b0bcb5u));
    V v86 = SIG0V(v43);
    V v87 = SIG1V(v82);
    V v88 = ADD(ADD(ADD(v40,v86),v67),v87);
    KW[52] = ADD(v88,SET1((int)0x391c0cb3u));
    V v89 = SIG0V(v46);
    V v90 = SIG1V(v85);
    V v91 = ADD(ADD(ADD(v43,v89),v70),v90);
    KW[53] = ADD(v91,SET1((int)0x4ed8aa4au));
    V v92 = SIG0V(v49);
    V v93 = SIG1V(v88);
    V v94 = ADD(ADD(ADD(v46,v92),v73),v93);
    KW[54] = ADD(v94,SET1((int)0x5b9cca4fu));
    V v95 = SIG0V(v52);
    V v96 = SIG1V(v91);
    V v97 = ADD(ADD(ADD(v49,v95),v76),v96);
    KW[55] = ADD(v97,SET1((int)0x682e6ff3u));
    V v98 = SIG0V(v55);
    V v99 = SIG1V(v94);
    V v100 = ADD(ADD(ADD(v52,v98),v79),v99);
    KW[56] = ADD(v100,SET1((int)0x748f82eeu));
    V v101 = SIG0V(v58);
    V v102 = SIG1V(v97);
    V v103 = ADD(ADD(ADD(v55,v101),v82),v102);
    KW[57] = ADD(v103,SET1((int)0x78a5636fu));
    V v104 = SIG0V(v61);
    V v105 = SIG1V(v100);
    V v106 = ADD(ADD(ADD(v58,v104),v85),v105);
    KW[58] = ADD(v106,SET1((int)0x84c87814u));
    V v107 = SIG0V(v64);
    V v108 = SIG1V(v103);
    V v109 = ADD(ADD(ADD(v61,v107),v88),v108);
    KW[59] = ADD(v109,SET1((int)0x8cc70208u));
    V v110 = SIG0V(v67);
    V v111 = SIG1V(v106);
    V v112 = ADD(ADD(ADD(v64,v110),v91),v111);
    KW[60] = ADD(v112,SET1((int)0x90befffau));
    V v113 = SIG0V(v70);
    V v114 = SIG1V(v109);
    V v115 = ADD(ADD(ADD(v67,v113),v94),v114);
    KW[61] = ADD(v115,SET1((int)0xa4506cebu));
    V v116 = SIG0V(v73);
    V v117 = SIG1V(v112);
    V v118 = ADD(ADD(ADD(v70,v116),v97),v117);
    KW[62] = ADD(v118,SET1((int)0xbef9a3f7u));
    V v119 = SIG0V(v76);
    V v120 = SIG1V(v115);
    V v121 = ADD(ADD(ADD(v73,v119),v100),v120);
    KW[63] = ADD(v121,SET1((int)0xc67178f2u));
}
static inline V hash_avx512(const uint32_t *c, const VS *vs, const V *KW){
    V a1 = SET1((int)vs->st3[0]);
    V b1 = SET1((int)vs->st3[1]);
    V c1 = SET1((int)vs->st3[2]);
    V d1 = SET1((int)vs->st3[3]);
    V e1 = SET1((int)vs->st3[4]);
    V f1 = SET1((int)vs->st3[5]);
    V g1 = SET1((int)vs->st3[6]);
    V h1 = SET1((int)vs->st3[7]);
    V t_p3 = ADD(ADD(ADD(h1,BS1V(e1)),CH(e1,f1,g1)),KW[3]);
    d1 = ADD(d1,t_p3);
    h1 = ADD(ADD(t_p3,BS0V(a1)),MAJ(a1,b1,c1));
    V t_p4 = ADD(ADD(ADD(g1,BS1V(d1)),CH(d1,e1,f1)),SET1((int)0xb956c25bu));
    c1 = ADD(c1,t_p4);
    g1 = ADD(ADD(t_p4,BS0V(h1)),MAJ(h1,a1,b1));
    V t_p5 = ADD(ADD(ADD(f1,BS1V(c1)),CH(c1,d1,e1)),SET1((int)0x59f111f1u));
    b1 = ADD(b1,t_p5);
    f1 = ADD(ADD(t_p5,BS0V(g1)),MAJ(g1,h1,a1));
    V t_p6 = ADD(ADD(ADD(e1,BS1V(b1)),CH(b1,c1,d1)),SET1((int)0x923f82a4u));
    a1 = ADD(a1,t_p6);
    e1 = ADD(ADD(t_p6,BS0V(f1)),MAJ(f1,g1,h1));
    V t_p7 = ADD(ADD(ADD(d1,BS1V(a1)),CH(a1,b1,c1)),SET1((int)0xab1c5ed5u));
    h1 = ADD(h1,t_p7);
    d1 = ADD(ADD(t_p7,BS0V(e1)),MAJ(e1,f1,g1));
    V t_p8 = ADD(ADD(ADD(c1,BS1V(h1)),CH(h1,a1,b1)),SET1((int)0xd807aa98u));
    g1 = ADD(g1,t_p8);
    c1 = ADD(ADD(t_p8,BS0V(d1)),MAJ(d1,e1,f1));
    V t_p9 = ADD(ADD(ADD(b1,BS1V(g1)),CH(g1,h1,a1)),SET1((int)0x12835b01u));
    f1 = ADD(f1,t_p9);
    b1 = ADD(ADD(t_p9,BS0V(c1)),MAJ(c1,d1,e1));
    V t_p10 = ADD(ADD(ADD(a1,BS1V(f1)),CH(f1,g1,h1)),SET1((int)0x243185beu));
    e1 = ADD(e1,t_p10);
    a1 = ADD(ADD(t_p10,BS0V(b1)),MAJ(b1,c1,d1));
    V t_p11 = ADD(ADD(ADD(h1,BS1V(e1)),CH(e1,f1,g1)),SET1((int)0x550c7dc3u));
    d1 = ADD(d1,t_p11);
    h1 = ADD(ADD(t_p11,BS0V(a1)),MAJ(a1,b1,c1));
    V t_p12 = ADD(ADD(ADD(g1,BS1V(d1)),CH(d1,e1,f1)),SET1((int)0x72be5d74u));
    c1 = ADD(c1,t_p12);
    g1 = ADD(ADD(t_p12,BS0V(h1)),MAJ(h1,a1,b1));
    V t_p13 = ADD(ADD(ADD(f1,BS1V(c1)),CH(c1,d1,e1)),SET1((int)0x80deb1feu));
    b1 = ADD(b1,t_p13);
    f1 = ADD(ADD(t_p13,BS0V(g1)),MAJ(g1,h1,a1));
    V t_p14 = ADD(ADD(ADD(e1,BS1V(b1)),CH(b1,c1,d1)),SET1((int)0x9bdc06a7u));
    a1 = ADD(a1,t_p14);
    e1 = ADD(ADD(t_p14,BS0V(f1)),MAJ(f1,g1,h1));
    V t_p15 = ADD(ADD(ADD(d1,BS1V(a1)),CH(a1,b1,c1)),SET1((int)0xc19bf3f4u));
    h1 = ADD(h1,t_p15);
    d1 = ADD(ADD(t_p15,BS0V(e1)),MAJ(e1,f1,g1));
    V t_p16 = ADD(ADD(ADD(c1,BS1V(h1)),CH(h1,a1,b1)),SET1((int)c[21]));
    g1 = ADD(g1,t_p16);
    c1 = ADD(ADD(t_p16,BS0V(d1)),MAJ(d1,e1,f1));
    V t_p17 = ADD(ADD(ADD(b1,BS1V(g1)),CH(g1,h1,a1)),SET1((int)c[24]));
    f1 = ADD(f1,t_p17);
    b1 = ADD(ADD(t_p17,BS0V(c1)),MAJ(c1,d1,e1));
    V t_p18 = ADD(ADD(ADD(a1,BS1V(f1)),CH(f1,g1,h1)),KW[18]);
    e1 = ADD(e1,t_p18);
    a1 = ADD(ADD(t_p18,BS0V(b1)),MAJ(b1,c1,d1));
    V t_p19 = ADD(ADD(ADD(h1,BS1V(e1)),CH(e1,f1,g1)),KW[19]);
    d1 = ADD(d1,t_p19);
    h1 = ADD(ADD(t_p19,BS0V(a1)),MAJ(a1,b1,c1));
    V t_p20 = ADD(ADD(ADD(g1,BS1V(d1)),CH(d1,e1,f1)),KW[20]);
    c1 = ADD(c1,t_p20);
    g1 = ADD(ADD(t_p20,BS0V(h1)),MAJ(h1,a1,b1));
    V t_p21 = ADD(ADD(ADD(f1,BS1V(c1)),CH(c1,d1,e1)),KW[21]);
    b1 = ADD(b1,t_p21);
    f1 = ADD(ADD(t_p21,BS0V(g1)),MAJ(g1,h1,a1));
    V t_p22 = ADD(ADD(ADD(e1,BS1V(b1)),CH(b1,c1,d1)),KW[22]);
    a1 = ADD(a1,t_p22);
    e1 = ADD(ADD(t_p22,BS0V(f1)),MAJ(f1,g1,h1));
    V t_p23 = ADD(ADD(ADD(d1,BS1V(a1)),CH(a1,b1,c1)),KW[23]);
    h1 = ADD(h1,t_p23);
    d1 = ADD(ADD(t_p23,BS0V(e1)),MAJ(e1,f1,g1));
    V t_p24 = ADD(ADD(ADD(c1,BS1V(h1)),CH(h1,a1,b1)),KW[24]);
    g1 = ADD(g1,t_p24);
    c1 = ADD(ADD(t_p24,BS0V(d1)),MAJ(d1,e1,f1));
    V t_p25 = ADD(ADD(ADD(b1,BS1V(g1)),CH(g1,h1,a1)),KW[25]);
    f1 = ADD(f1,t_p25);
    b1 = ADD(ADD(t_p25,BS0V(c1)),MAJ(c1,d1,e1));
    V t_p26 = ADD(ADD(ADD(a1,BS1V(f1)),CH(f1,g1,h1)),KW[26]);
    e1 = ADD(e1,t_p26);
    a1 = ADD(ADD(t_p26,BS0V(b1)),MAJ(b1,c1,d1));
    V t_p27 = ADD(ADD(ADD(h1,BS1V(e1)),CH(e1,f1,g1)),KW[27]);
    d1 = ADD(d1,t_p27);
    h1 = ADD(ADD(t_p27,BS0V(a1)),MAJ(a1,b1,c1));
    V t_p28 = ADD(ADD(ADD(g1,BS1V(d1)),CH(d1,e1,f1)),KW[28]);
    c1 = ADD(c1,t_p28);
    g1 = ADD(ADD(t_p28,BS0V(h1)),MAJ(h1,a1,b1));
    V t_p29 = ADD(ADD(ADD(f1,BS1V(c1)),CH(c1,d1,e1)),KW[29]);
    b1 = ADD(b1,t_p29);
    f1 = ADD(ADD(t_p29,BS0V(g1)),MAJ(g1,h1,a1));
    V t_p30 = ADD(ADD(ADD(e1,BS1V(b1)),CH(b1,c1,d1)),KW[30]);
    a1 = ADD(a1,t_p30);
    e1 = ADD(ADD(t_p30,BS0V(f1)),MAJ(f1,g1,h1));
    V t_p31 = ADD(ADD(ADD(d1,BS1V(a1)),CH(a1,b1,c1)),KW[31]);
    h1 = ADD(h1,t_p31);
    d1 = ADD(ADD(t_p31,BS0V(e1)),MAJ(e1,f1,g1));
    V t_p32 = ADD(ADD(ADD(c1,BS1V(h1)),CH(h1,a1,b1)),KW[32]);
    g1 = ADD(g1,t_p32);
    c1 = ADD(ADD(t_p32,BS0V(d1)),MAJ(d1,e1,f1));
    V t_p33 = ADD(ADD(ADD(b1,BS1V(g1)),CH(g1,h1,a1)),KW[33]);
    f1 = ADD(f1,t_p33);
    b1 = ADD(ADD(t_p33,BS0V(c1)),MAJ(c1,d1,e1));
    V t_p34 = ADD(ADD(ADD(a1,BS1V(f1)),CH(f1,g1,h1)),KW[34]);
    e1 = ADD(e1,t_p34);
    a1 = ADD(ADD(t_p34,BS0V(b1)),MAJ(b1,c1,d1));
    V t_p35 = ADD(ADD(ADD(h1,BS1V(e1)),CH(e1,f1,g1)),KW[35]);
    d1 = ADD(d1,t_p35);
    h1 = ADD(ADD(t_p35,BS0V(a1)),MAJ(a1,b1,c1));
    V t_p36 = ADD(ADD(ADD(g1,BS1V(d1)),CH(d1,e1,f1)),KW[36]);
    c1 = ADD(c1,t_p36);
    g1 = ADD(ADD(t_p36,BS0V(h1)),MAJ(h1,a1,b1));
    V t_p37 = ADD(ADD(ADD(f1,BS1V(c1)),CH(c1,d1,e1)),KW[37]);
    b1 = ADD(b1,t_p37);
    f1 = ADD(ADD(t_p37,BS0V(g1)),MAJ(g1,h1,a1));
    V t_p38 = ADD(ADD(ADD(e1,BS1V(b1)),CH(b1,c1,d1)),KW[38]);
    a1 = ADD(a1,t_p38);
    e1 = ADD(ADD(t_p38,BS0V(f1)),MAJ(f1,g1,h1));
    V t_p39 = ADD(ADD(ADD(d1,BS1V(a1)),CH(a1,b1,c1)),KW[39]);
    h1 = ADD(h1,t_p39);
    d1 = ADD(ADD(t_p39,BS0V(e1)),MAJ(e1,f1,g1));
    V t_p40 = ADD(ADD(ADD(c1,BS1V(h1)),CH(h1,a1,b1)),KW[40]);
    g1 = ADD(g1,t_p40);
    c1 = ADD(ADD(t_p40,BS0V(d1)),MAJ(d1,e1,f1));
    V t_p41 = ADD(ADD(ADD(b1,BS1V(g1)),CH(g1,h1,a1)),KW[41]);
    f1 = ADD(f1,t_p41);
    b1 = ADD(ADD(t_p41,BS0V(c1)),MAJ(c1,d1,e1));
    V t_p42 = ADD(ADD(ADD(a1,BS1V(f1)),CH(f1,g1,h1)),KW[42]);
    e1 = ADD(e1,t_p42);
    a1 = ADD(ADD(t_p42,BS0V(b1)),MAJ(b1,c1,d1));
    V t_p43 = ADD(ADD(ADD(h1,BS1V(e1)),CH(e1,f1,g1)),KW[43]);
    d1 = ADD(d1,t_p43);
    h1 = ADD(ADD(t_p43,BS0V(a1)),MAJ(a1,b1,c1));
    V t_p44 = ADD(ADD(ADD(g1,BS1V(d1)),CH(d1,e1,f1)),KW[44]);
    c1 = ADD(c1,t_p44);
    g1 = ADD(ADD(t_p44,BS0V(h1)),MAJ(h1,a1,b1));
    V t_p45 = ADD(ADD(ADD(f1,BS1V(c1)),CH(c1,d1,e1)),KW[45]);
    b1 = ADD(b1,t_p45);
    f1 = ADD(ADD(t_p45,BS0V(g1)),MAJ(g1,h1,a1));
    V t_p46 = ADD(ADD(ADD(e1,BS1V(b1)),CH(b1,c1,d1)),KW[46]);
    a1 = ADD(a1,t_p46);
    e1 = ADD(ADD(t_p46,BS0V(f1)),MAJ(f1,g1,h1));
    V t_p47 = ADD(ADD(ADD(d1,BS1V(a1)),CH(a1,b1,c1)),KW[47]);
    h1 = ADD(h1,t_p47);
    d1 = ADD(ADD(t_p47,BS0V(e1)),MAJ(e1,f1,g1));
    V t_p48 = ADD(ADD(ADD(c1,BS1V(h1)),CH(h1,a1,b1)),KW[48]);
    g1 = ADD(g1,t_p48);
    c1 = ADD(ADD(t_p48,BS0V(d1)),MAJ(d1,e1,f1));
    V t_p49 = ADD(ADD(ADD(b1,BS1V(g1)),CH(g1,h1,a1)),KW[49]);
    f1 = ADD(f1,t_p49);
    b1 = ADD(ADD(t_p49,BS0V(c1)),MAJ(c1,d1,e1));
    V t_p50 = ADD(ADD(ADD(a1,BS1V(f1)),CH(f1,g1,h1)),KW[50]);
    e1 = ADD(e1,t_p50);
    a1 = ADD(ADD(t_p50,BS0V(b1)),MAJ(b1,c1,d1));
    V t_p51 = ADD(ADD(ADD(h1,BS1V(e1)),CH(e1,f1,g1)),KW[51]);
    d1 = ADD(d1,t_p51);
    h1 = ADD(ADD(t_p51,BS0V(a1)),MAJ(a1,b1,c1));
    V t_p52 = ADD(ADD(ADD(g1,BS1V(d1)),CH(d1,e1,f1)),KW[52]);
    c1 = ADD(c1,t_p52);
    g1 = ADD(ADD(t_p52,BS0V(h1)),MAJ(h1,a1,b1));
    V t_p53 = ADD(ADD(ADD(f1,BS1V(c1)),CH(c1,d1,e1)),KW[53]);
    b1 = ADD(b1,t_p53);
    f1 = ADD(ADD(t_p53,BS0V(g1)),MAJ(g1,h1,a1));
    V t_p54 = ADD(ADD(ADD(e1,BS1V(b1)),CH(b1,c1,d1)),KW[54]);
    a1 = ADD(a1,t_p54);
    e1 = ADD(ADD(t_p54,BS0V(f1)),MAJ(f1,g1,h1));
    V t_p55 = ADD(ADD(ADD(d1,BS1V(a1)),CH(a1,b1,c1)),KW[55]);
    h1 = ADD(h1,t_p55);
    d1 = ADD(ADD(t_p55,BS0V(e1)),MAJ(e1,f1,g1));
    V t_p56 = ADD(ADD(ADD(c1,BS1V(h1)),CH(h1,a1,b1)),KW[56]);
    g1 = ADD(g1,t_p56);
    c1 = ADD(ADD(t_p56,BS0V(d1)),MAJ(d1,e1,f1));
    V t_p57 = ADD(ADD(ADD(b1,BS1V(g1)),CH(g1,h1,a1)),KW[57]);
    f1 = ADD(f1,t_p57);
    b1 = ADD(ADD(t_p57,BS0V(c1)),MAJ(c1,d1,e1));
    V t_p58 = ADD(ADD(ADD(a1,BS1V(f1)),CH(f1,g1,h1)),KW[58]);
    e1 = ADD(e1,t_p58);
    a1 = ADD(ADD(t_p58,BS0V(b1)),MAJ(b1,c1,d1));
    V t_p59 = ADD(ADD(ADD(h1,BS1V(e1)),CH(e1,f1,g1)),KW[59]);
    d1 = ADD(d1,t_p59);
    h1 = ADD(ADD(t_p59,BS0V(a1)),MAJ(a1,b1,c1));
    V t_p60 = ADD(ADD(ADD(g1,BS1V(d1)),CH(d1,e1,f1)),KW[60]);
    c1 = ADD(c1,t_p60);
    g1 = ADD(ADD(t_p60,BS0V(h1)),MAJ(h1,a1,b1));
    V t_p61 = ADD(ADD(ADD(f1,BS1V(c1)),CH(c1,d1,e1)),KW[61]);
    b1 = ADD(b1,t_p61);
    f1 = ADD(ADD(t_p61,BS0V(g1)),MAJ(g1,h1,a1));
    V t_p62 = ADD(ADD(ADD(e1,BS1V(b1)),CH(b1,c1,d1)),KW[62]);
    a1 = ADD(a1,t_p62);
    e1 = ADD(ADD(t_p62,BS0V(f1)),MAJ(f1,g1,h1));
    V t_p63 = ADD(ADD(ADD(d1,BS1V(a1)),CH(a1,b1,c1)),KW[63]);
    h1 = ADD(h1,t_p63);
    d1 = ADD(ADD(t_p63,BS0V(e1)),MAJ(e1,f1,g1));
    V v122 = ADD(d1,SET1((int)vs->mid[0]));
    V v123 = ADD(e1,SET1((int)vs->mid[1]));
    V v124 = ADD(f1,SET1((int)vs->mid[2]));
    V v125 = ADD(g1,SET1((int)vs->mid[3]));
    V v126 = ADD(h1,SET1((int)vs->mid[4]));
    V v127 = ADD(a1,SET1((int)vs->mid[5]));
    V v128 = ADD(b1,SET1((int)vs->mid[6]));
    V v129 = ADD(c1,SET1((int)vs->mid[7]));
    V t_q0 = ADD(v122,SET1((int)0xf377ed68u));
    V a2 = ADD(t_q0,SET1((int)0x08909ae5u));
    V e2 = ADD(t_q0,SET1((int)0xa54ff53au));
    V b2 = SET1((int)0x6a09e667u);
    V c2 = SET1((int)0xbb67ae85u);
    V d2 = SET1((int)0x3c6ef372u);
    V f2 = SET1((int)0x510e527fu);
    V g2 = SET1((int)0x9b05688cu);
    V h2 = SET1((int)0x1f83d9abu);
    V v130 = ADD(v123,SET1((int)0x71374491u));
    V t_q1 = ADD(ADD(ADD(h2,BS1V(e2)),CH(e2,f2,g2)),v130);
    d2 = ADD(d2,t_q1);
    h2 = ADD(ADD(t_q1,BS0V(a2)),MAJ(a2,b2,c2));
    V v131 = ADD(v124,SET1((int)0xb5c0fbcfu));
    V t_q2 = ADD(ADD(ADD(g2,BS1V(d2)),CH(d2,e2,f2)),v131);
    c2 = ADD(c2,t_q2);
    g2 = ADD(ADD(t_q2,BS0V(h2)),MAJ(h2,a2,b2));
    V v132 = ADD(v125,SET1((int)0xe9b5dba5u));
    V t_q3 = ADD(ADD(ADD(f2,BS1V(c2)),CH(c2,d2,e2)),v132);
    b2 = ADD(b2,t_q3);
    f2 = ADD(ADD(t_q3,BS0V(g2)),MAJ(g2,h2,a2));
    V v133 = ADD(v126,SET1((int)0x3956c25bu));
    V t_q4 = ADD(ADD(ADD(e2,BS1V(b2)),CH(b2,c2,d2)),v133);
    a2 = ADD(a2,t_q4);
    e2 = ADD(ADD(t_q4,BS0V(f2)),MAJ(f2,g2,h2));
    V v134 = ADD(v127,SET1((int)0x59f111f1u));
    V t_q5 = ADD(ADD(ADD(d2,BS1V(a2)),CH(a2,b2,c2)),v134);
    h2 = ADD(h2,t_q5);
    d2 = ADD(ADD(t_q5,BS0V(e2)),MAJ(e2,f2,g2));
    V v135 = ADD(v128,SET1((int)0x923f82a4u));
    V t_q6 = ADD(ADD(ADD(c2,BS1V(h2)),CH(h2,a2,b2)),v135);
    g2 = ADD(g2,t_q6);
    c2 = ADD(ADD(t_q6,BS0V(d2)),MAJ(d2,e2,f2));
    V v136 = ADD(v129,SET1((int)0xab1c5ed5u));
    V t_q7 = ADD(ADD(ADD(b2,BS1V(g2)),CH(g2,h2,a2)),v136);
    f2 = ADD(f2,t_q7);
    b2 = ADD(ADD(t_q7,BS0V(c2)),MAJ(c2,d2,e2));
    V t_q8 = ADD(ADD(ADD(a2,BS1V(f2)),CH(f2,g2,h2)),SET1((int)0x5807aa98u));
    e2 = ADD(e2,t_q8);
    a2 = ADD(ADD(t_q8,BS0V(b2)),MAJ(b2,c2,d2));
    V t_q9 = ADD(ADD(ADD(h2,BS1V(e2)),CH(e2,f2,g2)),SET1((int)0x12835b01u));
    d2 = ADD(d2,t_q9);
    h2 = ADD(ADD(t_q9,BS0V(a2)),MAJ(a2,b2,c2));
    V t_q10 = ADD(ADD(ADD(g2,BS1V(d2)),CH(d2,e2,f2)),SET1((int)0x243185beu));
    c2 = ADD(c2,t_q10);
    g2 = ADD(ADD(t_q10,BS0V(h2)),MAJ(h2,a2,b2));
    V t_q11 = ADD(ADD(ADD(f2,BS1V(c2)),CH(c2,d2,e2)),SET1((int)0x550c7dc3u));
    b2 = ADD(b2,t_q11);
    f2 = ADD(ADD(t_q11,BS0V(g2)),MAJ(g2,h2,a2));
    V t_q12 = ADD(ADD(ADD(e2,BS1V(b2)),CH(b2,c2,d2)),SET1((int)0x72be5d74u));
    a2 = ADD(a2,t_q12);
    e2 = ADD(ADD(t_q12,BS0V(f2)),MAJ(f2,g2,h2));
    V t_q13 = ADD(ADD(ADD(d2,BS1V(a2)),CH(a2,b2,c2)),SET1((int)0x80deb1feu));
    h2 = ADD(h2,t_q13);
    d2 = ADD(ADD(t_q13,BS0V(e2)),MAJ(e2,f2,g2));
    V t_q14 = ADD(ADD(ADD(c2,BS1V(h2)),CH(h2,a2,b2)),SET1((int)0x9bdc06a7u));
    g2 = ADD(g2,t_q14);
    c2 = ADD(ADD(t_q14,BS0V(d2)),MAJ(d2,e2,f2));
    V t_q15 = ADD(ADD(ADD(b2,BS1V(g2)),CH(g2,h2,a2)),SET1((int)0xc19bf274u));
    f2 = ADD(f2,t_q15);
    b2 = ADD(ADD(t_q15,BS0V(c2)),MAJ(c2,d2,e2));
    V v137 = SIG0V(v123);
    V v138 = ADD(v122,v137);
    V v139 = ADD(v138,SET1((int)0xe49b69c1u));
    V t_q16 = ADD(ADD(ADD(a2,BS1V(f2)),CH(f2,g2,h2)),v139);
    e2 = ADD(e2,t_q16);
    a2 = ADD(ADD(t_q16,BS0V(b2)),MAJ(b2,c2,d2));
    V v140 = SIG0V(v124);
    V v141 = ADD(ADD(v123,v140),SET1((int)0x00a00000u));
    V v142 = ADD(v141,SET1((int)0xefbe4786u));
    V t_q17 = ADD(ADD(ADD(h2,BS1V(e2)),CH(e2,f2,g2)),v142);
    d2 = ADD(d2,t_q17);
    h2 = ADD(ADD(t_q17,BS0V(a2)),MAJ(a2,b2,c2));
    V v143 = SIG0V(v125);
    V v144 = SIG1V(v138);
    V v145 = ADD(ADD(v124,v143),v144);
    V v146 = ADD(v145,SET1((int)0x0fc19dc6u));
    V t_q18 = ADD(ADD(ADD(g2,BS1V(d2)),CH(d2,e2,f2)),v146);
    c2 = ADD(c2,t_q18);
    g2 = ADD(ADD(t_q18,BS0V(h2)),MAJ(h2,a2,b2));
    V v147 = SIG0V(v126);
    V v148 = SIG1V(v141);
    V v149 = ADD(ADD(v125,v147),v148);
    V v150 = ADD(v149,SET1((int)0x240ca1ccu));
    V t_q19 = ADD(ADD(ADD(f2,BS1V(c2)),CH(c2,d2,e2)),v150);
    b2 = ADD(b2,t_q19);
    f2 = ADD(ADD(t_q19,BS0V(g2)),MAJ(g2,h2,a2));
    V v151 = SIG0V(v127);
    V v152 = SIG1V(v145);
    V v153 = ADD(ADD(v126,v151),v152);
    V v154 = ADD(v153,SET1((int)0x2de92c6fu));
    V t_q20 = ADD(ADD(ADD(e2,BS1V(b2)),CH(b2,c2,d2)),v154);
    a2 = ADD(a2,t_q20);
    e2 = ADD(ADD(t_q20,BS0V(f2)),MAJ(f2,g2,h2));
    V v155 = SIG0V(v128);
    V v156 = SIG1V(v149);
    V v157 = ADD(ADD(v127,v155),v156);
    V v158 = ADD(v157,SET1((int)0x4a7484aau));
    V t_q21 = ADD(ADD(ADD(d2,BS1V(a2)),CH(a2,b2,c2)),v158);
    h2 = ADD(h2,t_q21);
    d2 = ADD(ADD(t_q21,BS0V(e2)),MAJ(e2,f2,g2));
    V v159 = SIG0V(v129);
    V v160 = SIG1V(v153);
    V v161 = ADD(ADD(ADD(v128,v159),v160),SET1((int)0x00000100u));
    V v162 = ADD(v161,SET1((int)0x5cb0a9dcu));
    V t_q22 = ADD(ADD(ADD(c2,BS1V(h2)),CH(h2,a2,b2)),v162);
    g2 = ADD(g2,t_q22);
    c2 = ADD(ADD(t_q22,BS0V(d2)),MAJ(d2,e2,f2));
    V v163 = SIG1V(v157);
    V v164 = ADD(ADD(ADD(v129,v138),v163),SET1((int)0x11002000u));
    V v165 = ADD(v164,SET1((int)0x76f988dau));
    V t_q23 = ADD(ADD(ADD(b2,BS1V(g2)),CH(g2,h2,a2)),v165);
    f2 = ADD(f2,t_q23);
    b2 = ADD(ADD(t_q23,BS0V(c2)),MAJ(c2,d2,e2));
    V v166 = SIG1V(v161);
    V v167 = ADD(ADD(v141,v166),SET1((int)0x80000000u));
    V v168 = ADD(v167,SET1((int)0x983e5152u));
    V t_q24 = ADD(ADD(ADD(a2,BS1V(f2)),CH(f2,g2,h2)),v168);
    e2 = ADD(e2,t_q24);
    a2 = ADD(ADD(t_q24,BS0V(b2)),MAJ(b2,c2,d2));
    V v169 = SIG1V(v164);
    V v170 = ADD(v145,v169);
    V v171 = ADD(v170,SET1((int)0xa831c66du));
    V t_q25 = ADD(ADD(ADD(h2,BS1V(e2)),CH(e2,f2,g2)),v171);
    d2 = ADD(d2,t_q25);
    h2 = ADD(ADD(t_q25,BS0V(a2)),MAJ(a2,b2,c2));
    V v172 = SIG1V(v167);
    V v173 = ADD(v149,v172);
    V v174 = ADD(v173,SET1((int)0xb00327c8u));
    V t_q26 = ADD(ADD(ADD(g2,BS1V(d2)),CH(d2,e2,f2)),v174);
    c2 = ADD(c2,t_q26);
    g2 = ADD(ADD(t_q26,BS0V(h2)),MAJ(h2,a2,b2));
    V v175 = SIG1V(v170);
    V v176 = ADD(v153,v175);
    V v177 = ADD(v176,SET1((int)0xbf597fc7u));
    V t_q27 = ADD(ADD(ADD(f2,BS1V(c2)),CH(c2,d2,e2)),v177);
    b2 = ADD(b2,t_q27);
    f2 = ADD(ADD(t_q27,BS0V(g2)),MAJ(g2,h2,a2));
    V v178 = SIG1V(v173);
    V v179 = ADD(v157,v178);
    V v180 = ADD(v179,SET1((int)0xc6e00bf3u));
    V t_q28 = ADD(ADD(ADD(e2,BS1V(b2)),CH(b2,c2,d2)),v180);
    a2 = ADD(a2,t_q28);
    e2 = ADD(ADD(t_q28,BS0V(f2)),MAJ(f2,g2,h2));
    V v181 = SIG1V(v176);
    V v182 = ADD(v161,v181);
    V v183 = ADD(v182,SET1((int)0xd5a79147u));
    V t_q29 = ADD(ADD(ADD(d2,BS1V(a2)),CH(a2,b2,c2)),v183);
    h2 = ADD(h2,t_q29);
    d2 = ADD(ADD(t_q29,BS0V(e2)),MAJ(e2,f2,g2));
    V v184 = SIG1V(v179);
    V v185 = ADD(ADD(v164,v184),SET1((int)0x00400022u));
    V v186 = ADD(v185,SET1((int)0x06ca6351u));
    V t_q30 = ADD(ADD(ADD(c2,BS1V(h2)),CH(h2,a2,b2)),v186);
    g2 = ADD(g2,t_q30);
    c2 = ADD(ADD(t_q30,BS0V(d2)),MAJ(d2,e2,f2));
    V v187 = SIG0V(v138);
    V v188 = SIG1V(v182);
    V v189 = ADD(ADD(ADD(v187,v167),v188),SET1((int)0x00000100u));
    V v190 = ADD(v189,SET1((int)0x14292967u));
    V t_q31 = ADD(ADD(ADD(b2,BS1V(g2)),CH(g2,h2,a2)),v190);
    f2 = ADD(f2,t_q31);
    b2 = ADD(ADD(t_q31,BS0V(c2)),MAJ(c2,d2,e2));
    V v191 = SIG0V(v141);
    V v192 = SIG1V(v185);
    V v193 = ADD(ADD(ADD(v138,v191),v170),v192);
    V v194 = ADD(v193,SET1((int)0x27b70a85u));
    V t_q32 = ADD(ADD(ADD(a2,BS1V(f2)),CH(f2,g2,h2)),v194);
    e2 = ADD(e2,t_q32);
    a2 = ADD(ADD(t_q32,BS0V(b2)),MAJ(b2,c2,d2));
    V v195 = SIG0V(v145);
    V v196 = SIG1V(v189);
    V v197 = ADD(ADD(ADD(v141,v195),v173),v196);
    V v198 = ADD(v197,SET1((int)0x2e1b2138u));
    V t_q33 = ADD(ADD(ADD(h2,BS1V(e2)),CH(e2,f2,g2)),v198);
    d2 = ADD(d2,t_q33);
    h2 = ADD(ADD(t_q33,BS0V(a2)),MAJ(a2,b2,c2));
    V v199 = SIG0V(v149);
    V v200 = SIG1V(v193);
    V v201 = ADD(ADD(ADD(v145,v199),v176),v200);
    V v202 = ADD(v201,SET1((int)0x4d2c6dfcu));
    V t_q34 = ADD(ADD(ADD(g2,BS1V(d2)),CH(d2,e2,f2)),v202);
    c2 = ADD(c2,t_q34);
    g2 = ADD(ADD(t_q34,BS0V(h2)),MAJ(h2,a2,b2));
    V v203 = SIG0V(v153);
    V v204 = SIG1V(v197);
    V v205 = ADD(ADD(ADD(v149,v203),v179),v204);
    V v206 = ADD(v205,SET1((int)0x53380d13u));
    V t_q35 = ADD(ADD(ADD(f2,BS1V(c2)),CH(c2,d2,e2)),v206);
    b2 = ADD(b2,t_q35);
    f2 = ADD(ADD(t_q35,BS0V(g2)),MAJ(g2,h2,a2));
    V v207 = SIG0V(v157);
    V v208 = SIG1V(v201);
    V v209 = ADD(ADD(ADD(v153,v207),v182),v208);
    V v210 = ADD(v209,SET1((int)0x650a7354u));
    V t_q36 = ADD(ADD(ADD(e2,BS1V(b2)),CH(b2,c2,d2)),v210);
    a2 = ADD(a2,t_q36);
    e2 = ADD(ADD(t_q36,BS0V(f2)),MAJ(f2,g2,h2));
    V v211 = SIG0V(v161);
    V v212 = SIG1V(v205);
    V v213 = ADD(ADD(ADD(v157,v211),v185),v212);
    V v214 = ADD(v213,SET1((int)0x766a0abbu));
    V t_q37 = ADD(ADD(ADD(d2,BS1V(a2)),CH(a2,b2,c2)),v214);
    h2 = ADD(h2,t_q37);
    d2 = ADD(ADD(t_q37,BS0V(e2)),MAJ(e2,f2,g2));
    V v215 = SIG0V(v164);
    V v216 = SIG1V(v209);
    V v217 = ADD(ADD(ADD(v161,v215),v189),v216);
    V v218 = ADD(v217,SET1((int)0x81c2c92eu));
    V t_q38 = ADD(ADD(ADD(c2,BS1V(h2)),CH(h2,a2,b2)),v218);
    g2 = ADD(g2,t_q38);
    c2 = ADD(ADD(t_q38,BS0V(d2)),MAJ(d2,e2,f2));
    V v219 = SIG0V(v167);
    V v220 = SIG1V(v213);
    V v221 = ADD(ADD(ADD(v164,v219),v193),v220);
    V v222 = ADD(v221,SET1((int)0x92722c85u));
    V t_q39 = ADD(ADD(ADD(b2,BS1V(g2)),CH(g2,h2,a2)),v222);
    f2 = ADD(f2,t_q39);
    b2 = ADD(ADD(t_q39,BS0V(c2)),MAJ(c2,d2,e2));
    V v223 = SIG0V(v170);
    V v224 = SIG1V(v217);
    V v225 = ADD(ADD(ADD(v167,v223),v197),v224);
    V v226 = ADD(v225,SET1((int)0xa2bfe8a1u));
    V t_q40 = ADD(ADD(ADD(a2,BS1V(f2)),CH(f2,g2,h2)),v226);
    e2 = ADD(e2,t_q40);
    a2 = ADD(ADD(t_q40,BS0V(b2)),MAJ(b2,c2,d2));
    V v227 = SIG0V(v173);
    V v228 = SIG1V(v221);
    V v229 = ADD(ADD(ADD(v170,v227),v201),v228);
    V v230 = ADD(v229,SET1((int)0xa81a664bu));
    V t_q41 = ADD(ADD(ADD(h2,BS1V(e2)),CH(e2,f2,g2)),v230);
    d2 = ADD(d2,t_q41);
    h2 = ADD(ADD(t_q41,BS0V(a2)),MAJ(a2,b2,c2));
    V v231 = SIG0V(v176);
    V v232 = SIG1V(v225);
    V v233 = ADD(ADD(ADD(v173,v231),v205),v232);
    V v234 = ADD(v233,SET1((int)0xc24b8b70u));
    V t_q42 = ADD(ADD(ADD(g2,BS1V(d2)),CH(d2,e2,f2)),v234);
    c2 = ADD(c2,t_q42);
    g2 = ADD(ADD(t_q42,BS0V(h2)),MAJ(h2,a2,b2));
    V v235 = SIG0V(v179);
    V v236 = SIG1V(v229);
    V v237 = ADD(ADD(ADD(v176,v235),v209),v236);
    V v238 = ADD(v237,SET1((int)0xc76c51a3u));
    V t_q43 = ADD(ADD(ADD(f2,BS1V(c2)),CH(c2,d2,e2)),v238);
    b2 = ADD(b2,t_q43);
    f2 = ADD(ADD(t_q43,BS0V(g2)),MAJ(g2,h2,a2));
    V v239 = SIG0V(v182);
    V v240 = SIG1V(v233);
    V v241 = ADD(ADD(ADD(v179,v239),v213),v240);
    V v242 = ADD(v241,SET1((int)0xd192e819u));
    V t_q44 = ADD(ADD(ADD(e2,BS1V(b2)),CH(b2,c2,d2)),v242);
    a2 = ADD(a2,t_q44);
    e2 = ADD(ADD(t_q44,BS0V(f2)),MAJ(f2,g2,h2));
    V v243 = SIG0V(v185);
    V v244 = SIG1V(v237);
    V v245 = ADD(ADD(ADD(v182,v243),v217),v244);
    V v246 = ADD(v245,SET1((int)0xd6990624u));
    V t_q45 = ADD(ADD(ADD(d2,BS1V(a2)),CH(a2,b2,c2)),v246);
    h2 = ADD(h2,t_q45);
    d2 = ADD(ADD(t_q45,BS0V(e2)),MAJ(e2,f2,g2));
    V v247 = SIG0V(v189);
    V v248 = SIG1V(v241);
    V v249 = ADD(ADD(ADD(v185,v247),v221),v248);
    V v250 = ADD(v249,SET1((int)0xf40e3585u));
    V t_q46 = ADD(ADD(ADD(c2,BS1V(h2)),CH(h2,a2,b2)),v250);
    g2 = ADD(g2,t_q46);
    c2 = ADD(ADD(t_q46,BS0V(d2)),MAJ(d2,e2,f2));
    V v251 = SIG0V(v193);
    V v252 = SIG1V(v245);
    V v253 = ADD(ADD(ADD(v189,v251),v225),v252);
    V v254 = ADD(v253,SET1((int)0x106aa070u));
    V t_q47 = ADD(ADD(ADD(b2,BS1V(g2)),CH(g2,h2,a2)),v254);
    f2 = ADD(f2,t_q47);
    b2 = ADD(ADD(t_q47,BS0V(c2)),MAJ(c2,d2,e2));
    V v255 = SIG0V(v197);
    V v256 = SIG1V(v249);
    V v257 = ADD(ADD(ADD(v193,v255),v229),v256);
    V v258 = ADD(v257,SET1((int)0x19a4c116u));
    V t_q48 = ADD(ADD(ADD(a2,BS1V(f2)),CH(f2,g2,h2)),v258);
    e2 = ADD(e2,t_q48);
    a2 = ADD(ADD(t_q48,BS0V(b2)),MAJ(b2,c2,d2));
    V v259 = SIG0V(v201);
    V v260 = SIG1V(v253);
    V v261 = ADD(ADD(ADD(v197,v259),v233),v260);
    V v262 = ADD(v261,SET1((int)0x1e376c08u));
    V t_q49 = ADD(ADD(ADD(h2,BS1V(e2)),CH(e2,f2,g2)),v262);
    d2 = ADD(d2,t_q49);
    h2 = ADD(ADD(t_q49,BS0V(a2)),MAJ(a2,b2,c2));
    V v263 = SIG0V(v205);
    V v264 = SIG1V(v257);
    V v265 = ADD(ADD(ADD(v201,v263),v237),v264);
    V v266 = ADD(v265,SET1((int)0x2748774cu));
    V t_q50 = ADD(ADD(ADD(g2,BS1V(d2)),CH(d2,e2,f2)),v266);
    c2 = ADD(c2,t_q50);
    g2 = ADD(ADD(t_q50,BS0V(h2)),MAJ(h2,a2,b2));
    V v267 = SIG0V(v209);
    V v268 = SIG1V(v261);
    V v269 = ADD(ADD(ADD(v205,v267),v241),v268);
    V v270 = ADD(v269,SET1((int)0x34b0bcb5u));
    V t_q51 = ADD(ADD(ADD(f2,BS1V(c2)),CH(c2,d2,e2)),v270);
    b2 = ADD(b2,t_q51);
    f2 = ADD(ADD(t_q51,BS0V(g2)),MAJ(g2,h2,a2));
    V v271 = SIG0V(v213);
    V v272 = SIG1V(v265);
    V v273 = ADD(ADD(ADD(v209,v271),v245),v272);
    V v274 = ADD(v273,SET1((int)0x391c0cb3u));
    V t_q52 = ADD(ADD(ADD(e2,BS1V(b2)),CH(b2,c2,d2)),v274);
    a2 = ADD(a2,t_q52);
    e2 = ADD(ADD(t_q52,BS0V(f2)),MAJ(f2,g2,h2));
    V v275 = SIG0V(v217);
    V v276 = SIG1V(v269);
    V v277 = ADD(ADD(ADD(v213,v275),v249),v276);
    V v278 = ADD(v277,SET1((int)0x4ed8aa4au));
    V t_q53 = ADD(ADD(ADD(d2,BS1V(a2)),CH(a2,b2,c2)),v278);
    h2 = ADD(h2,t_q53);
    d2 = ADD(ADD(t_q53,BS0V(e2)),MAJ(e2,f2,g2));
    V v279 = SIG0V(v221);
    V v280 = SIG1V(v273);
    V v281 = ADD(ADD(ADD(v217,v279),v253),v280);
    V v282 = ADD(v281,SET1((int)0x5b9cca4fu));
    V t_q54 = ADD(ADD(ADD(c2,BS1V(h2)),CH(h2,a2,b2)),v282);
    g2 = ADD(g2,t_q54);
    c2 = ADD(ADD(t_q54,BS0V(d2)),MAJ(d2,e2,f2));
    V v283 = SIG0V(v225);
    V v284 = SIG1V(v277);
    V v285 = ADD(ADD(ADD(v221,v283),v257),v284);
    V v286 = ADD(v285,SET1((int)0x682e6ff3u));
    V t_q55 = ADD(ADD(ADD(b2,BS1V(g2)),CH(g2,h2,a2)),v286);
    f2 = ADD(f2,t_q55);
    b2 = ADD(ADD(t_q55,BS0V(c2)),MAJ(c2,d2,e2));
    V v287 = SIG0V(v229);
    V v288 = SIG1V(v281);
    V v289 = ADD(ADD(ADD(v225,v287),v261),v288);
    V v290 = ADD(v289,SET1((int)0x748f82eeu));
    V t_q56 = ADD(ADD(ADD(a2,BS1V(f2)),CH(f2,g2,h2)),v290);
    e2 = ADD(e2,t_q56);
    a2 = ADD(ADD(t_q56,BS0V(b2)),MAJ(b2,c2,d2));
    V v291 = SIG0V(v233);
    V v292 = SIG1V(v285);
    V v293 = ADD(ADD(ADD(v229,v291),v265),v292);
    V v294 = ADD(v293,SET1((int)0x78a5636fu));
    V t_q57 = ADD(ADD(ADD(h2,BS1V(e2)),CH(e2,f2,g2)),v294);
    d2 = ADD(d2,t_q57);
    V v295 = SIG0V(v237);
    V v296 = SIG1V(v289);
    V v297 = ADD(ADD(ADD(v233,v295),v269),v296);
    V v298 = ADD(v297,SET1((int)0x84c87814u));
    V t_q58 = ADD(ADD(ADD(g2,BS1V(d2)),CH(d2,e2,f2)),v298);
    c2 = ADD(c2,t_q58);
    V v299 = SIG0V(v241);
    V v300 = SIG1V(v293);
    V v301 = ADD(ADD(ADD(v237,v299),v273),v300);
    V v302 = ADD(v301,SET1((int)0x8cc70208u));
    V t_q59 = ADD(ADD(ADD(f2,BS1V(c2)),CH(c2,d2,e2)),v302);
    b2 = ADD(b2,t_q59);
    V v303 = SIG0V(v245);
    V v304 = SIG1V(v297);
    V v305 = ADD(ADD(ADD(v241,v303),v277),v304);
    V v306 = ADD(v305,SET1((int)0x90befffau));
    V t_q60 = ADD(ADD(ADD(e2,BS1V(b2)),CH(b2,c2,d2)),v306);
    a2 = ADD(a2,t_q60);
    return ADD(a2,SET1((int)0x5be0cd19u));
}
static uint64_t scan_avx512(const uint8_t *hdr, uint32_t start, uint64_t count, uint32_t mask, int M){
  uint32_t c[NC]; uint8_t hdrv[MAXM][76]; uint32_t ver[MAXM]; VS vs[MAXM];
  M=setup_versions(hdr,mask,M,hdrv,ver);
  prepare_shared(hdr,c); for(int j=0;j<M;j++) prepare_ver(hdrv[j],&vs[j]);
  V nv=ADD(SET1((int)start),LANEIDX); const V step=SET1(16); V KW[64];
  uint64_t hits=0;
  for(uint64_t base=0;base<count;base+=16){
    sched_avx512(c,BSWAP(nv),KW);
    for(int j=0;j<M;j++){
      unsigned mk=CMPZ(hash_avx512(c,&vs[j],KW));
      if(mk) for(int lane=0;lane<16;lane++) if(((mk>>lane)&1) && base+(uint64_t)lane<count)
        hits+=report_hit(hdrv[j],start+(uint32_t)(base+(uint64_t)lane),ver[j]);
    }
    nv=ADD(nv,step);
  }
  return hits;
}
static int test_avx512(void){
  uint64_t x=88172645463325252ULL; long checked=0,bad=0;
  for(int trial=0;trial<6;trial++){
    uint8_t hdr[76]; for(int i=0;i<76;i++){x^=x<<13;x^=x>>7;x^=x<<17;hdr[i]=(uint8_t)x;}
    uint32_t mask=0x1fffe000u,start=(uint32_t)x; int M=(trial%2)?16:8;
    uint32_t c[NC]; uint8_t hdrv[MAXM][76]; uint32_t ver[MAXM]; VS vs[MAXM];
    M=setup_versions(hdr,mask,M,hdrv,ver); prepare_shared(hdr,c); for(int j=0;j<M;j++) prepare_ver(hdrv[j],&vs[j]);
    V KW[64];
    for(uint32_t base=0;base<4096;base+=16){
      uint32_t ns[16]; for(int l=0;l<16;l++) ns[l]=start+base+l;
      sched_avx512(c,BSWAP(LOADU(ns)),KW);
      for(int j=0;j<M;j++){
        uint32_t out[16]; STOREU(out,hash_avx512(c,&vs[j],KW));
        for(int l=0;l<16;l++){ uint32_t s[8]; scalar_hash(hdrv[j],ns[l],s); checked++; if(s[7]!=out[l]) bad++; }
      }
    }
  }
  if(bad){ printf("%s: HATA checked=%ld bad=%ld\n","avx512",checked,bad); return 1; }
  printf("%s: OK checked=%ld\n","avx512",checked); return 0;
}
#undef V
#undef ADD
#undef XOR
#undef AND
#undef OR
#undef SHR
#undef SHL
#undef ROR
#undef T3
#undef SIG0V
#undef SIG1V
#undef BS0V
#undef BS1V
#undef CH
#undef MAJ
#undef SET1
#undef BSWAP
#undef LANEIDX
#undef LOADU
#undef STOREU
#undef CMPZ
#pragma GCC pop_options


/* ===== motor shani: SHA-NI, birden cok bagimsiz akis ic ice ===== */
#pragma GCC push_options
#pragma GCC target("sha,ssse3,sse4.1")
#ifndef NI_S
#define NI_S 4
#endif
typedef struct { __m128i s0, s1; } NIV;
static inline void ni_pack(const uint32_t *st, __m128i *abef, __m128i *cdgh){
  __m128i tmp=_mm_loadu_si128((const __m128i*)&st[0]), s1=_mm_loadu_si128((const __m128i*)&st[4]);
  tmp=_mm_shuffle_epi32(tmp,0xB1); s1=_mm_shuffle_epi32(s1,0x1B);
  *abef=_mm_alignr_epi8(tmp,s1,8); *cdgh=_mm_blend_epi16(s1,tmp,0xF0);
}
static inline __m128i ni_next(__m128i w0,__m128i w1,__m128i w2,__m128i w3){
  return _mm_sha256msg2_epu32(_mm_add_epi32(_mm_sha256msg1_epu32(w0,w1),_mm_alignr_epi8(w3,w2,4)),w3);
}
/* 2. blok mesaj genisletmesi (K ile toplanmis): nonce basina bir kez, surumler arasinda paylasilir */
static inline void ni_kw(uint32_t w0,uint32_t w1,uint32_t w2,uint32_t w3,__m128i *kw,__m128i *kwh){
  __m128i W[16];
  W[0]=_mm_setr_epi32((int)w0,(int)w1,(int)w2,(int)w3); W[1]=_mm_setr_epi32((int)0x80000000u,0,0,0);
  W[2]=_mm_setzero_si128(); W[3]=_mm_setr_epi32(0,0,0,640);
  for(int k=4;k<16;k++) W[k]=ni_next(W[k-4],W[k-3],W[k-2],W[k-1]);
  for(int k=0;k<16;k++){ __m128i m=_mm_add_epi32(W[k],_mm_loadu_si128((const __m128i*)(K+4*k))); kw[k]=m; kwh[k]=_mm_shuffle_epi32(m,0x0E); }
}
/* NI_S bagimsiz (mesaj, surum) akisi: 1. hash (64 tur) + 2. hash (62 tur); f[s] = e_61 (h7 = f + IV7) */
static inline void ni_batch(const __m128i *const *kw,const __m128i *const *kwh,const NIV *const *vs,uint32_t *f,__m128i iv0,__m128i iv1){
  __m128i s0[NI_S],s1[NI_S],W[NI_S][16],a0[NI_S],a1[NI_S];
  for(int s=0;s<NI_S;s++){ s0[s]=vs[s]->s0; s1[s]=vs[s]->s1; }
  for(int k=0;k<16;k++){
    for(int s=0;s<NI_S;s++) s1[s]=_mm_sha256rnds2_epu32(s1[s],s0[s],kw[s][k]);
    for(int s=0;s<NI_S;s++) s0[s]=_mm_sha256rnds2_epu32(s0[s],s1[s],kwh[s][k]);
  }
  for(int s=0;s<NI_S;s++){
    s0[s]=_mm_add_epi32(s0[s],vs[s]->s0); s1[s]=_mm_add_epi32(s1[s],vs[s]->s1);
    __m128i t=_mm_shuffle_epi32(s0[s],0x1B), u=_mm_shuffle_epi32(s1[s],0xB1);
    W[s][0]=_mm_blend_epi16(t,u,0xF0); W[s][1]=_mm_alignr_epi8(u,t,8);
    W[s][2]=_mm_setr_epi32((int)0x80000000u,0,0,0); W[s][3]=_mm_setr_epi32(0,0,0,256);
    a0[s]=iv0; a1[s]=iv1;
  }
  for(int k=4;k<16;k++) for(int s=0;s<NI_S;s++) W[s][k]=ni_next(W[s][k-4],W[s][k-3],W[s][k-2],W[s][k-1]);
  for(int k=0;k<15;k++){
    __m128i Kq=_mm_loadu_si128((const __m128i*)(K+4*k)), m[NI_S];
    for(int s=0;s<NI_S;s++){ m[s]=_mm_add_epi32(W[s][k],Kq); a1[s]=_mm_sha256rnds2_epu32(a1[s],a0[s],m[s]); }
    for(int s=0;s<NI_S;s++){ m[s]=_mm_shuffle_epi32(m[s],0x0E); a0[s]=_mm_sha256rnds2_epu32(a0[s],a1[s],m[s]); }
  }
  { __m128i Kq=_mm_loadu_si128((const __m128i*)(K+60));
    for(int s=0;s<NI_S;s++){ a1[s]=_mm_sha256rnds2_epu32(a1[s],a0[s],_mm_add_epi32(W[s][15],Kq)); f[s]=(uint32_t)_mm_cvtsi128_si32(a1[s]); } }
}
static uint64_t scan_shani(const uint8_t *hdr, uint32_t start, uint64_t count, uint32_t mask, int M){
  uint8_t hdrv[MAXM][76]; uint32_t ver[MAXM]; VS vs[MAXM]; NIV nv[MAXM];
  M=setup_versions(hdr,mask,M,hdrv,ver);
  for(int j=0;j<M;j++){ prepare_ver(hdrv[j],&vs[j]); ni_pack(vs[j].mid,&nv[j].s0,&nv[j].s1); }
  __m128i iv0,iv1; ni_pack(IV,&iv0,&iv1);
  const uint32_t w0=be32(hdr+64),w1=be32(hdr+68),w2=be32(hdr+72), target=0u-IV[7];
  __m128i kw[NI_S][16],kwh[NI_S][16]; uint64_t hits=0; uint32_t f[NI_S];
  const __m128i *kwp[NI_S],*kwhp[NI_S]; const NIV *vp[NI_S];
  if(M>=NI_S){
    for(uint64_t base=0;base<count;base++){
      uint32_t nonce=start+(uint32_t)base; ni_kw(w0,w1,w2,bswap32(nonce),kw[0],kwh[0]);
      for(int j=0;j<M;j+=NI_S){
        for(int s=0;s<NI_S;s++){ kwp[s]=kw[0]; kwhp[s]=kwh[0]; vp[s]=&nv[j+s]; }
        ni_batch(kwp,kwhp,vp,f,iv0,iv1);
        for(int s=0;s<NI_S;s++) if(f[s]==target) hits+=report_hit(hdrv[j+s],nonce,ver[j+s]);
      }
    }
  } else {
    for(uint64_t base=0;base<count;base+=NI_S){
      for(int s=0;s<NI_S;s++) ni_kw(w0,w1,w2,bswap32(start+(uint32_t)(base+(uint64_t)s)),kw[s],kwh[s]);
      for(int j=0;j<M;j++){
        for(int s=0;s<NI_S;s++){ kwp[s]=kw[s]; kwhp[s]=kwh[s]; vp[s]=&nv[j]; }
        ni_batch(kwp,kwhp,vp,f,iv0,iv1);
        for(int s=0;s<NI_S;s++) if(f[s]==target && base+(uint64_t)s<count) hits+=report_hit(hdrv[j],start+(uint32_t)(base+(uint64_t)s),ver[j]);
      }
    }
  }
  return hits;
}
static int test_shani(void){
  uint64_t x=88172645463325252ULL; long checked=0,bad=0;
  for(int trial=0;trial<6;trial++){
    uint8_t hdr[76]; for(int i=0;i<76;i++){x^=x<<13;x^=x>>7;x^=x<<17;hdr[i]=(uint8_t)x;}
    uint32_t mask=0x1fffe000u,start=(uint32_t)x; int M=(trial%3==0)?1:((trial%3==1)?8:16);
    uint8_t hdrv[MAXM][76]; uint32_t ver[MAXM]; VS vs[MAXM]; NIV nv[MAXM];
    M=setup_versions(hdr,M==1?0:mask,M,hdrv,ver);
    for(int j=0;j<M;j++){ prepare_ver(hdrv[j],&vs[j]); ni_pack(vs[j].mid,&nv[j].s0,&nv[j].s1); }
    __m128i iv0,iv1; ni_pack(IV,&iv0,&iv1);
    const uint32_t w0=be32(hdr+64),w1=be32(hdr+68),w2=be32(hdr+72);
    __m128i kw[NI_S][16],kwh[NI_S][16]; const __m128i *kwp[NI_S],*kwhp[NI_S]; const NIV *vp[NI_S]; uint32_t f[NI_S];
    for(uint32_t base=0;base<1024;base+=NI_S){
      for(int s=0;s<NI_S;s++) ni_kw(w0,w1,w2,bswap32(start+base+s),kw[s],kwh[s]);
      for(int j=0;j<M;j++){
        for(int s=0;s<NI_S;s++){ kwp[s]=kw[s]; kwhp[s]=kwh[s]; vp[s]=&nv[j]; }
        ni_batch(kwp,kwhp,vp,f,iv0,iv1);
        for(int s=0;s<NI_S;s++){ uint32_t sc[8]; scalar_hash(hdrv[j],start+base+s,sc); checked++; if(sc[7]!=f[s]+IV[7]) bad++; }
      }
    }
  }
  if(bad){ printf("shani: HATA checked=%ld bad=%ld\n",checked,bad); return 1; }
  printf("shani: OK checked=%ld\n",checked); return 0;
}
#pragma GCC pop_options

/* ===== motor secimi ===== */
typedef uint64_t (*scan_fn)(const uint8_t*,uint32_t,uint64_t,uint32_t,int);
typedef struct { const char *name; scan_fn scan; int (*test)(void); int (*avail)(void); } Engine;
static int av_scalar(void){ return 1; }
static int av_avx2(void){ __builtin_cpu_init(); return __builtin_cpu_supports("avx2"); }
static int av_avx512vl(void){ __builtin_cpu_init(); return __builtin_cpu_supports("avx2")&&__builtin_cpu_supports("avx512f")&&__builtin_cpu_supports("avx512vl"); }
static int av_avx512(void){ __builtin_cpu_init(); return av_avx512vl()&&__builtin_cpu_supports("avx512bw"); }
static int av_shani(void){
  __builtin_cpu_init(); if(!__builtin_cpu_supports("sse4.1")||!__builtin_cpu_supports("ssse3")) return 0;
  unsigned a,b,c,d; if(!__get_cpuid_count(7,0,&a,&b,&c,&d)) return 0; return (b>>29)&1;
}
static const Engine ENG[]={
  {"avx512",scan_avx512,test_avx512,av_avx512},
  {"avx512vl",scan_avx512vl,test_avx512vl,av_avx512vl},
  {"shani",scan_shani,test_shani,av_shani},
  {"avx2",scan_avx2,test_avx2,av_avx2},
  {"scalar",scan_scalar,test_scalar,av_scalar},
};
#define NENG ((int)(sizeof ENG/sizeof ENG[0]))
static const Engine *find_engine(const char *name){ for(int i=0;i<NENG;i++) if(!strcmp(ENG[i].name,name)&&ENG[i].avail()) return &ENG[i]; return NULL; }
static const Engine *default_engine(void){
  const char *e=getenv("SHA256D_ENGINE"); if(e&&*e){ const Engine *x=find_engine(e); if(x) return x; }
  /* ortam degiskeni yoksa: oncelik sirasi (PHP baslangicta --tune ile olcup SHA256D_ENGINE ayarlar) */
  static const char *pri[]={"avx512","shani","avx2","scalar"};
  for(unsigned i=0;i<sizeof pri/sizeof pri[0];i++){ const Engine *x=find_engine(pri[i]); if(x) return x; }
  return &ENG[NENG-1];
}
static double bench_engine(const Engine *e,int M,double secs){
  uint8_t h[76]; memset(h,1,sizeof h); uint64_t chunk=(M>1?400000ULL/(uint64_t)M:400000ULL); if(!strcmp(e->name,"scalar")) chunk/=40; if(chunk<64) chunk=64;
  uint64_t done=0; struct timespec a,b; clock_gettime(CLOCK_MONOTONIC,&a); double t;
  uint32_t st=0;
  do{ e->scan(h,st,chunk,M>1?0x1fffe000u:0,M); st+=(uint32_t)chunk; done+=chunk; clock_gettime(CLOCK_MONOTONIC,&b); t=(b.tv_sec-a.tv_sec)+(b.tv_nsec-a.tv_nsec)/1e9; }while(t<secs);
  return (double)done*(double)(M<1?1:M)/t/1e6;
}

int main(int argc,char**argv){
  if(argc>=2&&!strcmp(argv[1],"--info")){
    printf("sha256d_scan v5 asicboost engines:"); for(int i=0;i<NENG;i++) if(ENG[i].avail()) printf(" %s",ENG[i].name); printf("\nselected: %s\n",default_engine()->name); return 0; }
  if(argc>=2&&!strcmp(argv[1],"--test")){
    int bad=0; long total=0; for(int i=0;i<NENG;i++) if(ENG[i].avail()) bad+=ENG[i].test();
    (void)total; if(bad){ printf("TEST FAIL\n"); return 1; } printf("TEST OK\n"); return 0; }
  if(argc>=2&&!strcmp(argv[1],"--tune")){
    int M=argc>=3?atoi(argv[2]):16; const Engine *best=NULL; double bv=0;
    for(int i=0;i<NENG;i++) if(ENG[i].avail()&&strcmp(ENG[i].name,"scalar")){ double v=bench_engine(&ENG[i],M,0.25); printf("%s %.2f\n",ENG[i].name,v); if(v>bv){bv=v;best=&ENG[i];} }
    if(!best) best=&ENG[NENG-1]; printf("BEST %s\n",best->name); return 0; }
  if(argc>=2&&!strcmp(argv[1],"--bench")){
    int M=argc>=3?atoi(argv[2]):16; if(argc>=4){ const Engine *e=find_engine(argv[3]); if(!e){fprintf(stderr,"motor yok: %s\n",argv[3]);return 1;} fprintf(stderr,"%s M=%d: %.2f MH/s (tek thread)\n",e->name,M,bench_engine(e,M,1.5)); return 0; }
    for(int i=0;i<NENG;i++) if(ENG[i].avail()) fprintf(stderr,"%s M=%d: %.2f MH/s (tek thread)\n",ENG[i].name,M,bench_engine(&ENG[i],M,1.0)); return 0; }
  if(argc<4){fprintf(stderr,"kullanim: %s <header76hex> <start> <count> [mask_hex M]\n",argv[0]);return 1;}
  if(strlen(argv[1])!=152){fprintf(stderr,"header 152 hex karakter olmali\n");return 1;}
  uint8_t h[76];for(int i=0;i<76;i++){int a=hexv(argv[1][2*i]),b=hexv(argv[1][2*i+1]);if(a<0||b<0){fprintf(stderr,"gecersiz hex\n");return 1;}h[i]=(uint8_t)((a<<4)|b);}
  uint32_t mask=argc>=6?(uint32_t)strtoul(argv[4],NULL,16):0; int M=argc>=6?atoi(argv[5]):1;
  default_engine()->scan(h,(uint32_t)strtoul(argv[2],NULL,10),strtoull(argv[3],NULL,10),mask,M);return 0;}
