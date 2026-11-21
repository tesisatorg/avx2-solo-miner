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
#include "gen_nc.inc"
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
#include "gen_prepare.inc"
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
#include "gen_sched.inc"
}
/* her versiyon icin: kalan turlar */
static inline V hash8v(const uint32_t *c, const VS *vs, const V *KW){
#include "gen_hash.inc"
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
