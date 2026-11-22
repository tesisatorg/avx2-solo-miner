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
/*@NC@*/
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
/*@PREPARE@*/
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

/*@KERNELS@*/

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
