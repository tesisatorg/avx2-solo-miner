/*
 * gpu_scan.c - OpenCL GPU tarayici (SHA-256d, Bitcoin basligi)  |  tesisat.org
 *
 * Derleme (MSYS2 MinGW64 veya herhangi bir gcc):   gcc -O3 -static -o gpu_scan.exe gpu_scan.c
 * OpenCL baslik dosyasi / kutuphane GEREKMEZ: OpenCL.dll calisma aninda yuklenir.
 *
 * Kullanim:
 *   gpu_scan --info                      cihazlari listele
 *   gpu_scan --test  [cihaz]             GPU sonucunu CPU referansiyla karsilastir
 *   gpu_scan --bench [cihaz]             ~5 sn hiz olc
 *   gpu_scan --serve [cihaz]             miner.php icin kalici mod (stdin: "<header76hex> <start> <count>")
 * Ortam degiskenleri: GPU_DEVICE (cihaz no), GPU_DUTY (1-100, isi icin calisma orani, varsayilan 100),
 *   GPU_LWS (work-group boyutu, ornek 64/128/256; 0 = surucu secsin)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <dlfcn.h>
#include <time.h>
#include <unistd.h>
#endif

/* ---- minimal OpenCL 1.2 bildirimleri (baslik dosyasina gerek yok) ---- */
typedef int32_t cl_int; typedef uint32_t cl_uint; typedef uint64_t cl_ulong;
typedef void *cl_platform_id, *cl_device_id, *cl_context, *cl_command_queue, *cl_mem, *cl_program, *cl_kernel, *cl_event;
#define CL_SUCCESS 0
#define CL_DEVICE_TYPE_ALL 0xFFFFFFFFu
#define CL_DEVICE_TYPE_GPU 4u
#define CL_DEVICE_NAME 0x102B
#define CL_DEVICE_VENDOR 0x102C
#define CL_DEVICE_TYPE 0x1000
#define CL_DEVICE_MAX_COMPUTE_UNITS 0x1002
#define CL_PLATFORM_NAME 0x0902
#define CL_MEM_READ_WRITE 1u
#define CL_MEM_READ_ONLY 4u
#define CL_MEM_COPY_HOST_PTR 32u
#define CL_PROGRAM_BUILD_LOG 0x1183
#define CL_TRUE 1u
static struct {
  cl_int (*GetPlatformIDs)(cl_uint, cl_platform_id*, cl_uint*);
  cl_int (*GetPlatformInfo)(cl_platform_id, cl_uint, size_t, void*, size_t*);
  cl_int (*GetDeviceIDs)(cl_platform_id, cl_ulong, cl_uint, cl_device_id*, cl_uint*);
  cl_int (*GetDeviceInfo)(cl_device_id, cl_uint, size_t, void*, size_t*);
  cl_context (*CreateContext)(const void*, cl_uint, const cl_device_id*, void*, void*, cl_int*);
  cl_command_queue (*CreateCommandQueue)(cl_context, cl_device_id, cl_ulong, cl_int*);
  cl_program (*CreateProgramWithSource)(cl_context, cl_uint, const char**, const size_t*, cl_int*);
  cl_int (*BuildProgram)(cl_program, cl_uint, const cl_device_id*, const char*, void*, void*);
  cl_int (*GetProgramBuildInfo)(cl_program, cl_device_id, cl_uint, size_t, void*, size_t*);
  cl_kernel (*CreateKernel)(cl_program, const char*, cl_int*);
  cl_mem (*CreateBuffer)(cl_context, cl_ulong, size_t, void*, cl_int*);
  cl_int (*SetKernelArg)(cl_kernel, cl_uint, size_t, const void*);
  cl_int (*EnqueueNDRangeKernel)(cl_command_queue, cl_kernel, cl_uint, const size_t*, const size_t*, const size_t*, cl_uint, const cl_event*, cl_event*);
  cl_int (*EnqueueReadBuffer)(cl_command_queue, cl_mem, cl_uint, size_t, size_t, void*, cl_uint, const cl_event*, cl_event*);
  cl_int (*EnqueueWriteBuffer)(cl_command_queue, cl_mem, cl_uint, size_t, size_t, const void*, cl_uint, const cl_event*, cl_event*);
  cl_int (*Finish)(cl_command_queue);
} CL;
static int cl_load(void){
#ifdef _WIN32
  HMODULE h=LoadLibraryA("OpenCL.dll"); if(!h) return 0;
  #define LD(n) *(void**)&CL.n=(void*)GetProcAddress(h,"cl" #n); if(!CL.n) return 0;
#else
  void *h=dlopen("libOpenCL.so.1",RTLD_NOW); if(!h) h=dlopen("libOpenCL.so",RTLD_NOW); if(!h) return 0;
  #define LD(n) *(void**)&CL.n=dlsym(h,"cl" #n); if(!CL.n) return 0;
#endif
  LD(GetPlatformIDs) LD(GetPlatformInfo) LD(GetDeviceIDs) LD(GetDeviceInfo) LD(CreateContext) LD(CreateCommandQueue)
  LD(CreateProgramWithSource) LD(BuildProgram) LD(GetProgramBuildInfo) LD(CreateKernel) LD(CreateBuffer)
  LD(SetKernelArg) LD(EnqueueNDRangeKernel) LD(EnqueueReadBuffer) LD(EnqueueWriteBuffer) LD(Finish)
  return 1;
}

/* ---- SHA-256 referansi (CPU): midstate hesabi ve isabet dogrulamasi ---- */
#define ROR32(x,n) (((x)>>(n))|((x)<<(32-(n))))
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
/* P[0..7]=3 tur sonrasi durum, P[8..15]=midstate, P[16..18]=basligin son 12 bayti (w0..w2) */
static void make_params(const uint8_t *hdr, uint32_t P[19]){
  uint32_t mid[8],b0[16],w[3],a,b,cc,d,e,f,g,h,t1,t2;int i;
  memcpy(mid,IV,32);for(i=0;i<16;i++)b0[i]=be32(hdr+4*i);compress(mid,b0);
  w[0]=be32(hdr+64);w[1]=be32(hdr+68);w[2]=be32(hdr+72);
  a=mid[0];b=mid[1];cc=mid[2];d=mid[3];e=mid[4];f=mid[5];g=mid[6];h=mid[7];
  for(i=0;i<3;i++){
    t1=h+(ROR32(e,6)^ROR32(e,11)^ROR32(e,25))+((e&f)^(~e&g))+K[i]+w[i];
    t2=(ROR32(a,2)^ROR32(a,13)^ROR32(a,22))+((a&b)^(a&cc)^(b&cc));
    h=g;g=f;f=e;e=d+t1;d=cc;cc=b;b=a;a=t1+t2;
  }
  P[0]=a;P[1]=b;P[2]=cc;P[3]=d;P[4]=e;P[5]=f;P[6]=g;P[7]=h;
  for(i=0;i<8;i++)P[8+i]=mid[i];
  P[16]=w[0];P[17]=w[1];P[18]=w[2];
}

/* ---- zaman / uyku ---- */
static double now_s(void){
#ifdef _WIN32
  LARGE_INTEGER f,c; QueryPerformanceFrequency(&f); QueryPerformanceCounter(&c); return (double)c.QuadPart/(double)f.QuadPart;
#else
  struct timespec t; clock_gettime(CLOCK_MONOTONIC,&t); return t.tv_sec+t.tv_nsec*1e-9;
#endif
}
static void sleep_s(double s){
  if(s<=0) return;
#ifdef _WIN32
  Sleep((DWORD)(s*1000.0+0.5));
#else
  usleep((useconds_t)(s*1e6));
#endif
}

/* ---- OpenCL cekirdegi (kernel.cl'den uretildi) ---- */
static const char *KERNEL_SRC =
"#ifndef HCAP\n"
"#define HCAP 16u\n"
"#endif\n"
"#ifndef HM\n"
"#define HM 0xffffffffu\n"
"#endif\n"
"#define R(x,n) rotate((uint)(x),(uint)(32-(n)))\n"
"#define S0(x) (R(x,2)^R(x,13)^R(x,22))\n"
"#define S1(x) (R(x,6)^R(x,11)^R(x,25))\n"
"#define s0(x) (R(x,7)^R(x,18)^((x)>>3))\n"
"#define s1(x) (R(x,17)^R(x,19)^((x)>>10))\n"
"#define CH(e,f,g) bitselect((g),(f),(e))\n"
"#define MAJ(a,b,c) bitselect((b),(a),(b)^(c))\n"
"#define RND(i,w) { uint t1=h+S1(e)+CH(e,f,g)+KK[i]+(w); uint t2=S0(a)+MAJ(a,b,c); h=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2; }\n"
"__constant uint KK[64]={0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u};\n"
"__kernel void scan(__constant uint *P, const uint base, __global uint *hits){\n"
"  uint nonce = base + (uint)get_global_id(0);\n"
"  uint W[16];\n"
"  uint a=P[0],b=P[1],c=P[2],d=P[3],e=P[4],f=P[5],g=P[6],h=P[7];\n"
"  W[0]=P[16];W[1]=P[17];W[2]=P[18];\n"
"  W[3]=((nonce&0xffu)<<24)|((nonce&0xff00u)<<8)|((nonce>>8)&0xff00u)|(nonce>>24);\n"
"  W[4]=0x80000000u;\n"
"  #pragma unroll\n"
"  for(int i=5;i<15;i++) W[i]=0u;\n"
"  W[15]=640u;\n"
"  #pragma unroll\n"
"  for(int i=3;i<64;i++){\n"
"    uint w;\n"
"    if(i<16) w=W[i];\n"
"    else { w=W[i&15]+s0(W[(i+1)&15])+W[(i+9)&15]+s1(W[(i+14)&15]); W[i&15]=w; }\n"
"    RND(i,w)\n"
"  }\n"
"  uint X[16];\n"
"  X[0]=P[8]+a;X[1]=P[9]+b;X[2]=P[10]+c;X[3]=P[11]+d;X[4]=P[12]+e;X[5]=P[13]+f;X[6]=P[14]+g;X[7]=P[15]+h;\n"
"  X[8]=0x80000000u;\n"
"  #pragma unroll\n"
"  for(int i=9;i<15;i++) X[i]=0u;\n"
"  X[15]=256u;\n"
"  a=0x6a09e667u;b=0xbb67ae85u;c=0x3c6ef372u;d=0xa54ff53au;e=0x510e527fu;f=0x9b05688cu;g=0x1f83d9abu;h=0x5be0cd19u;\n"
"  #pragma unroll\n"
"  for(int i=0;i<61;i++){\n"
"    uint w;\n"
"    if(i<16) w=X[i];\n"
"    else { w=X[i&15]+s0(X[(i+1)&15])+X[(i+9)&15]+s1(X[(i+14)&15]); X[i&15]=w; }\n"
"    RND(i,w)\n"
"  }\n"
"  if(((e+0x5be0cd19u)&HM)==0u){\n"
"    uint idx=atomic_inc(&hits[0]);\n"
"    if(idx<HCAP) hits[1+idx]=nonce;\n"
"  }\n"
"}\n"
;

typedef struct { cl_context ctx; cl_command_queue q; cl_kernel k; cl_mem pb, hb; char name[128]; } GPU;
static int g_duty=100;
static size_t g_lws=0;
static uint32_t g_hcap=16;   /* cekirdekteki isabet tamponu (HCAP ile ayni olmali) */

static int pick_device(int want, cl_device_id *out, char *name, size_t nl, int verbose){
  cl_platform_id pl[8]; cl_uint np=0; int idx=0, discrete=0;
  if(CL.GetPlatformIDs(8,pl,&np)!=CL_SUCCESS||!np) return 0;
  for(cl_uint i=0;i<np;i++){
    cl_device_id dv[16]; cl_uint nd=0; char pn[128]="?";
    CL.GetPlatformInfo(pl[i],CL_PLATFORM_NAME,sizeof pn,pn,NULL);
    if(CL.GetDeviceIDs(pl[i],CL_DEVICE_TYPE_ALL,16,dv,&nd)!=CL_SUCCESS) continue;
    for(cl_uint j=0;j<nd;j++,idx++){
      char dn[128]="?"; cl_ulong ty=0; cl_uint cu=0;
      CL.GetDeviceInfo(dv[j],CL_DEVICE_NAME,sizeof dn,dn,NULL);
      CL.GetDeviceInfo(dv[j],CL_DEVICE_TYPE,sizeof ty,&ty,NULL);
      CL.GetDeviceInfo(dv[j],CL_DEVICE_MAX_COMPUTE_UNITS,sizeof cu,&cu,NULL);
      if(verbose) printf("  [%d] %s | %s | %s | %u birim\n",idx,dn,pn,(ty&CL_DEVICE_TYPE_GPU)?"GPU":"diger",cu);
      if(want<0){
        /* otomatik: once NVIDIA/AMD (ayrik kart), yoksa ilk GPU (ornegin Intel tumlesik) */
        if(ty&CL_DEVICE_TYPE_GPU){
          int disc=strstr(pn,"NVIDIA")||strstr(pn,"AMD")||strstr(pn,"Advanced Micro");
          if(!*out || (disc && !discrete)){ *out=dv[j]; discrete=disc; snprintf(name,nl,"%s",dn); }
        }
      } else if(idx==want && !*out){ *out=dv[j]; snprintf(name,nl,"%s",dn); }
    }
  }
  return *out!=NULL;
}
static int gpu_init(GPU *g,int want,const char *opts){
  cl_device_id dev=NULL; cl_int err;
  if(!pick_device(want,&dev,g->name,sizeof g->name,0)){ fprintf(stderr,"GPU bulunamadi (OpenCL cihazi yok). --info ile bak.\n"); return 0; }
  g->ctx=CL.CreateContext(NULL,1,&dev,NULL,NULL,&err); if(err){fprintf(stderr,"context hatasi %d\n",err);return 0;}
  g->q=CL.CreateCommandQueue(g->ctx,dev,0,&err); if(err){fprintf(stderr,"queue hatasi %d\n",err);return 0;}
  cl_program p=CL.CreateProgramWithSource(g->ctx,1,&KERNEL_SRC,NULL,&err); if(err){fprintf(stderr,"program hatasi %d\n",err);return 0;}
  if(CL.BuildProgram(p,1,&dev,opts,NULL,NULL)!=CL_SUCCESS){
    static char log[8192]; log[0]=0; CL.GetProgramBuildInfo(p,dev,CL_PROGRAM_BUILD_LOG,sizeof log-1,log,NULL);
    fprintf(stderr,"cekirdek derlenemedi:\n%s\n",log); return 0; }
  g->k=CL.CreateKernel(p,"scan",&err); if(err){fprintf(stderr,"kernel hatasi %d\n",err);return 0;}
  g->pb=CL.CreateBuffer(g->ctx,CL_MEM_READ_ONLY,19*4,NULL,&err); if(err)return 0;
  g->hb=CL.CreateBuffer(g->ctx,CL_MEM_READ_WRITE,129*4,NULL,&err); if(err)return 0;
  CL.SetKernelArg(g->k,0,sizeof(cl_mem),&g->pb); CL.SetKernelArg(g->k,2,sizeof(cl_mem),&g->hb);
  return 1;
}
/* [start, start+count) araligini tara; isabetleri dogrulayip yazdirir. dondurur: dogrulanan isabet sayisi, -1 = hata */
static long gpu_scan(GPU *g,const uint8_t *h76,uint32_t start,uint64_t count,size_t *batch,uint32_t hmask_check,int quiet,uint32_t *collect,int ncollect){
  uint32_t P[19]; make_params(h76,P);
  if(CL.EnqueueWriteBuffer(g->q,g->pb,CL_TRUE,0,sizeof P,P,0,NULL,NULL)!=CL_SUCCESS) return -1;
  uint32_t ver=(uint32_t)h76[0]|((uint32_t)h76[1]<<8)|((uint32_t)h76[2]<<16)|((uint32_t)h76[3]<<24);
  long ok=0; uint64_t done=0;
  while(done<count){
    size_t n=*batch; if(count-done<n) n=(size_t)(count-done);
    uint32_t hits[129]={0}; uint32_t base=start+(uint32_t)done;
    double t0=now_s();
    if(CL.EnqueueWriteBuffer(g->q,g->hb,CL_TRUE,0,sizeof hits,hits,0,NULL,NULL)!=CL_SUCCESS) return -1;
    CL.SetKernelArg(g->k,1,sizeof base,&base);
    size_t lws=g_lws; if(lws){ n=(n+lws-1)/lws*lws; }   /* GPU_LWS: work-group boyutu (0 = surucu secsin) */
    if(CL.EnqueueNDRangeKernel(g->q,g->k,1,NULL,&n,lws?&lws:NULL,0,NULL,NULL)!=CL_SUCCESS) return -1;
    if(CL.EnqueueReadBuffer(g->q,g->hb,CL_TRUE,0,sizeof hits,hits,0,NULL,NULL)!=CL_SUCCESS) return -1;
    double dt=now_s()-t0;
    uint32_t nh=hits[0]; if(nh>g_hcap){ fprintf(stderr,"cok fazla isabet (%u), ilk %u alindi\n",nh,g_hcap); nh=g_hcap; }
    for(uint32_t i=0;i<nh;i++){
      uint32_t nonce=hits[1+i], s[8]; scalar_hash(h76,nonce,s);
      if((s[7]&hmask_check)!=0){ fprintf(stderr,"UYUSMAZLIK nonce=%u\n",nonce); continue; }
      ok++;
      if(collect && (int)i<ncollect) collect[i]=nonce;
      if(!quiet){
        printf("%u %08x ",nonce,nonce);
        for(int k=7;k>=0;k--){uint32_t x=s[k];printf("%02x%02x%02x%02x",x&255,(x>>8)&255,(x>>16)&255,x>>24);}
        printf(" %08x\n",ver);
      }
    }
    done+=n;
    /* tek cagrinin suresini ~25-60 ms'de tut (ekran/surucu zaman asimi ve tepkisellik icin) */
    if(dt<0.025 && *batch<((size_t)1<<26)) *batch<<=1; else if(dt>0.060 && *batch>((size_t)1<<16)) *batch>>=1;
    if(g_duty<100) sleep_s(dt*(100.0/g_duty-1.0));
  }
  return ok;
}

static int parse_h76(const char *s,uint8_t h[76]){
  if(strlen(s)!=152) return 0;
  for(int i=0;i<76;i++){int a=hexv(s[2*i]),b=hexv(s[2*i+1]);if(a<0||b<0)return 0;h[i]=(uint8_t)((a<<4)|b);}
  return 1;
}

int main(int argc,char**argv){
  const char *mode=argc>=2?argv[1]:"--help";
  int want=-1; if(getenv("GPU_DEVICE")) want=atoi(getenv("GPU_DEVICE")); if(argc>=3 && argv[2][0]!='-') want=atoi(argv[2]);
  if(getenv("GPU_LWS")) g_lws=(size_t)atoi(getenv("GPU_LWS"));
  if(getenv("GPU_DUTY")){ g_duty=atoi(getenv("GPU_DUTY")); if(g_duty<1)g_duty=1; if(g_duty>100)g_duty=100; }
  if(!cl_load()){ fprintf(stderr,"OpenCL.dll/libOpenCL bulunamadi: ekran karti surucusu kurulu degil.\n"); return 2; }
  if(!strcmp(mode,"--info")){
    cl_device_id d=NULL; char nm[128]; puts("OpenCL cihazlari:"); int ok=pick_device(want,&d,nm,sizeof nm,1);
    printf(ok?"secilen: %s\n":"GPU yok\n",nm); return ok?0:1; }
  if(!strcmp(mode,"--test")){
    g_hcap=128; GPU g; if(!gpu_init(&g,want,"-DHM=0x0000ffffu -DHCAP=128u")) return 1;
    uint8_t h[76]; for(int i=0;i<76;i++) h[i]=(uint8_t)(i*37+11);
    size_t batch=1<<18; uint32_t got[128]; long n=gpu_scan(&g,h,0xFFFF0000u,1u<<20,&batch,0xffffu,1,got,128);
    long ref=0; for(uint64_t i=0;i<(1u<<20);i++){ uint32_t s[8]; scalar_hash(h,0xFFFF0000u+(uint32_t)i,s); if((s[7]&0xffffu)==0) ref++; }
    printf("GPU: %s\nGPU isabet: %ld | CPU referans isabet: %ld -> %s\n",g.name,n,ref,(n==ref&&ref>0)?"TEST OK":"TEST HATA");
    return (n==ref&&ref>0)?0:1; }
  if(!strcmp(mode,"--bench")){
    GPU g; if(!gpu_init(&g,want,"-DHM=0xffffffffu -DHCAP=16u")) return 1;
    uint8_t h[76]; for(int i=0;i<76;i++) h[i]=(uint8_t)(i*37+11);
    size_t batch=1<<20; uint64_t tot=0; double t0=now_s(),t;
    fprintf(stderr,"GPU: %s (GPU_DUTY=%d)\n",g.name,g_duty);
    while((t=now_s()-t0)<5.0){ if(gpu_scan(&g,h,(uint32_t)tot,1u<<24,&batch,0xffffffffu,1,NULL,0)<0){fprintf(stderr,"hata\n");return 1;} tot+=1u<<24; }
    printf("%.2f MH/s (batch=%zu)\n",tot/t/1e6,batch); return 0; }
  if(!strcmp(mode,"--serve")){
    /* GPU_HM: yalniz test icin (dusuk zorluklu deneme); normalde ayarlanmaz = 0xffffffff (tam 32 sifir bit) */
    uint32_t hm=getenv("GPU_HM")?(uint32_t)strtoul(getenv("GPU_HM"),NULL,16):0xffffffffu; char opt[96];
    if(hm!=0xffffffffu) g_hcap=128;   /* test modu: daha cok isabet gelebilir */
    snprintf(opt,sizeof opt,"-DHM=0x%xu -DHCAP=%uu",hm,g_hcap);
    GPU g; if(!gpu_init(&g,want,opt)) return 1;
    fprintf(stderr,"GPU hazir: %s (GPU_DUTY=%d)\n",g.name,g_duty);
    size_t batch=1<<22; char line[512];
    while(fgets(line,sizeof line,stdin)){
      char hx[200]; unsigned long long st,cn; uint8_t h[76];
      if(sscanf(line,"%199s %llu %llu",hx,&st,&cn)!=3||!parse_h76(hx,h)){ puts("ERR"); fflush(stdout); continue; }
      if(gpu_scan(&g,h,(uint32_t)st,cn,&batch,hm,0,NULL,0)<0) puts("ERR"); else puts("DONE");
      fflush(stdout);
    }
    return 0; }
  fprintf(stderr,"kullanim: gpu_scan --info | --test | --bench | --serve [cihaz]\n"); return 1;
}
