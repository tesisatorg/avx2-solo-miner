import socketserver,json,hashlib
sha=lambda b:hashlib.sha256(hashlib.sha256(b).digest()).digest()
MASK=0x1fffe000; BASEVER=0x20000000
class H(socketserver.StreamRequestHandler):
    def w(self,o): self.wfile.write((json.dumps(o)+"\n").encode())
    def handle(self):
        for line in self.rfile:
            m=json.loads(line)
            if m['method']=='mining.configure':
                self.w({"id":m['id'],"result":{"version-rolling":True,"version-rolling.mask":"1fffe000"},"error":None})
            elif m['method']=='mining.subscribe': self.w({"id":m['id'],"result":[[["mining.notify","x"]],"deadbeef",4],"error":None})
            elif m['method']=='mining.authorize':
                self.w({"id":m['id'],"result":True,"error":None})
                self.w({"id":None,"method":"mining.set_difficulty","params":[1e-9]})
                self.w({"id":None,"method":"mining.notify","params":["job1","00000000"*8,"0100","ffff",[],"20000000","17021673","664ba3a6",True]})
            elif m['method']=='mining.submit':
                u,job,en2,ntime,nonce=m['params'][:5]; vb=m['params'][5] if len(m['params'])>5 else None
                ver=(BASEVER&~MASK)|(int(vb,16)&MASK) if vb else BASEVER
                cb=bytes.fromhex("0100"+"deadbeef"+en2+"ffff"); mr=sha(cb)
                hdr=ver.to_bytes(4,'little')+bytes(32)+mr+bytes.fromhex(ntime)[::-1]+bytes.fromhex("17021673")[::-1]+int(nonce,16).to_bytes(4,'little')
                h=sha(hdr)[::-1].hex(); lz=len(h)-len(h.lstrip('0'))
                ok = int(h,16)>>(256-12)==0
                inmask = (int(vb,16)&~MASK)==0 if vb else True
                print("VERIFY","OK" if ok and inmask else "FAIL","vbits",vb,"ver=%08x"%ver,"hash",h[:20],flush=True)
                self.w({"id":m['id'],"result":bool(ok and inmask),"error":None})
class S(socketserver.ThreadingTCPServer): allow_reuse_address=True
S(("127.0.0.1",3333),H).serve_forever()
