import socketserver,json,sys
SUPPORT = sys.argv[1]=="on"
class H(socketserver.StreamRequestHandler):
    def w(self,o): self.wfile.write((json.dumps(o)+"\n").encode())
    def handle(self):
        for line in self.rfile:
            m=json.loads(line)
            if m['method']=='mining.configure':
                if SUPPORT: self.w({"id":m['id'],"result":{"version-rolling":True,"version-rolling.mask":"1fffe000"},"error":None})
                else: self.w({"id":m['id'],"result":None,"error":[20,"Unknown method",None]})
            elif m['method']=='mining.subscribe':
                self.w({"id":m['id'],"result":[[["mining.notify","x"]],"deadbeef",4],"error":None})
            elif m['method']=='mining.authorize':
                self.w({"id":m['id'],"result":True,"error":None})
                self.w({"id":None,"method":"mining.set_difficulty","params":[1]})
                self.w({"id":None,"method":"mining.notify","params":["job1","00000000"*8,"0100","ffff",[],"20000000","17021673","664ba3a6",True]})
            elif m['method']=='mining.submit':
                print("SUBMIT",m['params'],flush=True)
                self.w({"id":m['id'],"result":True,"error":None})
class S(socketserver.ThreadingTCPServer): allow_reuse_address=True
S(("127.0.0.1",3333),H).serve_forever()
