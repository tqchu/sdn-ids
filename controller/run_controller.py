#!/usr/bin/env python3
import os, sys, importlib, queue

# 1) Force Ryu to pick its pure-thread hub
os.environ['RYU_HUB_TYPE'] = 'thread'

# 2) Preload and monkey-patch ryu.lib.hub so all imports succeed
hub = importlib.import_module('ryu.lib.hub')

# stub out hub.patch()
setattr(hub, 'patch', lambda *args, **kwargs: None)

# stub out WSGIServer
class DummyWSGIServer:
    def __init__(self, *args, **kwargs): pass
    def start(self): pass
    def stop(self): pass
setattr(hub, 'WSGIServer', DummyWSGIServer)

# stub out StreamServer
class DummyStreamServer:
    def __init__(self, *args, **kwargs): pass
    def serve_forever(self): pass
    def close(self): pass
setattr(hub, 'StreamServer', DummyStreamServer)

# stub out Queue
setattr(hub, 'Queue', queue.Queue)

# 3) Grab your Ryu app name from argv
if len(sys.argv) != 2:
    print(f"Usage: {sys.argv[0]} <ryu_app_module>")
    sys.exit(1)
app = sys.argv[1]

# 4) Rewrite sys.argv for ryu-manager
sys.argv[:] = ['ryu-manager', app]

# 5) Launch
from ryu.cmd.manager import main
main()
