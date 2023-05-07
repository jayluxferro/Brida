# -*- coding: utf-8 -*-
import frida
import codecs
import Pyro4
import sys
from base64 import b64decode

# reload(sys)
# sys.setdefaultencoding('utf-8')

class Unbuffered(object):
    def __init__(self, stream):
        self.stream = stream

    def write(self, data):
        self.stream.write(data)
        self.stream.flush()

    def writelines(self, data):
        self.stream.writelines(data)
        self.stream.flush()

    def __getattr__(self, attr):
        return getattr(self.stream, attr)


@Pyro4.expose
class BridaServicePyro:
    def __init__(self, service):
        self.application_id = None
        self.script = None
        self.session = None
        self.frida_script = None
        self.pid = None
        self.device = None
        self.daemon = service

    def attach_application(self, pid, frida_script, device):
        self.frida_script = frida_script

        if pid.isnumeric():
            self.pid = int(pid)
        else:
            self.pid = pid

        if device == 'remote':
            self.device = frida.get_remote_device()
        elif device == 'usb':
            self.device = frida.get_usb_device()
        else:
            self.device = frida.get_local_device()

        self.session = self.device.attach(self.pid)

        with codecs.open(self.frida_script, 'r', 'utf-8') as f:
            source = f.read()

        self.script = self.session.create_script(source)
        self.script.load()

    def spawn_application(self, application_id, frida_script, device):
        self.application_id = application_id
        self.frida_script = frida_script

        if device == 'remote':
            self.device = frida.get_remote_device()
        elif device == 'usb':
            self.device = frida.get_usb_device()
        else:
            self.device = frida.get_local_device()

        self.pid = self.device.spawn([self.application_id])

        self.session = self.device.attach(self.pid)

        with codecs.open(self.frida_script, 'r', 'utf-8') as f:
            source = f.read()

        self.script = self.session.create_script(source)
        self.script.load()

    def resume_application(self):
        self.device.resume(self.pid)

    def reload_script(self):
        with codecs.open(self.frida_script, 'r', 'utf-8') as f:
            source = f.read()

        self.script = self.session.create_script(source)
        self.script.load()

    def disconnect_application(self):
        self.device.kill(self.pid)

    def detach_application(self):
        self.session.detach()

    def callexportfunction(self, methodName, args):
        method_to_call = getattr(self.script.exports_sync, methodName)
        # print(f"Method: {methodName} => Args: {args}")
        # Take the Java list passed as argument and create a new variable list of argument
        # (necessary for bridge Python - Java, I think)
        s = []
        for i in args:
            if type(i) == dict:
                s.append(b64decode(i['data']).decode())
            else:
                s.append(i)
            print(s)

        return_value = method_to_call(*s)
        # print(f'Method call: {method_to_call} => Args: {args} => RetVal: {return_value}')
        return return_value

    @Pyro4.oneway
    def shutdown(self):
        print('shutting down...')
        self.daemon.shutdown()


# Disable python buffering (cause issues when communicating with Java...)
sys.stdout = Unbuffered(sys.stdout)
sys.stderr = Unbuffered(sys.stderr)

host = sys.argv[1]
port = int(sys.argv[2])
daemon = Pyro4.Daemon(host=host, port=port)

# daemon = Pyro4.Daemon(host='127.0.0.1',port=9999)
bs = BridaServicePyro(daemon)
uri = daemon.register(bs, objectId='BridaServicePyro')

print("Ready.")
daemon.requestLoop()
