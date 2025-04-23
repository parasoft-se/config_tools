import re
import subprocess

class Cpptest:
    def __init__(self, install_path):
        self.variant = None
        self.friendly_version = None
        self.version = None
        self.build = None
        self.install_path = install_path

        #try to parse out version_info
        version_text = subprocess.run([install_path + '/cpptestcli', '-version'], stdout=subprocess.PIPE).stdout.decode('utf-8')
        groups = re.search(r"Parasoft C/C\+\+test ([A-Za-z0-9_\-]+) ([0-9.]+) \(([0-9.]+)B([0-9]+)\).*", version_text)

        if groups is not None:
            self.variant = groups.group(1)
            self.friendly_version = groups.group(2)
            self.version = groups.group(3)
            self.build = groups.group(4)
