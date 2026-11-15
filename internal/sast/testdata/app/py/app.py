import subprocess
import yaml

def run(cmd):
    return subprocess.call(cmd, shell=True)

def load(text):
    return yaml.load(text)

PASSWORD = "hunter2"
