import subprocess
import argparse
import threading
import time
import os

from pathlib import Path

def start_server(n, f, id):
    if id >= 10:
        command = "go run main.go -path=log{}.txt -n={} -f={} -id={} -port=:80{}".format(id, n, f, id, id)
    else:
        command = "go run main.go -path=log{}.txt -n={} -f={} -id={} -port=:800{}".format(id, n, f, id, id)
    c = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = c.communicate()
    print(stdout.decode())
    print(stderr.decode())

if __name__ == '__main__':
    parser = argparse.ArgumentParser('start server')
    parser.add_argument('n', help='Total node numbers.', type=int)
    parser.add_argument('f', help='Byzantine node numbers.', type=int)
    args = parser.parse_args()
    
    # Change work directory.
    cwd = Path.cwd().parents[1].as_posix()
    path = os.path.join(cwd, 'server')
    os.chdir(path)

    for i in range(args.n):
        x = threading.Thread(target=start_server, args=(args.n, args.f, i), daemon=True)
        x.start()

    # Wait forever (exclude ctrl+c exit program).
    while True:
        time.sleep(1)