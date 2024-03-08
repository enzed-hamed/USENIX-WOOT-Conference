#!/usr/bin/env python3
import os
import signal
import requests
import threading
import random
import time


def sigint_handler(*args, **keywords):
    os.kill(os.getpid(), signal.SIGKILL)


signal.signal(signal.SIGINT, sigint_handler)

hsts_list = dict()
insecure = dict()

errors = list()
domains = list()

domain_file = "top-1k.csv"
with open(domain_file) as f:
    while domain := f.readline():
        domains.append(domain.split(",")[1].strip("\n"))

rand_num = "".join(random.choices("0123456789", k=4))
base_name = "{}_{}".format(domain_file.split(".")[0], rand_num)

mutex = threading.Lock()
thread_list = []
connection_pool = threading.Semaphore(100)


headers = {
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36"
}


def send_a_request(domain):
    counter_flag = 10
    while counter_flag:
        counter_flag -= 1
        try:
            res = requests.head(
                "http://{}".format(domain),
                allow_redirects=True,
                timeout=10,
                headers=headers,
            )
        except Exception as e:
            print("@", flush=True, end="")
            time.sleep(random.randint(1, 5))
        else:
            if "strict-transport-security" in res.headers.keys():
                with mutex:
                    print("*", flush=True, end="")
                    hsts_list[domain] = res.headers
            else:
                with mutex:
                    print(".", flush=True, end="")
                    insecure[domain] = res.headers
            break
        counter_flag -= 1

    if not counter_flag:
        errors.append(domain)

    connection_pool.release()


for record in domains:
    connection_pool.acquire()
    thread = threading.Thread(target=send_a_request, args=(record,))
    thread_list.append(thread)
    thread.start()
    time.sleep(0.1)

for thread in thread_list:
    if thread.is_alive():
        print("\n\n> House keeping..\n")
        thread.join()


print("\n[+] Writing Errors Log Files")
with open("errors-{}.txt".format(base_name), "w") as f:
    for record in errors:
        print(record, file=f, flush=True)


print("[+] Writing HSTS Enabled Domains Log Files")
with open("hsts_log-{}.txt".format(base_name), "w") as f:
    for record in hsts_list.keys():
        print("#" * 50, file=f, flush=True)
        print("#" * 50, file=f, flush=True)
        print(record, file=f, flush=True)
        print("*" * 15, flush=True, file=f)
        print(hsts_list[record], file=f, flush=True)

with open("hsts-{}.txt".format(base_name), "w") as f:
    for record in hsts_list.keys():
        print(record, file=f, flush=True)

print("[+] Writing Insecure Domains Log Files")
with open("insecure_log-{}.txt".format(base_name), "w") as f:
    for record in insecure.keys():
        print("#" * 50, file=f, flush=True)
        print("#" * 50, file=f, flush=True)
        print(record, file=f, flush=True)
        print("*" * 15, flush=True, file=f)
        print(insecure[record], file=f, flush=True)

with open("insecure-{}.txt".format(base_name), "w") as f:
    for record in insecure.keys():
        print(record, file=f, flush=True)

print("[+] Writing Statistics")
with open("stats-{}.txt".format(base_name), "w") as f:
    print("All Domains: {}".format(len(domains)), flush=True, file=f)
    print("HSTS Enabled Websites: {}".format(len(hsts_list)), flush=True, file=f)
    print("Insecure Websites: {}".format(len(insecure)), flush=True, file=f)
    print("Encountered Errors: {}".format(len(errors)), flush=True, file=f)

print("--> Base Name: {}".format(base_name))
