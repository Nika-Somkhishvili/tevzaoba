
import re
import math

import certstream
import tqdm
import yaml
import time
import os
from Levenshtein import distance
from termcolor import colored, cprint
from tld import get_tld

from confusables import unconfuse
from flask_socketio import SocketIO, emit
import sys
import json
import requests
from flask import Flask, render_template, redirect #@new
from threading import Lock
import threading


app = Flask(__name__)
socketio = SocketIO(app)

# Initialize the data
data = 0

# Function to emit data every 1 second
def emit_data():
    while True:
        socketio.emit('data', {'domain': "google.com", "score":12})
        time.sleep(1)

def doit():
    
    socketio.emit('data', {'domain': "google.com", "score":12})
    time.sleep(1)
    
    socketio.emit('data', {'domain': "google.com", "score":12})
    time.sleep(1)

    socketio.emit('data', {'domain': "google.com", "score":12})
    time.sleep(1)
    with open(suspicious_yaml, 'r') as f:
        suspicious = yaml.safe_load(f)

    with open(external_yaml, 'r') as f:
        external = yaml.safe_load(f)

    if external['override_suspicious.yaml'] is True:
        suspicious = external
    else:
        if external['keywords'] is not None:
            suspicious['keywords'].update(external['keywords'])

        if external['tlds'] is not None:
            suspicious['tlds'].update(external['tlds'])

    certstream.listen_for_events(callback, url=certstream_url)


# Start the data emission in a separate thread
thread = threading.Thread(target=doit)
thread.daemon = True
thread.start()

@app.route('/')
def index():
    return render_template('index.html')

@socketio.on('connect')
def handle_connect():
    print('Client connected')

@socketio.on('disconnect')
def handle_disconnect():
    print('Client disconnected')

if __name__ == '__main__':
    socketio.run(app, debug=True)

# thread = None
# thread_lock = Lock()

# webhook_url = "https://eospcyrbrulc7gm.m.pipedream.net"
# items = [
#     {"domain": "paypal.sdffsdfsd.com", "score": 30},
#     {"domain": "paypal.com", "score": 12},
#     {"domain": "paypal.login.hecker.com", "score": 346},
#     {"domain": "paypal.moneyget.net", "score": 54},
# ]

# app = Flask(__name__) #@new
# socketio = SocketIO(app, cors_allowed_origins='*')

# @socketio.on('connect')
# def ws_connect():
#     global thread
#     items.append({"statusi": "new connection", "age": 99})
#     tem = {"testname": "testvalue"}
#     emit('user', tem, broadcast=True)


#     print("Starting background thread")
    
#     with thread_lock:
#         if thread is None:
#             thread = socketio.start_background_task(bg_thread)

# #@new
# @app.route('/', methods=["GET", "POST"])
# def home():
#     return render_template('index.html', items=items)

# def bg_thread():
#     while True:
#         testval = {"randval": 65}
#         print("Emitting test event:", testval) 
#         socketio.emit('test', testval, broadcast=True)
#         socketio.sleep(1)


# @app.route('/add_item', methods=['POST'])
# def add_item():
    
#     ########
#     payload = {
#         "name": "nika",
#         "haha": "huhu"
#     }
#     response = requests.post(webhook_url, json=payload)
#     #############
#     name = response.status_code
#     age = 999
#     new_item = {"name": name, "age": int(age)}
#     items.append(new_item)
#     return redirect('/')

# @app.route('/adder', methods=['GET'])
# def adder():
#     while True:
#         items.append({"name": "aa", "age": 66})
#         time.sleep(3)
    








certstream_url = 'wss://certstream.calidog.io'

log_suspicious = os.path.dirname(os.path.realpath(__file__))+'/suspicious_domains_'+time.strftime("%Y-%m-%d")+'.log'

suspicious_yaml = os.path.dirname(os.path.realpath(__file__))+'/suspicious.yaml'

external_yaml = os.path.dirname(os.path.realpath(__file__))+'/external.yaml'

pbar = tqdm.tqdm(desc='certificate_update', unit='cert')

def entropy(string):
    """Calculates the Shannon entropy of a string"""
    prob = [ float(string.count(c)) / len(string) for c in dict.fromkeys(list(string)) ]
    entropy = - sum([ p * math.log(p) / math.log(2.0) for p in prob ])
    return entropy

def score_domain(domain):
    """Score `domain`.

    The highest score, the most probable `domain` is a phishing site.

    Args:
        domain (str): the domain to check.

    Returns:
        int: the score of `domain`.
    """
    score = 0
    for t in suspicious['tlds']:
        if domain.endswith(t):
            score += 20

    # Remove initial '*.' for wildcard certificates bug
    if domain.startswith('*.'):
        domain = domain[2:]

    # Removing TLD to catch inner TLD in subdomain (ie. paypal.com.domain.com)
    try:
        res = get_tld(domain, as_object=True, fail_silently=True, fix_protocol=True)
        domain = '.'.join([res.subdomain, res.domain])
    except Exception:
        pass

    # Higer entropy is kind of suspicious
    score += int(round(entropy(domain)*10))

    # Remove lookalike characters using list from http://www.unicode.org/reports/tr39
    domain = unconfuse(domain)

    words_in_domain = re.split("\W+", domain)

    # ie. detect fake .com (ie. *.com-account-management.info)
    if words_in_domain[0] in ['com', 'net', 'org']:
        score += 10

    # Testing keywords
    for word in suspicious['keywords']:
        if word in domain:
            score += suspicious['keywords'][word]

    # Testing Levenshtein distance for strong keywords (>= 70 points) (ie. paypol)
    for key in [k for (k,s) in suspicious['keywords'].items() if s >= 70]:
        # Removing too generic keywords (ie. mail.domain.com)
        for word in [w for w in words_in_domain if w not in ['email', 'mail', 'cloud']]:
            if distance(str(word), str(key)) == 1:
                score += 70

    # Lots of '-' (ie. www.paypal-datacenter.com-acccount-alert.com)
    if 'xn--' not in domain and domain.count('-') >= 4:
        score += domain.count('-') * 3

    # Deeply nested subdomains (ie. www.paypal.com.security.accountupdate.gq)
    if domain.count('.') >= 3:
        score += domain.count('.') * 3

    return score


def callback(message, context):
    """Callback handler for certstream events."""
    socketio.emit('data', {'domain': "google.com", "score":12})
    time.sleep(1)
    socketio.emit('data', {'domain': "google.com", "score":12})
    time.sleep(1)
    socketio.emit('data', {'domain': "google.com", "score":12})
    time.sleep(1)
    if message['message_type'] == "heartbeat":
        return

    if message['message_type'] == "certificate_update":
        all_domains = message['data']['leaf_cert']['all_domains']

        for domain in all_domains:
            pbar.update(1)
            score = score_domain(domain.lower())

            # If issued from a free CA = more suspicious
            if "Let's Encrypt" == message['data']['leaf_cert']['issuer']['O']:
                score += 10

            if score >= 100:
                
                tqdm.tqdm.write(
                    "[!] Suspicious: "
                    "{} (score={})".format(colored(domain, 'red', attrs=['underline', 'bold']), score))
            elif score >= 90:
                tqdm.tqdm.write(
                    "[!] Suspicious: "
                    "{} (score={})".format(colored(domain, 'red', attrs=['underline']), score))
            elif score >= 80:
                tqdm.tqdm.write(
                    "[!] Likely    : "
                    "{} (score={})".format(colored(domain, 'yellow', attrs=['underline']), score))
            elif score >= 65:
                tqdm.tqdm.write(
                    "[+] Potential : "
                    "{} (score={})".format(colored(domain, attrs=['underline']), score))

            if score >= 75:
                with open(log_suspicious, 'a') as f:
                    f.write("{}\n".format(domain))




