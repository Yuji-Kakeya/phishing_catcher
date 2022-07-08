#!/usr/bin/env python
# Copyright (c) 2017 @x0rz
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
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

from download import get_phish_feed

l1_phish_feeds = get_phish_feed(1)
l2_phish_feeds = get_phish_feed(2)
l3_phish_feeds = get_phish_feed(3)

certstream_url = 'wss://certstream.calidog.io'
log_suspicious = os.path.dirname(os.path.realpath(__file__))+'/suspicious_domains_'+time.strftime("%Y-%m-%d")+'.log'
suspicious_yaml = os.path.dirname(os.path.realpath(__file__))+'/suspicious.yaml'
external_yaml = os.path.dirname(os.path.realpath(__file__))+'/external.yaml'
safe_yaml = os.path.dirname(os.path.realpath(__file__))+'/safe.yaml'
pbar = tqdm.tqdm(desc='certificate_update', unit='cert')

fake_tld = ['com', 'net', 'org', "jp"]

base_score = {
    "l1_phish_feed": 5,
    "l2_phish_feed": 100,
    "l3_phish_feed": 1000,    
    "static_suspicious_tld": 70,
    "levenshtein_static_suspicious_keyword": 40,
    "entropy": 10,
    "fake_tld": 50,
    "hyphen": 5,
    "dot": 5
}

threshold = {
    "very_suspicious": 100,
    "suspicious": 90,
    "likely": 80,
    "potential": 70,
}

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

    flag = {
        "l1_phish_feed": False,
        "l2_phish_feed": False,
        "l3_phish_feed": False,
        "levenshtein_phish_feed": False,
        "static_safe": False,
        "static_suspicious_keyword": False,
        "static_suspicious_tld": False,
        "levenshtein_static_suspicious_keyword": False,
        "fake_tld": False,
        "hyphen": False,
        "dot": False
    }

    # Remove initial '*.' for wildcard certificates bug
    if domain.startswith('*.'):
        domain = domain[2:]

    # Remove lookalike characters using list from http://www.unicode.org/reports/tr39
    domain = unconfuse(domain)
    words_in_domain = re.split("\W+", domain)


    # # Removing TLD to catch inner TLD in subdomain (ie. paypal.com.domain.com)
    # try:
    #     res = get_tld(domain, as_object=True, fail_silently=True, fix_protocol=True)
    #     domain = '.'.join([res.subdomain, res.domain])
    # except Exception:
    #     pass


    #Phish Feed
    try:
        for phish_feed in l1_phish_feeds:
            if domain.endswith(l1_phish_feed):
                score += base_score["phish_feed"]
                flag["l1_phish_feed"] = True

        for phish_feed in l2_phish_feeds:
            if domain.endswith(l2_phish_feed):
                score += base_score["phish_feed"]
                flag["l2_phish_feed"] = True

        for phish_feed in l3_phish_feeds:
            if domain.endswith(l3_phish_feed):
                score += base_score["phish_feed"]
                flag["l3_phish_feed"] = True
    except:
        pass

    #Static Safe Domain
    try:
        for end_word in safe['end_words']:
            if domain.endswith(end_word):
                flag["static_safe"] = True
                return (0, flag)

        for keyword in safe['keywords']:
            if keyword in domain:
                flag["static_safe"] = True
                return (0, flag)
    except:
        print("error safe_domain")
        pass



    #Static Suspicious Domain
    try:
        for end_word in suspicious['end_words']:
            if domain.endswith(end_word):
                score += suspicious['end_words'][end_word]
                flag["static_suspicious_keyword"] = True

        for keyword in suspicious['keywords']:
            if keyword in domain:
                score += suspicious['keywords'][keyword]
                flag["static_suspicious_keyword"] = True

        for tld in suspicious['tlds']:
            if domain.endswith(tld):
                score += base_score["static_suspicious_tld"]
                flag["static_suspicious_tld"] = True               
    except:
        print("error suspicious_domain")        
        pass


    # Higer entropy is kind of suspicious
    score += int(round(entropy(domain)*base_score["entropy"]))

    # ie. detect fake .com (ie. *.com-account-management.info)
    try:
        for word in words_in_domain[-1]:
            if word in fake_tld:
                score += base_score["fake_tld"]
                flag["fake_tld"] = True
    except:
        print("error fake_tld")


    # Testing Levenshtein distance for strong keywords (>= 70 points) (ie. paypol)
    try:
        for key in [k for (k,s) in suspicious['keywords'].items() if s >= 70]:
            # Removing too generic keywords (ie. mail.domain.com)
            for word in [w for w in words_in_domain if w not in ['email', 'mail', 'cloud']]:
                if distance(str(word), str(key)) == 1:
                    score += base_score["levenshtein_static_suspicious_keyword"]
                    flag["levenshtein_static_suspicious_keyword"] = True
    except:
        print("error levenshtein")

    # Lots of '-' (ie. www.paypal-datacenter.com-acccount-alert.com)
    if 'xn--' not in domain and domain.count('-') >= 4:
        score += domain.count('-') * base_score["hyphen"]
        flag["hyphen"] = True

    # Deeply nested subdomains (ie. www.paypal.com.security.accountupdate.gq)
    if domain.count('.') >= 3:
        score += domain.count('.') * base_score["dot"]
        flag["dot"] = True

    return (score, flag)





def callback(message, context):
    """Callback handler for certstream events."""
    if message['message_type'] == "heartbeat":
        return

    if message['message_type'] == "certificate_update":
        all_domains = message['data']['leaf_cert']['all_domains']

        for domain in all_domains:
            pbar.update(1)
            score, flag = score_domain(domain.lower())

            # If issued from a free CA = more suspicious
            if "Let's Encrypt" == message['data']['leaf_cert']['issuer']['O']:
                score += 10

            if score >= threshold["very_suspicious"]:
                tqdm.tqdm.write(
                    "[!] Suspicious: "
                    "{} (score={})".format(colored(domain, 'red', attrs=['underline', 'bold']), score))
            elif score >= threshold["suspicious"]:
                tqdm.tqdm.write(
                    "[!] Suspicious: "
                    "{} (score={})".format(colored(domain, 'magenta', attrs=['underline']), score))
            elif score >= threshold["likely"]:
                tqdm.tqdm.write(
                    "[!] Likely    : "
                    "{} (score={})".format(colored(domain, 'yellow', attrs=['underline']), score))
            elif score >= threshold["potential"]:
                tqdm.tqdm.write(
                    "[+] Potential : "
                    "{} (score={})".format(colored(domain, 'cyan', attrs=['underline']), score))


            if score >= 50:
                with open(log_suspicious, 'a') as f:
                    f.write("{}\n".format(domain))


if __name__ == '__main__':
    with open(suspicious_yaml, 'r') as f:
        suspicious = yaml.safe_load(f)

    with open(external_yaml, 'r') as f:
        external = yaml.safe_load(f)

    with open(safe_yaml, 'r') as f:
        safe = yaml.safe_load(f)

    if external['override_suspicious.yaml'] is True:
        suspicious = external
    else:
        if external['keywords'] is not None:
            suspicious['keywords'].update(external['keywords'])

        if external['tlds'] is not None:
            suspicious['tlds'].update(external['tlds'])

    certstream.listen_for_events(callback, url=certstream_url)
