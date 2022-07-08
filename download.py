import urllib.request as request
phish_feed = "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-NEW-today.txt"


def get_phish_feed(level):
    req = request.Request(phish_feed)
    result = []
    with request.urlopen(req) as res:
        domains = res.read().decode("utf-8").split()
        for domain in domains:
            word = domain.split(".")
            if(len(word) >= level):
                result.append(".".join([_ for _ in word[len(word)-level:]]))
    return list(set(result))