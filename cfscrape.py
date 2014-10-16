import re, requests, operator as op
from urlparse import urlparse
from requests.adapters import HTTPAdapter

DEFAULT_USER_AGENT = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
                      "Ubuntu Chromium/34.0.1847.116 Chrome/34.0.1847.116 Safari/537.36")

KITTY = ['+[]', '+!![]'] + [''.join(['!+[]'] + ['+!![]' for _ in (range(1, i))]) for i in range(2, 10)]

class CloudflareAdapter(HTTPAdapter):
    def send(self, request, **kwargs):
        domain = request.url.split("/")[2]
        resp = super(CloudflareAdapter, self).send(request, **kwargs)

        # Check if we already solved a challenge
        if request._cookies.get("cf_clearance", domain="." + domain):
            return resp

        # Check if Cloudflare anti-bot is on
        if "a = document.getElementById('jschl-answer');" in resp.content:
            return self.solve_cf_challenge(resp, request.headers, **kwargs)

        # Otherwise, no Cloudflare anti-bot detected
        return resp

    def add_headers(self, request):
        # Spoof Chrome on Linux if no custom User-Agent has been set
        if "requests" in request.headers["User-Agent"]:
            request.headers["User-Agent"] = DEFAULT_USER_AGENT

    def calculate_challenge(self, s):
        output = None

        for o in ''.join(['\n' if e in list('()') else e for e in list(s)]).split('\n'):
          if '[' not in o: continue

          answer = 1 if o.replace('[]+[]', '[]') == '!![]' else KITTY.index(o.replace('[]+[]', '[]'))

          if isinstance(output, basestring) or '[]+[]' in o:
              answer = str(answer)
          
          output = answer if output == None else output + answer

        return int(output)

    def solve_cf_challenge(self, resp, headers, **kwargs):
        headers = headers.copy()
        url = resp.url
        parsed = urlparse(url)
        domain = parsed.netloc
        page = resp.content
        kwargs.pop("params", None)

        try:
            challenge = re.search(r'name="jschl_vc" value="(\w+)"', page).group(1)
            items = [filter(None, x) for x in re.findall(r'(?:(?:"(:)(.*?)})|([-+\*\/])=(.*?))\;', page)]

            for s, l in items:
                c = self.calculate_challenge(l)
                answer = c if s == ':' else ({'+': op.add, '-': op.sub, '*': op.mul, '/': op.div}[s])(answer, c)

        except AttributeError:
            raise IOError("Unable to parse Cloudflare anti-bots page.")

        params = {"jschl_vc": challenge, "jschl_answer": answer + len(domain)}
        submit_url = "%s://%s/cdn-cgi/l/chk_jschl" % (parsed.scheme, domain)
        headers["Referer"] = url

        return requests.get(submit_url, params=params, headers=headers, **kwargs)


def create_scraper(session=None):
    """
    Convenience function for creating a ready-to-go requests.Session object.
    You may optionally pass in an existing Session to mount the CloudflareAdapter to it.
    """
    sess = session or requests.session()
    adapter = CloudflareAdapter()
    sess.mount("http://", adapter)
    sess.mount("https://", adapter)
    return sess
