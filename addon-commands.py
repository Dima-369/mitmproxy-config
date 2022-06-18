import hashlib
import json
import os
import re
import shlex
import subprocess
import typing
from pathlib import Path
from urllib.parse import unquote, urljoin, urlparse

# noinspection PyUnresolvedReferences
import pyperclip
import sexpdata
# noinspection PyUnresolvedReferences
from mitmproxy import command
# noinspection PyUnresolvedReferences
from mitmproxy import ctx
# noinspection PyUnresolvedReferences
from mitmproxy import flow
# noinspection PyUnresolvedReferences
from mitmproxy import http

map_local_base_url = "http://api.baubuddy.de/int/index.php/"
map_local_dir = "/Users/Gira/vero/mitmproxy-local/"


def get_status_code():
    """
    :return: the response status code as a string
    """
    ctx.master.commands.execute("cut.clip @focus response.status_code")
    return pyperclip.paste()


def get_response_content_in_blocks():
    ctx.master.commands.execute("cut.clip @focus response.content")
    raw = pyperclip.paste()
    # noinspection PyBroadException
    try:
        return "```json\n" + \
               trim_response_content(json.dumps(json.loads(raw), indent=2)) + \
               "\n```"
    except Exception:
        return "```\n" + \
               trim_response_content(raw) + \
               "```"


def trim_response_content(s):
    if len(s) >= 2100:
        s = s[:2100] + "..."
    return s


def get_time_from_timestamps():
    ctx.master.commands.execute("cut.clip @focus request.timestamp_start")
    start = pyperclip.paste()
    ctx.master.commands.execute("cut.clip @focus response.timestamp_end")
    end = pyperclip.paste()
    return float(end) - float(start)


def get_curl_formatted():
    ctx.master.commands.execute("export.clip curl @focus")
    s = pyperclip.paste()

    parts = shlex.split(s)
    output = parts[0] + " \\\n"
    next_cmd = False

    for s in parts[1:]:
        if next_cmd:
            output += "'" + s + "' \\\n"
            next_cmd = False
        elif s.startswith("--"):
            output += "   " + s + " \\\n"
            next_cmd = False
        elif s.startswith("-"):
            output += "   " + s + " "
            next_cmd = True
        else:
            # in most cases this is the URL at the very end of the command
            output += "   '" + s + "' \\\n"
            next_cmd = False

    output = output.strip()
    if output.endswith("\\"):
        output = output[:-1]
    return output


class CurlAddon:
    @command.command("cu")
    def do(self) -> None:
        pyperclip.copy("```bash\n" + get_curl_formatted() + "\n```")
        ctx.log.alert("Copied cURL with ```bash to clipboard")


class UrlAddon:
    @command.command("u")
    def do(self) -> None:
        ctx.master.commands.execute("cut.clip @focus request.url")
        pyperclip.copy(unquote(pyperclip.paste()))
        ctx.log.alert("Copied URL to clipboard")


class ShortUrlAddon:
    @command.command("url")
    def do(self) -> None:
        """Copy the method plus the URL with the base and the params cut off.

        Example: GET printouts/printhours.pdf
        """
        ctx.master.commands.execute("cut.clip @focus request.url")
        raw_url = unquote(pyperclip.paste())

        last = "/index.php/"
        if last in raw_url:
            url = raw_url[raw_url.index(last) + len(last):]
            if "?" in url:
                url = url[:url.index("?")]
        else:
            url = raw_url

        ctx.master.commands.execute("cut.clip @focus request.method")
        method = pyperclip.paste()
        pyperclip.copy(method + " " + url)

        ctx.log.alert("Copied to clipboard: " + method + " " + url)


class AllResponseBodyAddon:
    @command.command("a")
    def do(self) -> None:
        curl = get_curl_formatted()
        code = get_status_code()
        time = get_time_from_timestamps()
        response = get_response_content_in_blocks()
        pyperclip.copy("```bash\n" + curl + "\n```\n\n" + "Took " +
                       "{:.2f}".format(time) + "s with " + "status code " +
                       code + " to return:\n\n" + response)
        ctx.log.alert(
            "Copied cURL, response body and status code to clipboard")


class AllResponseWithoutBodyAddon:
    @command.command("ab")
    def do(self) -> None:
        curl = get_curl_formatted()
        code = get_status_code()
        time = get_time_from_timestamps()
        pyperclip.copy("```bash\n" + curl + "\n```\n\n" + "Took " +
                       "{:.2f}".format(time) + "s with " + "status code " +
                       code + ".")
        ctx.log.alert(
            "Copied cURL  and status code to clipboard")


# request.text or request.raw_content also seem to work
class RequestBodyAddon:
    @command.command("req")
    def do(self) -> None:
        ctx.master.commands.execute("cut.clip @focus request.content")
        ctx.log.alert("Copied request body to clipboard")


class ResponseBodyAddon:
    @command.command("resp")
    def do(self) -> None:
        ctx.master.commands.execute("cut.clip @focus response.content")
        response = pyperclip.paste()
        # noinspection PyBroadException
        try:
            response = json.dumps(json.loads(response), indent=2)
            pyperclip.copy(response)
            ctx.log.alert("Copied JSON response body to clipboard")
        except Exception:
            ctx.log.alert("Copied non-JSON response body to clipboard")


class KeyBindingAddon:
    @command.command("k")
    def do(self) -> None:
        ctx.master.commands.execute("console.view.keybindings")


class QuitAddon:
    @command.command("e")
    def do(self) -> None:
        ctx.master.commands.execute("console.exit")


class FlowResumeAddon:
    @command.command("r")
    def do(self) -> None:
        ctx.master.commands.execute("flow.resume @focus")


class InterceptAddon:
    @command.command("intercept.inner")
    def addheader(self, flows: typing.Sequence[flow.Flow]) -> None:
        for f in flows:
            url = re.escape(f.request.url)
            ctx.master.commands.execute(
                f"console.command set intercept '~u {url} & ~s'")

    @command.command("cept")
    def do(self) -> None:
        ctx.master.commands.execute("intercept.inner @focus")


# interaction with Emacs/Common Lisp for automated
# test cases when used together with Selenium
class WriteFlowsToFileSystem:
    @staticmethod
    def should_persist(flow: http.HTTPFlow) -> bool:
        return flow.request.host == "api.baubuddy.de" and False

    @staticmethod
    def get_pretty_json(raw: str) -> str:
        # noinspection PyBroadException
        try:
            return json.dumps(json.loads(raw), indent=2)
        except Exception:
            return raw

    def response(self, flow: http.HTTPFlow) -> None:
        if self.should_persist(flow):
            sexp_file = Path.home() / ".cache/mitmproxy-flows.lisp"
            sexp = []
            if os.path.isfile(sexp_file):
                text = Path(sexp_file).read_text()
                if text:
                    # strip leading quote for sexpdata
                    text = text[1:]
                sexp = sexpdata.loads(text)
            else:
                # create empty file
                open(sexp_file, 'a').close()

            obj = {
                'url': flow.request.pretty_url,
                'status-code': flow.response.status_code,
                'request-content': self.get_pretty_json(flow.request.content.decode()),
                'response-content': self.get_pretty_json(flow.response.content.decode())
            }
            sexp.append(obj)

            # prepend a quote for valid Lisp code
            Path(sexp_file).write_text("'" + sexpdata.dumps(sexp))


# because some requests just take too long :/
class NopeOutRequests:
    # for the Dashboard
    filter_urls = \
        [
            "api.baubuddy.de/int/index.php/v2/reports/liveTicker?top=10",
            # "api.baubuddy.de/int/index.php/login/refresh",
            # "api.baubuddy.de/int/index.php/v2/reports/statisticsForDashboard",
        ]
    # spam Google instead of Vero API because Google has a fast response time ;)
    redirect_to = "https://www.google.de/nope"

    def request(self, flow: http.HTTPFlow) -> None:
        should_filter_url = False
        for f in self.filter_urls:
            if f in flow.request.pretty_url:
                should_filter_url = True
                break

        if should_filter_url:
            flow.request.url = self.redirect_to

    def response(self, flow: http.HTTPFlow) -> None:
        if flow.request.pretty_url == self.redirect_to:
            flow.response.status_code = 503
            flow.response.text = "{}"


def get_url_without_parameters(url):
    return urljoin(url, urlparse(url).path)


def create_url_parameters_hash(url):
    if url:
        return ' ' + hashlib.sha256(urlparse(url).query.encode('utf-8')).hexdigest()[0:12]
    return ''


def map_api_url_to_local_path(url):
    without_parameters = get_url_without_parameters(url)
    after_base = without_parameters.replace(map_local_base_url, '')
    return os.path.join(map_local_dir, after_base) + create_url_parameters_hash(url) + ".json"


class MapLocalRequests:
    """ Map to local response bodies from a directory. """

    @staticmethod
    def request(flow: http.HTTPFlow) -> None:
        url = flow.request.pretty_url
        local_file = map_api_url_to_local_path(url)
        local_header_file = local_file.replace('.json', ' headers.json')

        if os.path.exists(local_file):
            with open(local_file) as f:
                with open(local_header_file) as f_headers:
                    json_headers = json.loads(f_headers.read())
                    flow.response = http.Response.make(200, f.read(), json_headers)


def process_local_flow(flow):
    url = flow.request.pretty_url

    if map_local_base_url in url:
        content = flow.response.content

        local_file = map_api_url_to_local_path(url)
        local_header_file = local_file.replace('.json', ' headers.json')
        local_dir = os.path.dirname(local_file)

        if not os.path.exists(local_dir):
            os.makedirs(local_dir)

        with open(local_file, 'w+') as f:
            f.write(json.dumps(json.loads(content), indent=2))

        response_headers = {}
        for k, v in flow.response.headers.items():
            response_headers[k] = v
        with open(local_header_file, 'w+') as f:
            f.write(json.dumps(response_headers, indent=2))

        subprocess.run('emacsclient -n "' + local_file + '"', shell=True)
    else:
        ctx.log.alert('Configured base URL is not present: ' + map_local_base_url)


class CreateLocal:
    @command.command("l")
    def do(self, flows: typing.Sequence[flow.Flow]) -> None:
        for flow in flows:
            process_local_flow(flow)


addons = [
    # NopeOutRequests(),
    # WriteFlowsToFileSystem(),
    MapLocalRequests(),
    CreateLocal(),
    CurlAddon(),
    UrlAddon(),
    ShortUrlAddon(),
    RequestBodyAddon(),
    ResponseBodyAddon(),
    KeyBindingAddon(),
    QuitAddon(),
    InterceptAddon(),
    FlowResumeAddon(),
    AllResponseBodyAddon(),
    AllResponseWithoutBodyAddon(),
]
