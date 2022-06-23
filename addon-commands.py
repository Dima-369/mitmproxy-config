import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
from collections.abc import Sequence
from urllib.parse import unquote, urljoin, urlparse

import pyperclip
from mitmproxy import command
from mitmproxy import ctx
from mitmproxy import flow
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
        url = unquote(pyperclip.paste())
        pyperclip.copy(url)
        ctx.log.alert("Copied to clipboard: " + url)


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


class FlowResumeAddon:
    @command.command("r")
    def do(self) -> None:
        ctx.master.commands.execute("flow.resume @focus")


class InterceptAddon:
    @command.command("intercept.inner")
    def do(self, flows: Sequence[flow.Flow]) -> None:
        for f in flows:
            url = re.escape(f.request.url)
            ctx.master.commands.execute(
                f"console.command set intercept '~u {url} & ~s'")

    @command.command("cept")
    def do(self) -> None:
        ctx.master.commands.execute("intercept.inner @focus")


def get_url_without_parameters(url):
    path = urljoin(url, urlparse(url).path)
    # drop /v1/ for a cleaner file system
    path = path.replace("/index.php/v1/", "/index.php/")
    # strip trailing / to be able to create a file on file system
    if path.endswith('/'):
        return path[:-1]
    return path


def create_url_parameters_hash(url):
    query = urlparse(url).query
    if query:
        return ' ' + hashlib.sha256(query.encode('utf-8')).hexdigest()[0:12]
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

        if os.path.exists(local_file):
            with open(local_file) as f:
                data = json.loads(f.read())
                # flow.response = http.Response.make(data['statusCode'], data['response'], data['headers'])
                flow.response = http.Response.make(
                    data['statusCode'],
                    json.dumps(data['response'], indent=2),
                    data['headers'])


class CreateLocal:
    @command.command("local")
    def do(self, flows: Sequence[flow.Flow]) -> None:
        has_error = False
        single_flow = len(flows) == 1
        no_response_count = 0

        for flow in flows:
            if flow.response:
                url = flow.request.pretty_url
                if map_local_base_url in url:
                    content = flow.response.content

                    local_file = map_api_url_to_local_path(url)
                    local_dir = os.path.dirname(local_file)

                    if not os.path.exists(local_dir):
                        os.makedirs(local_dir)

                    response_headers = {}
                    for k, v in flow.response.headers.items():
                        response_headers[k] = v

                    data = {
                        'response': json.loads(content),
                        'url': flow.request.method + ' ' + flow.request.pretty_url,
                        'headers': response_headers,
                        'statusCode': flow.response.status_code,
                    }
                    with open(local_file, 'w+') as f:
                        f.write(json.dumps(data, indent=2))

                    if single_flow:
                        # focus Emacs, open the file without prompting for auto reverts and reload
                        # the buffer for potential new changes
                        subprocess.Popen(['emacsclient', '-e',
                                          """
                                          (run-at-time nil nil (lambda ()
                                            (x-focus-frame nil)
                                            (let (query-about-changed-file)
                                              (find-file "{0}")
                                              (revert-buffer-quick)
                                              (goto-char (point-min)))))
                                          """.replace('{0}', local_file)],
                                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
                else:
                    if single_flow:
                        has_error = True
                        ctx.log.alert('Configured base URL is not present: ' + map_local_base_url)
            else:
                no_response_count += 1

        if not has_error:
            if no_response_count == 0:
                ctx.log.alert('Saved ' + str(len(flows)) + ' flow(s) to ' + map_local_dir)
            else:
                ctx.log.alert('Saved ' + str(len(flows) - no_response_count) + ' flow(s) to ' + map_local_dir +
                              ' --- ' + str(no_response_count) + ' flow(s) without response')


class CreateAllLocalKey:
    @command.command("la")
    def do(self) -> None:
        ctx.master.commands.execute("local @all")


class CreateLocalKey:
    @command.command("l")
    def do(self) -> None:
        ctx.master.commands.execute("local @focus")


class DeleteLocalRequest:
    @command.command("localdelete")
    def do(self, flows: Sequence[flow.Flow]) -> None:
        for flow in flows:
            url = flow.request.pretty_url

            if map_local_base_url in url:
                local_file = map_api_url_to_local_path(url)

                try:
                    os.remove(local_file)
                    ctx.log.alert('Deleted ' + local_file)
                except FileNotFoundError:
                    ctx.log.alert('Local mapping files do not exist!')
            else:
                ctx.log.alert('Configured base URL is not present: ' + map_local_base_url)


class DeleteLocalRequestKey:
    @command.command("ld")
    def do(self) -> None:
        ctx.master.commands.execute("localdelete @focus")


class ClearMappedLocalRequests:
    @command.command("lc")
    def do(self) -> None:
        shutil.rmtree(map_local_dir)
        os.mkdir(map_local_dir)
        ctx.log.alert('Deleted everything under ' + map_local_dir)


addons = [
    MapLocalRequests(),
    CreateLocal(),
    DeleteLocalRequest(),
    DeleteLocalRequest(),
    ClearMappedLocalRequests(),

    CurlAddon(),
    UrlAddon(),
    ShortUrlAddon(),
    RequestBodyAddon(),
    ResponseBodyAddon(),
    KeyBindingAddon(),
    InterceptAddon(),
    FlowResumeAddon(),
    AllResponseBodyAddon(),
    AllResponseWithoutBodyAddon(),

    DeleteLocalRequestKey(),
    CreateLocalKey(),
    CreateAllLocalKey(),
]
