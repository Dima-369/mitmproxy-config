import hashlib
import json
import os
import pathlib
import urllib.parse
import re
import shlex
import shutil
import subprocess
from collections.abc import Sequence
from urllib.parse import unquote, urljoin, urlparse, parse_qs

import pyperclip
from mitmproxy import command
from mitmproxy import ctx
from mitmproxy import http
from mitmproxy.flow import Flow

with open(os.path.join(
        pathlib.Path(__file__).parent.absolute(), "config.json")) as f:
    json_config = json.load(f)

map_local_base_urls = json_config['mapLocalBaseUrls']
map_local_dir = json_config['mapLocalDir']


def is_url_in_map_local_base_urls(url):
    for base_url in map_local_base_urls:
        if base_url in url:
            return True
    return False


def get_after_base_url_from_local_base(without_parameters_url):
    for base_url in map_local_base_urls:
        if base_url in without_parameters_url:
            return without_parameters_url.replace(base_url, '')
    return without_parameters_url


def get_status_code():
    """
    :return: the response status code as a string
    """
    ctx.master.commands.execute("cut.clip @focus response.status_code")
    return pyperclip.paste()


def trim_response_content(s):
    """
    :return: a string
    """
    if isinstance(s, bytes):
        s = s.decode('utf-8')
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
    markdown_table = ""

    for s in parts[1:]:
        parsed_url = urlparse(s)
        if parsed_url.scheme and parsed_url.netloc:
            # unquote since the export.clip command returns a string like this:
            # ?alias=projectStatus%3Astatus
            s = unquote(s)

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
            # pass -g for the unescaped URL so the curl can be executed in the
            # terminal
            output += "   -g \\\n"

            # pretty much always, this is the URL at the very end of the command
            output += "   '" + s + "' \\\n"

            query_params = parse_qs(urlparse(s).query)
            if len(query_params) >= 1:
                url = strip_base_url_prefix(s)
                if '?' in url:
                    url = url[:url.index('?')]

                ctx.master.commands.execute("cut.clip @focus request.method")
                method = pyperclip.paste()
                full = method + " " + url

                param_list = [{"Parameter": key, "Value": value[0]} for key, value in query_params.items()]
                markdown_table = "\n<details>\n<summary>" + full + "</summary>\n\n"
                for param in param_list:
                    markdown_table += f"`{param['Parameter']}`\n{param['Value']}\n\n"
                markdown_table += '</details>'

            next_cmd = False

    output = output.strip()
    if output.endswith("\\"):
        output = output[:-1]

    return "```bash\n" + output + "\n```\n" + markdown_table


class CurlAddon:

    @command.command("cu")
    def do(self) -> None:
        pyperclip.copy(get_curl_formatted())
        ctx.log.alert("Copied cURL with ```bash to clipboard")


class UrlAddon:

    @command.command("u")
    def do(self) -> None:
        ctx.master.commands.execute("cut.clip @focus request.url")
        url = unquote(pyperclip.paste())
        pyperclip.copy(url)
        ctx.log.alert("Copied to clipboard: " + url)


class ShortUrlMarkdownAddon:

    @command.command("ur")
    def do(self) -> None:
        """Copy the method plus the URL with the base and the params cut off
        with surrounding Markdown code blocks.
      
        Example: `GET printouts/printhours.pdf`
        """
        ctx.master.commands.execute("cut.clip @focus request.url")
        url = strip_base_url_prefix(unquote(pyperclip.paste()))

        ctx.master.commands.execute("cut.clip @focus request.method")
        method = pyperclip.paste()
        full = "`" + method + " " + url + "`"
        pyperclip.copy(full)

        ctx.log.alert("Copied to clipboard: " + full)


class ShortUrlAddon:

    @command.command("url")
    def do(self) -> None:
        """Copy the method plus the URL with the base and the params cut off.

        Example: GET printouts/printhours.pdf
        """
        ctx.master.commands.execute("cut.clip @focus request.url")
        raw_url = unquote(pyperclip.paste())
        url = strip_base_url_prefix(raw_url)
        if raw_url != url:
            if "?" in url:
                url = url[:url.index("?")]

        ctx.master.commands.execute("cut.clip @focus request.method")
        method = pyperclip.paste()
        pyperclip.copy(method + " " + url)

        ctx.log.alert("Copied to clipboard: " + method + " " + url)


class AllResponseBodyAddon:

    @command.command("copyall")
    def do(self, flows: Sequence[Flow]) -> None:
        if len(flows) != 1:
            ctx.log.alert("This can only operate on a single flow!")
        else:
            flow = flows[0]
            curl = get_curl_formatted()
            code = get_status_code()
            time = get_time_from_timestamps()
            response = flow.response.content

            if len(response) == 0:
                pyperclip.copy(curl + "\nTook " +
                               "{:.2f}".format(time) + "s with " +
                               "status code " + code +
                               " with no response body.")
                ctx.log.alert("Copied cURL and status code to clipboard. " +
                              "There was no response body!")
            else:
                # noinspection PyBroadException
                try:
                    as_json = "```json\n" + trim_response_content(
                        json.dumps(json.loads(response), indent=2)) + \
                              "\n```"
                except Exception:
                    as_json = "```\n" + \
                              trim_response_content(response) + \
                              "```"
                pyperclip.copy(curl + "\n" + "Took " +
                               "{:.2f}".format(time) + "s with " +
                               "status code " + code + " to return:\n\n" +
                               as_json)
                ctx.log.alert(
                    "Copied cURL, response body and status code to clipboard")


class AllResponseBodyKey:

    @command.command("a")
    def do(self) -> None:
        ctx.master.commands.execute("copyall @focus")


class AllResponseWithoutBodyAddon:

    @command.command("ab")
    def do(self) -> None:
        curl = get_curl_formatted()
        code = get_status_code()
        time = get_time_from_timestamps()
        pyperclip.copy(curl + "\nTook " +
                       "{:.2f}".format(time) + "s with " + "status code " +
                       code + ".")
        ctx.log.alert("Copied cURL  and status code to clipboard")


# if is_request is false, it is assumed that this is a request
def copy_content_as_json(content, is_request):
    if content == b'':
        ctx.log.alert("The flow does not have a request body!")
    else:
        # noinspection PyBroadException
        try:
            as_json = json.dumps(json.loads(content), indent=2)
            pyperclip.copy(as_json)
            if is_request:
                ctx.log.alert("Copied JSON request body to clipboard")
            else:
                ctx.log.alert("Copied JSON request body to clipboard")
        except Exception:
            pyperclip.copy(content.decode('utf-8'))
            if is_request:
                ctx.log.alert("Copied non-JSON request body to clipboard")
            else:
                ctx.log.alert("Copied non-JSON response body to clipboard")


class RequestBodyAddon:

    @command.command("copyrequest")
    def do(self, flows: Sequence[Flow]) -> None:
        if len(flows) != 1:
            ctx.log.alert("This can only operate on a single flow!")
        else:
            flow = flows[0]
            content = flow.request.content
            copy_content_as_json(content, is_request=True)


class RequestBodyKey:

    @command.command("req")
    def do(self) -> None:
        ctx.master.commands.execute("copyrequest @focus")


class ResponseBodyAddon:

    @command.command("copyresponse")
    def do(self, flows: Sequence[Flow]) -> None:
        if len(flows) != 1:
            ctx.log.alert("This can only operate on a single flow!")
        else:
            flow = flows[0]
            content = flow.response.content
            copy_content_as_json(content, is_request=False)


class ResponseBodyKey:

    @command.command("resp")
    def do(self) -> None:
        ctx.master.commands.execute("copyresponse @focus")


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
    def do(self, flows: Sequence[Flow]) -> None:
        for f in flows:
            url = re.escape(f.request.url)
            ctx.master.commands.execute(
                f"console.command set intercept '~u {url} & ~s'")


class InterceptKey:

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


def append_to_debug(data):
    home_dir = os.path.expanduser("~")
    debug_file = os.path.join(home_dir, "debug.py")
    with open(debug_file, "a") as df:
        df.write(data + '\n')


# noinspection PyShadowingNames
def map_flow_to_local_path(flow):
    url = flow.request.pretty_url

    if 'stripUrlParts' in json_config:
        query_params = parse_qs(urlparse(url).query)
        for key in json_config['stripUrlParts']:
            query_params.pop(key, None)

        new_query_string = "&".join(f"{key}={value[0]}" for key, value in query_params.items())
        # noinspection PyProtectedMember
        url = urlparse(url)._replace(query=new_query_string).geturl()

    without_parameters = get_url_without_parameters(url)
    after_base = get_after_base_url_from_local_base(without_parameters)
    base_name = os.path.basename(after_base)
    return os.path.join(map_local_dir, os.path.dirname(after_base),
                        flow.request.method + ' ' +
                        base_name) + create_url_parameters_hash(url) + ".json"


class MapLocalRequests:
    """ Map to local response bodies from a directory. """

    @staticmethod
    def request(flow: http.HTTPFlow) -> None:
        local_file = map_flow_to_local_path(flow)

        if os.path.exists(local_file):
            with open(local_file) as f:
                data = json.loads(f.read())
                flow.response = http.Response.make(
                    data['statusCode'], json.dumps(data['response'], indent=2),
                    data['headers'])


def format_any_content(content):
    if content == 'b':
        return None
    try:
        return json.loads(content)
    except (json.JSONDecodeError, UnicodeDecodeError):
        try:
            return content.decode('utf-8')
        except UnicodeDecodeError:
            # note that this is the case for POST files
            return "unmappable content for JSON"


def strip_base_url_prefix(url):
    for base_url in map_local_base_urls:
        if url.startswith(base_url):
            return url[len(base_url):]
    return url


def check_if_flow_ignored(flow):
    if 'ignoreForLocalMapping' in json_config:
        url = strip_base_url_prefix(flow.request.pretty_url)
        for ignore in json_config['ignoreForLocalMapping']:
            parts = ignore.split(" ")
            if parts[0] == flow.request.method and parts[1] == url:
                return True
    return False


class CreateLocal:

    @command.command("local")
    def do(self, flows: Sequence[Flow]) -> None:
        has_error = False
        single_flow = len(flows) == 1
        no_response_count = 0
        unmappable_response_count = 0

        for flow in flows:
            if flow.response:
                url = flow.request.pretty_url
                if is_url_in_map_local_base_urls(url):
                    if check_if_flow_ignored(flow):
                        continue

                    local_file = map_flow_to_local_path(flow)
                    local_dir = os.path.dirname(local_file)

                    if not os.path.exists(local_dir):
                        os.makedirs(local_dir)

                    response_headers = {}
                    for k, v in flow.response.headers.items():
                        response_headers[k] = v

                    request_content = format_any_content(flow.request.content)
                    resp = format_any_content(flow.response.content)

                    if request_content == "unmappable content for JSON" or \
                            resp == "unmappable content for JSON":
                        unmappable_response_count += 1
                        continue

                    req = flow.request
                    data = {
                        'response': resp,
                        'headers': response_headers,
                        'statusCode': flow.response.status_code,
                        'url': req.method + ' ' + req.pretty_url,
                        'requestBody': request_content,
                    }

                    json_string = json.dumps(data, indent=2)

                    if single_flow:
                        if 'startCommandOnLocalMap' in json_config and \
                                len(json_config['startCommandOnLocalMap']) >= 1:

                            with open(local_file, 'w+') as f1:
                                f1.write(json_string)

                            command = json_config['startCommandOnLocalMap']
                            cmd = map(lambda x: x.replace('###', local_file), command)
                            subprocess.Popen(cmd,
                                             stdout=subprocess.PIPE,
                                             stderr=subprocess.PIPE,
                                             stdin=subprocess.PIPE)
                        else:
                            c = ctx.master.spawn_editor(json_string)
                            with open(local_file, 'w+') as f2:
                                f2.write(c)
                    else:
                        with open(local_file, 'w+') as f3:
                            f3.write(json_string)

                else:
                    if single_flow:
                        has_error = True
                        ctx.log.alert(
                            'Configured base URLs are not present: ' +
                            str(map_local_base_urls))
            else:
                no_response_count += 1

        if not has_error:
            if no_response_count == 0 and unmappable_response_count == 0:
                ctx.log.alert('Saved ' + str(len(flows)) + ' flow(s) to ' +
                              map_local_dir)
            else:
                ctx.log.alert('Saved ' + str(
                    len(flows) - no_response_count -
                    unmappable_response_count) + ' flow(s) to ' +
                              map_local_dir + ' --- ' +
                              str(no_response_count) +
                              ' flow(s) without response --- ' +
                              str(unmappable_response_count) +
                              ' flow(s) unmappable to JSON')


class CreateAllLocalKey:

    @command.command("la")
    def do(self) -> None:
        ctx.master.commands.execute("local @shown")


class CreateLocalKey:

    @command.command("l")
    def do(self) -> None:
        ctx.master.commands.execute("local @focus")


class DeleteLocalRequest:

    @command.command("localdelete")
    def do(self, flows: Sequence[Flow]) -> None:
        for flow in flows:
            url = flow.request.pretty_url

            if is_url_in_map_local_base_urls(url):
                local_file = map_flow_to_local_path(flow)

                try:
                    os.remove(local_file)
                    ctx.log.alert('Deleted ' + local_file)
                except FileNotFoundError:
                    ctx.log.alert('Local mapping files do not exist!')
            else:
                ctx.log.alert('Configured base URLs are not present: ' +
                              str(map_local_base_urls))


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


class SetupViewFilterKey:

    @command.command("f")
    def do(self) -> None:
        ctx.master.commands.execute("console.command set view_filter")


addons = [
    MapLocalRequests(),
    CreateLocal(),
    DeleteLocalRequest(),
    DeleteLocalRequest(),
    ClearMappedLocalRequests(),
    # other functionality
    CurlAddon(),
    UrlAddon(),
    ShortUrlAddon(),
    ShortUrlMarkdownAddon(),
    RequestBodyAddon(),
    ResponseBodyAddon(),
    KeyBindingAddon(),
    InterceptAddon(),
    FlowResumeAddon(),
    AllResponseBodyAddon(),
    AllResponseWithoutBodyAddon(),
    # keys
    SetupViewFilterKey(),
    DeleteLocalRequestKey(),
    CreateLocalKey(),
    CreateAllLocalKey(),
    ResponseBodyKey(),
    RequestBodyKey(),
    AllResponseBodyKey(),
    InterceptKey(),
]
