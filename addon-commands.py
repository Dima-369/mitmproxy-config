import json
import re
import shlex
import typing
from urllib.parse import unquote

import pyperclip
from mitmproxy import command
from mitmproxy import ctx
from mitmproxy import flow


def get_status_code():
    """
    :return: the response status code as a string
    """
    ctx.master.commands.execute("cut.clip @focus response.status_code")
    return pyperclip.paste()


def get_response_content_in_blocks():
    ctx.master.commands.execute("cut.clip @focus response.content")
    raw = pyperclip.paste()
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
        """Copy the method plus the URL with the base cut off.

        Example: GET printouts/printhours.pdf?personalNo=365
        """
        ctx.master.commands.execute("cut.clip @focus request.url")
        raw_url = unquote(pyperclip.paste())

        last = "/index.php/"
        url = raw_url[raw_url.index(last) + len(last):]

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
        pyperclip.copy("```bash\n" + curl + "\n```\n\n" +
                       "Took " + "{:.2f}".format(time) + "s with " +
                       "status code " + code + " to return:\n\n" +
                       response)
        ctx.log.alert("Copied cURL, response body and status code to clipboard")


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

    @command.command("t")
    def do(self) -> None:
        ctx.master.commands.execute("intercept.inner @focus")


addons = [
    CurlAddon(),
    UrlAddon(),
    ShortUrlAddon(),
    RequestBodyAddon(),
    ResponseBodyAddon(),
    KeyBindingAddon(),
    QuitAddon(),
    InterceptAddon(),
    FlowResumeAddon(),
    AllResponseBodyAddon()
]
