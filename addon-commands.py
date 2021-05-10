import json
import re
import shlex
import typing
from urllib.parse import unquote

import pyperclip
from mitmproxy import command
from mitmproxy import ctx
from mitmproxy import flow


def format_json_human():
    raw = pyperclip.paste()
    pyperclip.copy(json.dumps(json.loads(raw), indent=2))


def copy_response_body():
    ctx.master.commands.execute("cut.clip @focus response.content")
    try:
        format_json_human()
        ctx.log.alert("Copied JSON response body to clipboard")
    except Exception:
        ctx.master.commands.execute("cut.clip @focus response.content")
        ctx.log.alert("Copied non-JSON response body to clipboard")


def get_time_from_timestamps():
    ctx.master.commands.execute(
        "cut.clip @focus request.timestamp_start")
    start = pyperclip.paste()
    ctx.master.commands.execute(
        "cut.clip @focus response.timestamp_end")
    end = pyperclip.paste()
    return float(end) - float(start)


def beautify_curl(s):
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
        ctx.master.commands.execute("export.clip curl @focus")
        pyperclip.copy("```bash\n" + beautify_curl(pyperclip.paste()) +
                       "\n```")
        ctx.log.alert("Copied cURL with ```bash to clipboard")


class UrlAddon:
    @command.command("u")
    def do(self) -> None:
        ctx.master.commands.execute("cut.clip @focus request.url")
        pyperclip.copy(unquote(pyperclip.paste()))
        ctx.log.alert("Copied URL to clipboard")


# request.text or request.raw_content also seem to work
class RequestBodyAddon:
    @command.command("bq")
    def do(self) -> None:
        try:
            ctx.master.commands.execute("cut.clip @focus request.content")
            format_json_human()
            ctx.log.alert("Copied request body to clipboard")
        except Exception:
            ctx.master.commands.execute("cut.clip @focus request.content")
            ctx.log.alert("Copied nonJSON request body to clipboard")


class FullResponseBodyAddon:
    @command.command("a")
    def do(self) -> None:
        ctx.master.commands.execute("cut.clip @focus request.url")
        url = pyperclip.paste()

        try:
            ctx.master.commands.execute("cut.clip @focus response.content")
            format_json_human()

            # trimmed to not copy huge responses
            response = pyperclip.paste()
            if len(response) >= 2100:
                response = response[:2100] + "..."

            time = get_time_from_timestamps()
            pyperclip.copy(url + " took " + "{:.2f}".format(time) +
                           "s to return:\n\n```json\n" + response + "\n```")
            ctx.log.alert(
                "Copied URL, response time and body in ```json to clipboard")
        except Exception:
            ctx.master.commands.execute("cut.clip @focus response.content")

            # trimmed to not copy huge responses
            response = pyperclip.paste()
            if len(response) >= 2100:
                response = response[:2100] + "..."

            time = get_time_from_timestamps()
            pyperclip.copy(url + " took " + "{:.2f}".format(time) +
                           "s to return:\n\n```\n" + response + "\n```")
            ctx.log.alert(
                "Copied URL, response time and "
                "non-JSON body in ``` to clipboard")


class ResponseBodyAddon:
    @command.command("bs")
    def do(self) -> None:
        copy_response_body()


# alias
class ResponseBodyAddon2:
    @command.command("resp")
    def do(self) -> None:
        copy_response_body()


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


# todo try out https://docs.mitmproxy.org/stable/overview-features/#map-local


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
    RequestBodyAddon(),
    ResponseBodyAddon2(),
    ResponseBodyAddon(),
    KeyBindingAddon(),
    QuitAddon(),
    InterceptAddon(),
    FlowResumeAddon(),
    FullResponseBodyAddon(),
]
