from mitmproxy import command
from mitmproxy import ctx
from mitmproxy import flow
from urllib.parse import unquote

import pyperclip
import typing
import re


def format_json_human():
    raw = pyperclip.paste()
    pyperclip.copy(json.dump(json.load(raw), indent=2))


class CurlAddon:
    @command.command("cu")
    def do(self) -> None:
        ctx.master.commands.execute("export.clip curl @focus")
        pyperclip.copy("```bash\n" + pyperclip.paste() + "\n```")
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
        ctx.master.commands.execute("cut.clip @focus request.content")
        format_json_human()
        ctx.log.alert("Copied request body to clipboard")


class ResponseBodyAddon:
    @command.command("bs")
    def do(self) -> None:
        ctx.master.commands.execute("cut.clip @focus response.content")
        format_json_human()
        ctx.log.alert("Copied response body to clipboard")


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
    ResponseBodyAddon(),
    KeyBindingAddon(),
    QuitAddon(),
    InterceptAddon(),
    FlowResumeAddon(),
]
