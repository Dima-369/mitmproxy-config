from mitmproxy import command
from mitmproxy import ctx
from mitmproxy import flow

import typing
import subprocess
import re


def format_json_human():
    subprocess.getoutput(
        "pbpaste | python -c 'import json, sys ; json.dump(json.load(sys.stdin), sys.stdout, indent=2)' | pbcopy")


class CurlAddon:
    @command.command("cu")
    def do(self) -> None:
        ctx.master.commands.execute("export.clip curl @focus")
        ctx.log.alert("Copied cURL to clipboard")


class UrlAddon:
    @command.command("u")
    def do(self) -> None:
        ctx.master.commands.execute("cut.clip @focus request.url")
        # stripping the newline inside python does not work, but tr -d does
        subprocess.getoutput(
            "pbpaste | python3 -c 'import sys; from urllib.parse import unquote; print(unquote(sys.stdin.read()));' | tr -d '\n' | pbcopy")
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
]
