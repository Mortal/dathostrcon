import argparse
import asyncio
import ctypes
import json
import traceback
import readline
from typing import Any

import aiohttp
import websockets


libreadline = ctypes.CDLL("libreadline.so")

parser = argparse.ArgumentParser()
parser.add_argument("--username", "-u", required=True)
parser.add_argument("--password", "-p", required=True)
parser.add_argument("--server", "-s", required=True)


async def get_console_auth(args) -> str:
    url = f"https://dathost.net/api/0.1/game-servers/{args.server}/console-auth"
    auth = aiohttp.BasicAuth(args.username, args.password)

    async with aiohttp.ClientSession(auth=auth) as session:
        async with session.get(url) as response:
            response.raise_for_status()
            return await response.text()


async def get_game_servers(args) -> list[Any]:
    url = "https://dathost.net/api/0.1/game-servers"
    auth = aiohttp.BasicAuth(args.username, args.password)

    async with aiohttp.ClientSession(auth=auth) as session:
        async with session.get(url) as response:
            response.raise_for_status()
            return await response.json()


async def main2(args):
    servers = await get_game_servers(args)
    server, = [s for s in servers if s["id"] == args.server]
    console_auth = await get_console_auth(args)

    async with websockets.connect(f"wss://{server['ip']}/console-server/") as ws:
        command = {"cmd": "auth", "args": {"token": console_auth}}
        await ws.send(json.dumps(command))
        response = json.loads(await ws.recv())
        print(response["cmd"])
        if response["cmd"] != "data":
            raise Exception(response)
        data = response["args"]["data"]
        print("\n".join(data.splitlines()[-1000:]))

        async def print_incoming() -> None:
            try:
                while True:
                    try:
                        r = json.loads(await ws.recv())
                    except websockets.ConnectionClosed:
                        return
                    if r["cmd"] == "data":
                        data = r["args"]["data"].replace("\r", "").strip("\n")
                        if data:
                            print(f"\r\x1b[K{data}\n", end="", flush=True)
                            libreadline.rl_on_new_line()
                            readline.redisplay()
            except Exception:
                traceback.print_exc()

        print_incoming_task = asyncio.create_task(print_incoming())
        commands = [
            "mp_warmup_end",
            "changelevel",
            "mp_freezetime",
        ]
        maps = [
            "changelevel de_mirage",
            "changelevel de_inferno",
            "changelevel cs_italy",
        ]

        def completer(text: str, state: int) -> str | None:
            matches = [m for m in commands if m.startswith(text)]
            if not matches:
                if text.split()[0] == "changelevel":
                    matches = [m for m in maps if m.startswith(text)]
            if state < len(matches):
                return matches[state]
            return None

        readline.parse_and_bind("tab: complete")
        readline.set_completer_delims("")
        readline.set_completer(completer)

        loop = asyncio.get_running_loop()
        while True:
            try:
                line = await loop.run_in_executor(None, input)
            except KeyboardInterrupt:
                print("KeyboardInterrupt")
                break
            except asyncio.CancelledError:
                print("Please use CTRL-D to exit instead of CTRL-C")
                break
            except EOFError:
                break
            if line.strip() == "exit":
                break
            if not line.strip():
                print("", flush=True)
                continue
            await ws.send(json.dumps({"cmd": "sendLine", "args": {"data": line}}))
        print("Closing websocket connection...")
        await ws.close()
        # await print_incoming_task
        del print_incoming_task


def main() -> None:
    asyncio.run(main2(parser.parse_args()))


if __name__ == "__main__":
    main()
