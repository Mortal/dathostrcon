import argparse
import asyncio
import ctypes
import json
import traceback
import readline
from typing import Any

import aiohttp
import websockets

import valve_rcon


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
    rcon_password = server["cs2_settings"]["rcon"]
    host = server["ip"]
    port = server["ports"]["game"]
    rcon = valve_rcon.rcon_connect((host, port), rcon_password)
    console_auth = await get_console_auth(args)

    async with websockets.connect(f"wss://{host}/console-server/") as ws:
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

        loop = asyncio.get_running_loop()
        try:
            await loop.run_in_executor(None, valve_rcon.RCONShell(rcon).cmdloop)
        except KeyboardInterrupt:
            print("KeyboardInterrupt")
        except asyncio.CancelledError:
            print("Please use CTRL-D to exit instead of CTRL-C")
        print("Closing websocket connection...")
        await ws.close()
        # await print_incoming_task
        del print_incoming_task


def main() -> None:
    asyncio.run(main2(parser.parse_args()))


if __name__ == "__main__":
    main()
