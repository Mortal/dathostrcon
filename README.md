valve_rcon
==========

This is a fork of
[python-valve](https://github.com/serverstf/python-valve)
to modernize the rcon client and add specific support for CS2 servers on dathost.


Usage
-----

You can use this in RCON-only mode, or Dathost console mode.

* RCON-only mode - works with any arbitrary CS2 server:

        python3 -m valve_rcon -p RCONPASSWORD SERVERADDR:SERVERPORT

* Dathost console mode (obtains rcon password and server ip through Dathost API):

        python3 dathostrcon.py -u USERNAME -p PASSWORD -s SERVERID


Python usage example
--------------------

In this example we connect to a Source server's remote console and issue
a simple ``echo`` command to it.


    import valve_rcon

    server_address = ("...", 27015)
    password = "top_secret"

    with valve_rcon.rcon_connect(server_address, password) as rcon:
        print(rcon("echo Hello, world!"))


Trademarks
----------

Valve, the Valve logo, Half-Life, the Half-Life logo, the Lambda logo,
Steam, the Steam logo, Team Fortress, the Team Fortress logo, Opposing
Force, Day of Defeat, the Day of Defeat logo, Counter-Strike, the
Counter-Strike logo, Source, the Source logo, Counter-Strike: Condition
Zero, Portal, the Portal logo, Dota, the Dota 2 logo, and Defense of the
Ancients are trademarks and/or registered trademarks of Valve
Corporation.

Any reference to these are purely for the purpose of identification.
Valve Corporation is not affiliated with Python-valve or any
Python-valve contributors in any way.
