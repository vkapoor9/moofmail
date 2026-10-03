"""Phone and voice access: serve the remote connector from your own machine.

`moofmail-phone setup` builds a Cloudflare Tunnel and an Access application in
YOUR Cloudflare account, starts two background services, and refuses to hand out
the connector URL until a self-test gate passes. See setup.py for the design.
"""
