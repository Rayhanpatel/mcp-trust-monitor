# Independent installed consumer

`external_stdio_server.py` is an independently configured synthetic MCP server.
It imports only the MCP SDK and standard library. It accepts its own definition,
server name and received-call log paths; it has no dependency on repository demos.

From the root of a source checkout or extracted source distribution, after
building or downloading the reviewed wheel:

```sh
mtm_example_dir=$(mktemp -d)
cp examples/installed_consumer.py examples/external_stdio_server.py "$mtm_example_dir/"
python3 -m venv "$mtm_example_dir/venv"
"$mtm_example_dir/venv/bin/python" -m pip install ./dist/mcp_trust_monitor-0.2.0a2-py3-none-any.whl
(cd "$mtm_example_dir" && ./venv/bin/python installed_consumer.py)
```

Replace `./dist/...whl` with the location of your downloaded wheel if needed.
Do not use an editable install or set `PYTHONPATH`. The example creates a custom
policy, a non-demo server ID and a temporary state directory. It proves explicit
approval, protected discovery, a successful call, metadata-change invalidation
and a refused call whose independent server-side count stays unchanged. Expected
output includes `"installed_consumer": "passed"` and equal before/after counts of
`1` for the blocked call. No cloud service is used.

The example tests metadata-change enforcement, not malicious-code detection or
process sandboxing. The sample server is deliberately instrumented and synthetic.
It does not prove that arbitrary servers provide reliable received-call evidence.

# Offline learning-loop walkthrough

`learning_loop_offline.py` runs the human-reviewed memory loop described in
[docs/SENSO_LEARNING_LOOP.md](../docs/SENSO_LEARNING_LOOP.md) from a source checkout:
`uv sync --locked`, then `uv run python examples/learning_loop_offline.py`. It uses
the real library and real stdio servers (`external_stdio_server.py`). Three labelled
local stand-ins replace Senso lesson storage, Senso policy search and the model, so
its output shows the library's local checks, not Senso or model behavior. No
credential or network service is used.
