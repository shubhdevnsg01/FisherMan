from http.server import BaseHTTPRequestHandler
import importlib.util
import json
from pathlib import Path


def test_vercel_config_rewrites_to_python_function():
    config = json.loads(Path("vercel.json").read_text())

    assert config["rewrites"] == [{"source": "/(.*)", "destination": "/api/web"}]
    assert "api/web.py" in config["functions"]


def test_vercel_handler_imports():
    spec = importlib.util.spec_from_file_location("vercel_web", Path("api/web.py"))
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    assert issubclass(module.handler, BaseHTTPRequestHandler)
