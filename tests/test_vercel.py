from http.server import BaseHTTPRequestHandler
import tomllib
import importlib.util
import json
from pathlib import Path


def test_vercel_config_rewrites_to_python_function():
    config = json.loads(Path("vercel.json").read_text())

    assert config["rewrites"] == [{"source": "/(.*)", "destination": "/api/web"}]
    assert "functions" not in config


def test_vercel_handler_imports():
    spec = importlib.util.spec_from_file_location("vercel_web", Path("api/web.py"))
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    assert issubclass(module.handler, BaseHTTPRequestHandler)


def test_pyproject_declares_vercel_entrypoint():
    config = tomllib.loads(Path("pyproject.toml").read_text())

    assert config["tool"]["vercel"]["entrypoint"] == "api.web:handler"
