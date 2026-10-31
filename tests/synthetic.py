"""Synthetic repositories for the tests: small code bases with patterns that the inventory marks.

Each repository is generated from code in this file, so the tests hold no
real project and no real vulnerability report.
"""

from __future__ import annotations

from pathlib import Path

# A long comment block at the top of each source file: the first 40 lines of a
# file (the header of each unit slice) then hold no marked line, so that a
# lead belongs to the unit of its line whatever the order of the calls.
PREAMBLE_LINES = 45


def preamble(comment: str) -> str:
    return "".join(f"{comment} synthetic code for the tests, line {number}\n" for number in range(1, PREAMBLE_LINES + 1))


def _with_preamble(files: dict[str, str]) -> dict[str, str]:
    marks = {".py": "#", ".rb": "#", ".js": "//", ".go": "//", ".java": "//", ".c": "//", ".php": None}
    output = {}
    for name, text in files.items():
        suffix = Path(name).suffix
        if suffix in marks and marks[suffix] is not None and not name.startswith(("tests/", "docs/", "vendor/", ".")):
            text = preamble(marks[suffix]) + text
        elif suffix == ".php":
            text = text.replace("<?php\n", "<?php\n" + preamble("//"), 1)
        output[name] = text
    return output


WEBAPP: dict[str, str] = {
    "app.py": """import os
import pickle
import sqlite3
import subprocess

from flask import Flask, redirect, request

app = Flask(__name__)
DB = sqlite3.connect("app.db")


@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    os.system("ping -c 1 " + host)
    return "ok"


@app.route("/user")
def user():
    name = request.args.get("name", "")
    cursor = DB.cursor()
    cursor.execute("SELECT * FROM users WHERE name = '%s'" % name)
    return str(cursor.fetchall())


@app.route("/load", methods=["POST"])
def load():
    blob = request.get_data()
    state = pickle.loads(blob)
    return str(state)


@app.route("/go")
def go():
    target = request.args.get("next", "/")
    return redirect(target)


def safe_name(name):
    if not name.isalnum():
        raise ValueError(name)
    return name


@app.route("/archive")
def archive():
    name = safe_name(request.args.get("name", ""))
    subprocess.run(["tar", "czf", name + ".tgz", name], check=True)
    return "done"
""",
    "files.py": """import os

BASE = "/srv/files"


def read(name):
    with open(os.path.join(BASE, name)) as stream:
        return stream.read()


def write(name, data):
    path = os.path.join(BASE, name)
    with open(path, "w") as stream:
        stream.write(data)
""",
    "config_loader.py": """import yaml


def load_config(text):
    return yaml.load(text)


def load_safe(text):
    return yaml.safe_load(text)
""",
    "static/app.js": """const express = require("express");
const app = express();

app.get("/run", (req, res) => {
  const runner = require("child_process");
  runner.exec("ls " + req.query.dir, (err, out) => res.send(out));
});

app.get("/calc", (req, res) => {
  const value = eval(req.query.expr);
  res.send(String(value));
});

function render(target, html) {
  target.innerHTML = html;
}

module.exports = { app, render };
""",
    "tests/test_app.py": """import os


def test_ping():
    os.system("echo test")
""",
    "docs/README.md": "# Webapp\n\nRun `python app.py`.\n",
    "vendor/lib.js": "function helper(code) { return eval(code); }\nmodule.exports = helper;\n",
    ".github/workflows/ci.yml": "name: ci\non: [push]\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ${{ github.event.issue.title }}\n",
    ".git/HEAD": "ref: refs/heads/main\n",
    ".git/config": "[core]\n\tbare = false\n",
}

MIXED: dict[str, str] = {
    "cmd/server/main.go": """package main

import (
	"net/http"
	"os/exec"
)

func handler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	out, _ := exec.Command("sh", "-c", "echo "+name).Output()
	w.Write(out)
}

func main() {
	http.HandleFunc("/echo", handler)
	http.ListenAndServe(":8080", nil)
}
""",
    "src/main/java/app/UserController.java": """package app;

import java.sql.Connection;
import java.sql.Statement;

public class UserController {
    private Connection connection;

    public String find(String name) throws Exception {
        Statement statement = connection.createStatement();
        statement.execute("SELECT * FROM users WHERE name = '" + name + "'");
        return "ok";
    }

    public void run(String command) throws Exception {
        Runtime.getRuntime().exec(command);
    }
}
""",
    "web/index.php": """<?php
$file = $_GET["file"];
include($file);

function show($name) {
    echo "<p>" . $name . "</p>";
}

system("ls " . $_GET["dir"]);
?>
""",
    "lib/report.rb": """class Report
  def generate(name)
    system("generate-report #{name}")
  end

  def load(data)
    Marshal.load(data)
  end
end
""",
    "native/parse.c": """#include <stdio.h>
#include <string.h>

void copy_name(const char *input) {
    char buffer[16];
    strcpy(buffer, input);
    printf(buffer);
}

int main(int argc, char **argv) {
    if (argc > 1) {
        copy_name(argv[1]);
    }
    return 0;
}
""",
    ".hg/store/data": "x\n",
}


def many_modules(count: int) -> dict[str, str]:
    """``count`` small Python modules, each with a few units that the inventory marks."""
    files: dict[str, str] = {}
    for index in range(count):
        files[f"pkg/module_{index:03d}.py"] = (
            preamble("#")
            + f"""import os
import subprocess


def run_{index}(command):
    os.system("tool-{index} " + command)
    return 0


def query_{index}(cursor, name):
    cursor.execute("SELECT * FROM t{index} WHERE n = '%s'" % name)
    return cursor.fetchall()


def calc_{index}(expression):
    return eval(expression)
"""
        )
    return files


def counted_files(count: int) -> dict[str, str]:
    """A tree with ``count`` counted files and files in version-control folders that do not count."""
    files = {f"src/file_{index:04d}.txt": f"line {index}\n" for index in range(count)}
    files[".git/HEAD"] = "ref: refs/heads/main\n"
    for name in (".git/objects/aa/bb", ".hg/store/data", ".svn/entries", "nested/.git/config", "nested/deep/.svn/wc.db"):
        files[name] = "x\n"
    return files


WEBAPP = _with_preamble(WEBAPP)
MIXED = _with_preamble(MIXED)


def line_of(files: dict[str, str], path: str, text: str) -> int:
    """The line number of the first line of ``path`` that holds ``text``."""
    for number, line in enumerate(files[path].split("\n"), 1):
        if text in line:
            return number
    raise ValueError(f"{text!r} is not in {path}")


def write_repository(folder: Path, files: dict[str, str]) -> Path:
    folder.mkdir(parents=True, exist_ok=True)
    for name, text in files.items():
        path = folder / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    return folder
