"""Phase 0 of the funnel: a deterministic inventory and a ranked queue of code units.

The module reads the repository and gives one JSON document. It uses
ripgrep (``rg``) when it is on PATH and a slower Python scanner when it is
not. It uses the Python standard library only, and it makes no model call.

Steps:

1. census: each file, its language, its path tags, and the skip counts;
2. scan: sink, source, route, guard and name patterns for each language
   family (one ``rg`` call for each family and batch of files);
3. units: the enclosing function of each signal (``ast`` for Python, brace,
   indent and clause rules for the other languages, a window as fallback),
   route records and handler links;
4. score: a deterministic score for each unit, then a rank with a file
   diversity factor.

Interface::

    build_inventory(repo_root, *, deadline_seconds=1500.0, max_units=5000,
                    log=None) -> dict
    python -m sentrytower.funnel.inventory --repo PATH --out PATH
                    [--deadline-seconds N] [--max-units N]

Paths in the result are relative to the repository root with "/" separators.
Line numbers are 1-based and inclusive.
"""

from __future__ import annotations

import argparse
import ast
import bisect
import heapq
import json
import math
import os
import re
import signal
import subprocess
import sys
import tempfile
import threading
import time
import warnings
from collections import Counter, defaultdict

VERSION = "funnel-inventory-v1"
SCORE_VERSION = "score-v2"

MAX_SCAN_BYTES = 4 * 1024 * 1024      # files above this size get no scan
MAX_LINES_PER_FILE = 4000             # rg --max-count: matching lines for each file
MAX_SIGNALS_TOTAL = 4_000_000         # stop the scan above this count (partial)
MAX_FILES_OUT = 20_000
MAX_ROUTES_OUT = 20_000
MAX_SIGNALS_PER_UNIT_OUT = 24
MAX_FUNCTION_LINES = 600              # a longer function becomes windows around its signals
WINDOW_PAD = 15
WINDOW_MAX = 120
WINDOW_GAP = 30
SMALL_CLOSURE_LINES = 15
FILE_DECAY = 0.8                      # rank factor for the k-th unit of one file
TEXT_MAX = 160
ARG_BYTES_PER_BATCH = 600_000

EXTENSIONS = {
    ".py": "python", ".pyw": "python", ".pyi": "python",
    ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript", ".jsx": "javascript",
    ".ts": "typescript", ".tsx": "typescript", ".mts": "typescript", ".cts": "typescript",
    ".vue": "vue", ".svelte": "svelte", ".astro": "javascript",
    ".php": "php", ".phtml": "php", ".php3": "php", ".php4": "php", ".php5": "php", ".php7": "php",
    ".phps": "php", ".inc": "php?", ".module": "php?",
    ".go": "go",
    ".java": "java", ".kt": "kotlin", ".kts": "kotlin", ".scala": "scala", ".sc": "scala",
    ".groovy": "groovy", ".gvy": "groovy", ".jsp": "jsp", ".jspx": "jsp", ".jspf": "jsp",
    ".c": "c", ".h": "c?", ".cc": "cpp", ".cpp": "cpp", ".cxx": "cpp", ".c++": "cpp", ".hh": "cpp",
    ".hpp": "cpp", ".hxx": "cpp", ".h++": "cpp", ".ipp": "cpp", ".inl": "cpp", ".tcc": "cpp",
    ".cu": "cpp", ".cuh": "cpp", ".m": "objc", ".mm": "objc",
    ".cs": "csharp", ".cshtml": "razor", ".razor": "razor",
    ".rb": "ruby", ".rake": "ruby", ".gemspec": "ruby", ".ru": "ruby", ".erb": "erb", ".haml": "haml",
    ".slim": "slim",
    ".rs": "rust",
    ".ex": "elixir", ".exs": "elixir", ".heex": "heex", ".eex": "heex", ".leex": "heex",
    ".erl": "erlang", ".hrl": "erlang", ".escript": "erlang",
    ".clj": "clojure", ".cljs": "clojure", ".cljc": "clojure",
    ".pl": "perl", ".pm": "perl", ".t": "perl", ".cgi": "perl", ".psgi": "perl",
    ".swift": "swift", ".lua": "lua", ".dart": "dart",
    ".sh": "shell", ".bash": "shell", ".zsh": "shell", ".ksh": "shell",
    ".html": "html", ".htm": "html", ".xhtml": "html", ".ejs": "template", ".hbs": "template",
    ".handlebars": "template", ".mustache": "template", ".twig": "template", ".jinja": "template",
    ".jinja2": "template", ".j2": "template", ".njk": "template", ".liquid": "template",
    ".tpl": "template", ".vm": "template", ".ftl": "template", ".pug": "template", ".jade": "template",
    ".yaml": "yaml", ".yml": "yaml", ".json": "json", ".toml": "toml", ".xml": "xml", ".ini": "ini",
    ".cfg": "ini", ".conf": "conf", ".properties": "properties", ".sql": "sql",
    ".md": "markdown", ".markdown": "markdown", ".rst": "rst", ".txt": "text", ".adoc": "asciidoc",
    ".proto": "proto", ".graphql": "graphql", ".gql": "graphql", ".tf": "terraform",
    ".r": "r", ".jl": "julia", ".hs": "haskell", ".ml": "ocaml", ".fs": "fsharp", ".zig": "zig",
    ".nim": "nim", ".cr": "crystal", ".ps1": "powershell", ".vb": "vbnet", ".asm": "asm", ".s": "asm",
    ".css": "css", ".scss": "css", ".less": "css", ".svg": "svg", ".csv": "data", ".tsv": "data",
    ".lock": "lock", ".map": "sourcemap",
}
SPECIAL_NAMES = {
    "dockerfile": "dockerfile", "makefile": "make", "gnumakefile": "make", "rakefile": "ruby",
    "gemfile": "ruby", "jenkinsfile": "groovy", "vagrantfile": "ruby", "guardfile": "ruby",
    "podfile": "ruby", "brewfile": "ruby", "build": "starlark", "workspace": "starlark",
}
SHEBANGS = (
    ("python", "python"), ("node", "javascript"), ("deno", "typescript"), ("ruby", "ruby"),
    ("perl", "perl"), ("php", "php"), ("bash", "shell"), ("/sh", "shell"), ("zsh", "shell"),
    ("ksh", "shell"), ("lua", "lua"), ("elixir", "elixir"), ("escript", "erlang"),
)
BINARY_EXTENSIONS = frozenset(
    "png jpg jpeg gif bmp ico icns tif tiff webp psd ai eps pdf doc docx xls xlsx ppt pptx odt ods odp "
    "zip gz tgz bz2 xz 7z rar tar zst lz4 lzma jar war ear apk aab aar class dex so dylib dll exe o a "
    "lib obj pyc pyo pyd whl egg wasm bin dat db sqlite sqlite3 mdb woff woff2 ttf otf eot mp3 mp4 m4a "
    "wav ogg flac avi mov mkv webm swf fla deb rpm msi iso img dmg pkg node keystore jks p12 pfx der "
    "pcap pcapng heic avif raw cr2 nef blend fbx glb gltf onnx pt pth ckpt safetensors npy npz h5 "
    "parquet orc avro pb tflite mo pak bundle".split()
)
# Directories that the census does not enter: VCS data, installed dependencies, caches.
SKIP_DIRS = frozenset({
    ".git", ".hg", ".svn", ".bzr", "node_modules", "bower_components", "jspm_packages",
    "__pycache__", ".venv", "site-packages", "dist-packages", ".tox", ".nox", ".mypy_cache",
    ".pytest_cache", ".ruff_cache", ".gradle", ".idea", ".next", ".nuxt", ".svelte-kit",
    ".yarn", ".pnpm-store", ".turbo", ".parcel-cache", ".angular", ".dart_tool", ".terraform",
    ".cache", "Pods", "Carthage", ".bundle", ".cargo", ".m2", ".stack-work", "_build", "deps",
    ".elixir_ls", ".ccls-cache", ".vs",
})
# A language family selects the rule groups of the scan.
FAMILY_OF_LANGUAGE = {
    "python": "python", "javascript": "js", "typescript": "js", "vue": "jstpl", "svelte": "jstpl",
    "php": "php", "go": "go", "java": "jvm", "kotlin": "jvm", "scala": "jvm", "groovy": "jvm",
    "jsp": "jsp", "c": "c", "cpp": "c", "objc": "c", "csharp": "cs", "razor": "razor",
    "ruby": "ruby", "erb": "erb", "haml": "erb", "slim": "erb", "rust": "rust", "elixir": "elixir",
    "heex": "heex", "erlang": "erlang", "clojure": "clojure", "perl": "perl", "swift": "swift",
    "lua": "lua", "dart": "dart", "shell": "shell", "html": "tpl", "template": "tpl",
}
FAMILY_GROUPS = {
    "python": ("py", "any"), "js": ("js", "any"), "jstpl": ("js", "tpl", "any"),
    "php": ("php", "tpl", "any"), "go": ("go", "any"), "jvm": ("jvm", "any"),
    "jsp": ("jvm", "tpl", "any"), "c": ("c", "any"), "cs": ("cs", "any"),
    "razor": ("cs", "tpl", "any"), "ruby": ("rb", "any"), "erb": ("rb", "tpl", "any"),
    "rust": ("rs", "any"), "elixir": ("ex", "any"), "heex": ("ex", "tpl", "any"),
    "erlang": ("erl", "any"), "clojure": ("clj", "any"), "perl": ("pl", "any"),
    "swift": ("swift", "any"), "lua": ("lua", "any"), "dart": ("any",), "shell": ("sh", "any"),
    "tpl": ("tpl",), "gha": ("gha",),
}
FAMILY_ORDER = (
    "python", "js", "jstpl", "php", "go", "jvm", "jsp", "c", "cs", "razor", "ruby", "erb", "rust",
    "elixir", "heex", "erlang", "clojure", "perl", "swift", "lua", "dart", "shell", "tpl", "gha",
)

TAG_DIRS = {
    "test": {"test", "tests", "__tests__", "__test__", "spec", "specs", "testing", "e2e",
             "unittests", "unit_tests", "unittest", "integration_tests", "integration-tests",
             "integrationtests", "testsuite", "test-suite", "testcases", "testutil", "testutils",
             "test_utils", "test-utils", "testhelpers", "test_helpers", "mocks", "__mocks__", "mock",
             "cypress", "playwright", "selenium", "conformance", "regress", "regression"},
    "fixtures": {"fixtures", "fixture", "__fixtures__", "testdata", "test-data", "test_data",
                 "test-fixtures", "test_fixtures", "golden", "snapshots", "__snapshots__", "corpus",
                 "corpora", "stubs"},
    "example": {"example", "examples", "sample", "samples", "demo", "demos", "playground",
                "tutorial", "tutorials", "quickstart", "cookbook", "showcase", "sandbox", "starter",
                "templates-examples"},
    "docs": {"doc", "docs", "documentation", "man", "manual", "website", "site-docs", "docs-site"},
    "vendor": {"vendor", "vendors", "vendored", "_vendor", "third_party", "third-party", "compiled", "precompiled",
               "thirdparty", "3rdparty", "external", "externals", "extern", "node_modules",
               "bower_components", "jspm_packages", "site-packages", "pods", "carthage"},
    "generated": {"generated", "__generated__", "autogen", "auto-generated", "gen-src", "gensrc"},
    "build": {"dist", "build", "out", "target", "obj", "coverage", ".next", "cmake-build-debug",
              "cmake-build-release", "public/build", "_site", "htmlcov"},
    "benchmark": {"bench", "benchmark", "benchmarks", "benches", "perf", "jmh"},
    "tooling": {"scripts", "script", "tools", "tool", "hack", "ci", "devtools", "dev-tools", "dev",
                "utils-dev", "misc", "contrib", ".github", ".circleci", ".buildkite", "buildtools",
                "build-tools", "build_tools", "buildsrc", "build-tools-internal", "build-logic", "gradle"},
}
SOURCE_DIRS = frozenset({"src", "source", "sources", "lib", "pkg", "internal", "app", "packages"})
TEST_FILE_RE = re.compile(
    r"^(?:test_.+\.py|.+_test\.py|conftest\.py|.+_test\.go|.+\.(?:test|spec|e2e|cy|stories|story)\.[cm]?[jt]sx?"
    r"|.+(?:Test|Tests|TestCase|IT|Spec)\.(?:java|kt|scala|groovy|cs|swift|php)|.+_(?:spec|test)\.rb"
    r"|(?:test_.+|.+_test|.+_unittest|.+_tests)\.(?:c|cc|cpp|cxx|h|hpp)|.+_test\.(?:exs|dart|rs)|tests\.rs"
    r"|.+\.t|test\..+|mock_.+|.+_mock\.\w+|.+\.mock\.[jt]sx?|fake_.+|.+_fake\.\w+)$"
)
GENERATED_FILE_RE = re.compile(
    r"^(?:.+\.(?:min\.js|min\.css|min\.mjs|bundle\.js|chunk\.js|pb\.go|pb\.gw\.go|pb\.cc|pb\.h|pb2\.py|pb2_grpc\.py"
    r"|generated\.\w+|g\.dart|freezed\.dart|designer\.cs|d\.ts)|.+_pb2\.py|.+_pb2_grpc\.py|zz_generated.+"
    r"|.+_generated\.\w+|.+\.generated\.\w+|.+-generated\.\w+|bindata\.go|.+_string\.go|mock_.+\.go"
    r"|.+\.pb\.\w+|package-lock\.json|yarn\.lock|pnpm-lock\.yaml|composer\.lock|cargo\.lock|go\.sum)$"
)
DOC_FILE_RE = re.compile(
    r"^(?:readme|changelog|changes|history|news|authors|contributors|security|license|licence|copying"
    r"|notice|code_of_conduct|contributing|release-notes|release_notes|releasenotes)(?:\..*)?$"
)
GENERATED_MARK_RE = re.compile(
    r"(?i)(?:code generated .{0,80}do not edit|@generated\b|this file (?:was|is) (?:automatically |auto-)?generated"
    r"|auto-?generated (?:by|file|code)|generated by (?:the )?(?:protoc|swagger|openapi|thrift|bison|flex|yacc|antlr)"
    r"|do not edit (?:this file|manually|by hand))"
)
TAG_MULTIPLIER = {
    "test": 0.12, "fixtures": 0.15, "docs": 0.15, "example": 0.3, "vendor": 0.2, "generated": 0.15,
    "build": 0.2, "benchmark": 0.3, "tooling": 0.6, "minified": 0.1, "declarations": 0.3,
}

# Signal rules. Each regex must compile in Python `re` and in Rust `regex`
# (ripgrep): no look-around, no back references, braces escaped, scoped flags.
# Fields: id, kind, class, CWE, weight, groups (space separated), regex.

_RULE_SPECS = (
    # Routes and entry points
    ("route.express", "route", "route", None, 1.0, "js",
     r'''\b[A-Za-z_$][\w$]*\.(?:get|post|put|patch|delete|del|all|head|options|use|route)\s*\(\s*['"`]/'''),
    ("route.nest", "route", "route", None, 1.0, "js",
     r'''@(?:Get|Post|Put|Patch|Delete|All|Options|Head|Sse|Query|Mutation|Subscription|MessagePattern|EventPattern|SubscribeMessage)\s*\('''),
    ("route.nest_controller", "route", "route", None, 0.5, "js", r'''@(?:Controller|Resolver|WebSocketGateway)\s*\('''),
    ("route.next_handler", "route", "route", None, 1.0, "js",
     r'''\bexport\s+(?:async\s+)?function\s+(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b|\bexport\s+const\s+(?:GET|POST|PUT|PATCH|DELETE)\s*='''),
    ("route.next_default", "route", "route", None, 0.8, "js", r'''\bexport\s+default\s+(?:async\s+)?function\b'''),
    ("route.server_action", "route", "route", None, 0.8, "js", r'''^\s*['"]use server['"]'''),
    ("route.trpc", "route", "route", None, 0.9, "js",
     r'''\b(?:public|protected|admin|authed|private|authenticated|user|org)Procedure\b'''),
    ("route.js_lambda", "route", "route", None, 0.8, "js",
     r'''\bexports\.handler\s*=|\bexport\s+(?:const|async\s+function|function)\s+handler\b'''),
    ("route.js_ws", "route", "route", None, 0.6, "js", r'''\.on\s*\(\s*['"](?:message|connection|upgrade|request)['"]'''),
    ("route.flask", "route", "route", None, 1.0, "py", r'''@[\w.]+\.route\s*\('''),
    ("route.fastapi", "route", "route", None, 1.0, "py",
     r'''@[\w.]+\.(?:get|post|put|patch|delete|options|head|api_route|websocket)\s*\('''),
    ("route.django", "route", "route", None, 0.9, "py", r'''\b(?:path|re_path|url)\s*\(\s*r?['"]'''),
    ("route.py_view", "route", "route", None, 0.9, "py",
     r'''@api_view\s*\(|@action\s*\(|\bclass\s+\w+\s*\([^)]*(?:APIView|ViewSet|GenericAPIView|View|ListView|DetailView|CreateView|UpdateView|DeleteView|FormView|TemplateView|RequestHandler|MethodView|Resource|Consumer)\b'''),
    ("route.aiohttp", "route", "route", None, 0.9, "py",
     r'''\b(?:web|router|app\.router)\.(?:add_get|add_post|add_put|add_patch|add_delete|add_route|add_view)\s*\('''),
    ("route.py_lambda", "route", "route", None, 0.8, "py", r'''\bdef\s+(?:lambda_handler|handler)\s*\(\s*event\b'''),
    ("route.spring", "route", "route", None, 1.0, "jvm", r'''@(?:Get|Post|Put|Delete|Patch|Request)Mapping\b'''),
    ("route.jaxrs", "route", "route", None, 1.0, "jvm", r'''@(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|Path)\b'''),
    ("route.servlet", "route", "route", None, 1.0, "jvm",
     r'''\b(?:doGet|doPost|doPut|doDelete|doPatch|service)\s*\(\s*(?:final\s+)?HttpServletRequest\b'''),
    ("route.ktor", "route", "route", None, 0.9, "jvm", r'''\b(?:get|post|put|patch|delete|route)\s*\(\s*"/'''),
    ("route.jvm_queue", "route", "route", None, 0.6, "jvm",
     r'''@(?:KafkaListener|RabbitListener|JmsListener|SqsListener|StreamListener|MessageMapping|SubscribeMapping|GrpcService)\b'''),
    ("route.jvm_grpc", "route", "route", None, 0.7, "jvm", r'''\bextends\s+\w+ImplBase\b'''),
    ("route.es_rest", "route", "route", None, 0.9, "jvm",
     r'''\bnew\s+Route\s*\(\s*(?:RestRequest\.)?(?:GET|POST|PUT|DELETE|HEAD)\b|\bextends\s+Base\w*RestHandler\b|\bRestRequest\b'''),
    ("route.laravel", "route", "route", None, 1.0, "php",
     r'''\bRoute::(?:get|post|put|patch|delete|any|match|resource|apiResource|resources|apiResources|view|group|middleware|prefix|controller|redirect)\s*\('''),
    ("route.symfony", "route", "route", None, 1.0, "php", r'''#\[Route\s*\(|@Route\s*\('''),
    ("route.wp", "route", "route", None, 1.0, "php",
     r'''\bregister_rest_route\s*\(|\badd_action\s*\(\s*['"](?:wp_ajax_|admin_post_)|\badd_shortcode\s*\('''),
    ("route.php_app", "route", "route", None, 0.9, "php",
     r'''\$\w+->(?:get|post|put|patch|delete|any|map|match|addRoute)\s*\(\s*['"]/'''),
    ("route.php_controller", "route", "route", None, 0.4, "php",
     r'''\bclass\s+\w+Controller\b|\bfunction\s+action[A-Z]\w*\s*\(|\bextends\s+(?:\w+)?Controller\b'''),
    ("route.rails", "route", "route", None, 0.9, "rb",
     r'''^\s*(?:get|post|put|patch|delete|match|resources?|root|namespace|scope|mount)\s*\(?\s*['":]'''),
    ("route.sinatra", "route", "route", None, 1.0, "rb", r'''^\s*(?:get|post|put|patch|delete|options|head)\s+['"]/'''),
    ("route.rails_controller", "route", "route", None, 0.4, "rb", r'''\bclass\s+\w+Controller\s*<'''),
    ("route.go_router", "route", "route", None, 1.0, "go",
     r'''\.(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|Any|Handle|HandleFunc|Get|Post|Put|Delete|Patch|Head|Options|Group|Route|Method|Mount|Methods)\s*\(\s*"'''),
    ("route.go_grpc", "route", "route", None, 0.7, "go", r'''\bUnimplemented\w+Server\b|\bRegister\w+Server\s*\('''),
    ("route.aspnet", "route", "route", None, 1.0, "cs",
     r'''\[(?:Http(?:Get|Post|Put|Delete|Patch|Head|Options)|Route)\b|\.Map(?:Get|Post|Put|Delete|Patch|Methods|Fallback|Hub|Group)?\s*\(\s*"'''),
    ("route.aspnet_controller", "route", "route", None, 0.4, "cs",
     r''':\s*(?:Controller|ControllerBase|ApiController|PageModel|Hub)\b'''),
    ("route.phoenix", "route", "route", None, 1.0, "ex",
     r'''^\s*(?:get|post|put|patch|delete|options|head|live|forward|resources|match)\s+"/'''),
    ("route.phoenix_module", "route", "route", None, 0.4, "ex",
     r'''\buse\s+[\w.]+,\s*:(?:controller|live_view|live_component|channel)\b|\buse\s+Phoenix\.(?:Controller|LiveView|Channel)\b'''),
    ("route.rust_web", "route", "route", None, 1.0, "rs",
     r'''#\[(?:get|post|put|delete|patch|head|options|route)\s*\(\s*"|\.route\s*\(\s*"/'''),
    ("route.clj", "route", "route", None, 1.0, "clj", r'''\((?:GET|POST|PUT|DELETE|PATCH|ANY|context)\s+"/|\["/'''),
    ("route.perl", "route", "route", None, 0.9, "pl", r'''^\s*(?:get|post|put|del|any|under)\s+['"]/'''),
    ("route.erl", "route", "route", None, 0.8, "erl", r'''\{\s*"/[^"]*"\s*,\s*\w+'''),
    ("route.cli", "route", "route", None, 0.4, "any",
     r'''\bif\s+__name__\s*==\s*['"]__main__['"]|\bargparse\.ArgumentParser\s*\(|@click\.(?:command|group)\b|\bfunc\s+main\s*\(\s*\)|\bint\s+main\s*\(|\bpublic\s+static\s+void\s+main\s*\(|\bfn\s+main\s*\(\s*\)|\bcobra\.Command\s*\{|\bflag\.Parse\s*\(\s*\)'''),

    # Sources: request input and other external input
    ("src.py.request", "source", "input", None, 1.0, "py",
     r'''\brequest\.(?:args|form|values|json|data|files|cookies|headers|get_json|get_data|query_params|query_string|GET|POST|FILES|COOKIES|META|body|path_params|stream|environ|remote_addr|url|full_path|path)\b'''),
    ("src.py.handler", "source", "input", None, 1.0, "py",
     r'''\bself\.(?:get_argument|get_arguments|get_body_argument|get_query_argument|get_cookie|get_secure_cookie)\b|\bself\.request\.(?:body|arguments|files|headers)\b'''),
    ("src.py.cli", "source", "input", None, 0.4, "py",
     r'''\bsys\.argv\b|\bsys\.stdin\b|\bos\.environ\b|\bos\.getenv\s*\('''),
    ("src.js.request", "source", "input", None, 1.0, "js",
     r'''\b(?:req|request|ctx|event)\.(?:query|body|params|headers|cookies|files|file|url|originalUrl|path|hostname|ip|ips|searchParams|nextUrl|formData|queryStringParameters|pathParameters|request)\b'''),
    ("src.js.browser", "source", "input", None, 0.8, "js",
     r'''\blocation\.(?:hash|search|href|pathname)\b|\bdocument\.(?:URL|documentURI|referrer|cookie)\b|\bwindow\.name\b|\bnew\s+URLSearchParams\b|\baddEventListener\s*\(\s*['"]message['"]|\bonmessage\b'''),
    ("src.js.cli", "source", "input", None, 0.4, "js", r'''\bprocess\.(?:argv|env|stdin)\b'''),
    ("src.php.super", "source", "input", None, 1.2, "php",
     r'''\$_(?:GET|POST|REQUEST|COOKIE|FILES|SERVER|ENV)\b|\$HTTP_RAW_POST_DATA\b|php://input|\bfilter_input\s*\(|\bgetallheaders\s*\('''),
    ("src.php.request", "source", "input", None, 1.0, "php",
     r'''\$request->(?:input|get|query|post|all|file|files|only|except|cookie|header|headers|json|getContent|request|attributes|server|route|validated|safe|string|integer|boolean)\b|\brequest\(\)->|\bRequest::(?:input|get|all|query|file)\b|\bInput::(?:get|all)\b|\$this->request->(?:getPost|getGet|getVar|getJSON|getRawInput|input|post|get|data|query|param|getParam|getData)\b|\$this->input->(?:post|get|cookie|server)\b'''),
    ("src.go.request", "source", "input", None, 1.0, "go",
     r'''\b(?:r|req|request)\.(?:URL\.Query|FormValue|PostFormValue|Form|PostForm|MultipartForm|Body|Header\.Get|Cookie|Cookies|URL\.Path|URL\.RawQuery|Host|RemoteAddr|ParseForm|ParseMultipartForm|FormFile|PathValue)\b|\b(?:c|ctx)\.(?:Param|Query|DefaultQuery|PostForm|DefaultPostForm|FormFile|MultipartForm|Bind|ShouldBind\w*|BindJSON|BindQuery|GetHeader|Cookie|GetRawData|QueryParam|QueryParams|FormValue|Params|BodyParser|UserValue|QueryArgs|PostArgs|PostBody)\s*\(|\bmux\.Vars\s*\(|\bchi\.URLParam\s*\('''),
    ("src.go.decode", "source", "input", None, 1.2, "go",
     r'''\bjson\.NewDecoder\s*\(\s*(?:r|req|request)\.Body|\bio(?:util)?\.ReadAll\s*\(\s*(?:r|req|request)\.Body'''),
    ("src.go.cli", "source", "input", None, 0.4, "go", r'''\bos\.Args\b|\bos\.Getenv\s*\(|\bos\.Stdin\b'''),
    ("src.jvm.annot", "source", "input", None, 1.0, "jvm",
     r'''@(?:RequestParam|PathVariable|RequestBody|RequestHeader|CookieValue|RequestPart|MatrixVariable|QueryParam|PathParam|FormParam|HeaderParam|CookieParam|BeanParam)\b'''),
    ("src.jvm.servlet", "source", "input", None, 1.0, "jvm",
     r'''\.(?:getParameter|getParameterValues|getParameterMap|getHeader|getHeaders|getQueryString|getInputStream|getReader|getCookies|getRequestURI|getRequestURL|getPathInfo|getPart|getParts|getServletPath|param|paramAsInt|paramAsBoolean|content|contentParser)\s*\('''),
    ("src.jvm.types", "source", "input", None, 0.6, "jvm",
     r'''\bMultipartHttpServletRequest\b|\bHttpServletRequest\b|\bServerHttpRequest\b|\bServerRequest\b|\bRoutingContext\b|\bApplicationCall\b|\bcall\.receive\w*|\bcall\.parameters\b|\bRestRequest\b'''),
    ("src.cs.request", "source", "input", None, 1.0, "cs",
     r'''\b(?:Request|HttpContext\.Request|context\.Request)\.(?:Query|Form|Headers|Cookies|Body|Path|QueryString|Files|RouteValues|ReadFromJsonAsync|ReadFormAsync)\b|\[From(?:Query|Body|Form|Route|Header)\b'''),
    ("src.rb.params", "source", "input", None, 1.0, "rb",
     r'''\bparams\[|\bparams\.(?:require|permit|fetch|dig|to_unsafe_h|to_h|slice|merge|except|key\?)|\brequest\.(?:body|params|headers|env|raw_post|query_string|path|url|host|remote_ip|ip|cookies|POST|GET)\b|\bcookies\['''),
    ("src.ex.conn", "source", "input", None, 1.0, "ex",
     r'''\bconn\.(?:params|body_params|query_params|path_params|req_headers|cookies|req_cookies|host|request_path|query_string|remote_ip)\b|\bPlug\.Conn\.(?:read_body|get_req_header|fetch_query_params)\b|\bget_req_header\s*\(|\bread_body\s*\(|\bdef\s+handle_(?:event|in|info|call|cast|params)\s*\('''),
    ("src.rs.extract", "source", "input", None, 1.0, "rs",
     r'''\b(?:web|extract|axum::extract)::(?:Query|Json|Path|Form|Multipart|Bytes|RawQuery)\b|\b(?:Query|Json|Form|Multipart)\s*<|\bHttpRequest\b|\bstd::env::args\b|\breq\.(?:match_info|query_string|headers|uri)\s*\('''),
    ("src.c.read", "source", "input", None, 0.8, "c",
     r'''\b(?:recv|recvfrom|recvmsg|recvmmsg|read|pread|readv|fread|fgets|getline|getdelim|scanf|fscanf|getc|fgetc|getchar|readlink|getenv|secure_getenv|SSL_read|BIO_read|gnutls_record_recv)\s*\('''),
    ("src.c.parse", "source", "input", None, 1.0, "c",
     r'''\b(?:ntohs|ntohl|ntohll|be16toh|be32toh|be64toh|le16toh|le32toh|le64toh|be16_to_cpu|be32_to_cpu|be64_to_cpu|le16_to_cpu|le32_to_cpu|le64_to_cpu|get_unaligned\w*|BE_IN8|BE_IN16|BE_IN32|BE_IN64|LE_IN16|LE_IN32|LE_IN64|BSWAP_16|BSWAP_32|BSWAP_64|bswap_16|bswap_32|bswap_64|EXTRACT_\w+|GET_BE_U_\d+|GET_LE_U_\d+|nvlist_lookup_\w+|nvpair_value_\w+|xdr_\w+|nla_get_\w+|nla_data|skb_pull|skb_header_pointer|pskb_may_pull)\s*\('''),
    ("src.c.user", "source", "input", None, 1.2, "c",
     r'''\b(?:copyin|copyout|ddi_copyin|ddi_copyout|copyinstr|copyoutstr|copy_from_user|copy_to_user|get_user|put_user|uiomove|strncpy_from_user|memdup_user|ioctl|compat_ptr|mdb_vread|kmdb_\w+)\s*\('''),
    ("src.c.argv", "source", "input", None, 0.4, "c", r'''\bargv\s*\['''),
    ("src.pl.cgi", "source", "input", None, 1.0, "pl",
     r'''\bparam\s*\(|\$cgi->|\$q->param|\$ENV\s*\{|<STDIN>|\$ARGV\b|@ARGV\b|\$c->(?:req|param|stash)\b|\$self->param\b'''),
    ("src.erl", "source", "input", None, 1.0, "erl",
     r'''\bcowboy_req:(?:read_body|binding|parse_qs|match_qs|header|headers|read_urlencoded_body)\b|\bgen_tcp:recv\b|\bssl:recv\b|\bhandle_call\s*\(|\bhandle_cast\s*\(|\bhandle_info\s*\('''),
    ("src.clj", "source", "input", None, 1.0, "clj",
     r''':(?:params|query-params|form-params|body-params|route-params|multipart-params|path-params)\b'''),
    ("src.lua", "source", "input", None, 1.0, "lua", r'''\bngx\.req\.\w+|\bngx\.var\.\w+'''),
    ("src.swift", "source", "input", None, 1.0, "swift", r'''\breq\.(?:query|content|parameters|body)\b'''),
    ("src.go.binary", "source", "input", None, 0.8, "go",
     r'''\bbinary\.(?:BigEndian|LittleEndian|NativeEndian)\.(?:Uint16|Uint32|Uint64)\s*\(|\bbinary\.Read\s*\(|\bbinary\.(?:Uvarint|Varint|ReadUvarint|ReadVarint)\s*\('''),
    ("src.jvm.binary", "source", "input", None, 0.7, "jvm",
     r'''\.(?:readInt|readLong|readShort|readUnsignedShort|readUnsignedByte|readFully|readUTF|readVInt|readVLong|readVInt|readByte|readBytes|readString)\s*\(|\bByteBuffer\.wrap\s*\('''),

    # Command execution
    ("cmd.py.os", "sink", "cmd", "CWE-78", 3.0, "py",
     r'''\bos\.(?:system|popen|popen2|popen3|execl|execle|execlp|execlpe|execv|execve|execvp|execvpe|spawnl|spawnle|spawnlp|spawnv|spawnve|spawnvp|posix_spawn|posix_spawnp)\s*\('''),
    ("cmd.py.subprocess", "sink", "cmd", "CWE-78", 2.5, "py",
     r'''\bsubprocess\.(?:run|call|check_call|check_output|Popen|getoutput|getstatusoutput)\s*\('''),
    ("cmd.py.shell", "sink", "cmd", "CWE-78", 2.5, "py", r'''\bshell\s*=\s*True\b'''),
    ("cmd.py.other", "sink", "cmd", "CWE-78", 2.5, "py",
     r'''\b(?:commands\.getoutput|pty\.spawn|asyncio\.create_subprocess_shell|asyncio\.create_subprocess_exec|pexpect\.spawn|pexpect\.run)\s*\('''),
    ("cmd.js.cp", "sink", "cmd", "CWE-78", 2.5, "js",
     r'''\b(?:child_process|childProcess|cp|proc)\.(?:exec|execSync|execFile|execFileSync|spawn|spawnSync|fork)\s*\('''),
    ("cmd.js.bare", "sink", "cmd", "CWE-78", 2.0, "js",
     r'''(?:^|[^.\w$])(?:exec|execSync|execFileSync|spawnSync|execa|execaSync|execaCommand|execaCommandSync|spawn|execFile)\s*\('''),
    ("cmd.js.module", "sink", "cmd", "CWE-78", 1.5, "js",
     r'''\brequire\s*\(\s*['"](?:node:)?child_process['"]\s*\)|\bfrom\s+['"](?:node:)?child_process['"]'''),
    ("cmd.js.shell", "sink", "cmd", "CWE-78", 2.0, "js", r'''\bshell\s*:\s*true\b'''),
    ("cmd.php", "sink", "cmd", "CWE-78", 3.0, "php",
     r'''(?:^|[^>\w$:])(?:exec|shell_exec|system|passthru|popen|proc_open|pcntl_exec|expect_popen)\s*\('''),
    ("cmd.php.escape", "guard", "cmd", "CWE-78", 0.6, "php", r'''\bescapeshell(?:arg|cmd)\s*\('''),
    ("cmd.go", "sink", "cmd", "CWE-78", 2.5, "go",
     r'''\bexec\.Command(?:Context)?\s*\(|\bsyscall\.(?:Exec|ForkExec|StartProcess)\s*\(|\bos\.StartProcess\s*\('''),
    ("cmd.shell_c", "sink", "cmd", "CWE-78", 2.5, "any", r'''['"](?:/bin/|/usr/bin/)?(?:ba|z|da)?sh['"]\s*,\s*['"]-c['"]'''),
    ("cmd.jvm", "sink", "cmd", "CWE-78", 3.0, "jvm",
     r'''\bRuntime\.getRuntime\s*\(\s*\)\s*\.exec\s*\(|\bnew\s+ProcessBuilder\s*\(|\bProcessBuilder\s*\(|\bCommandLine\.parse\s*\(|\bDefaultExecutor\b|\.execute\s*\(\s*\)\s*\.text\b'''),
    ("cmd.c", "sink", "cmd", "CWE-78", 2.5, "c",
     r'''\b(?:system|popen|execl|execlp|execle|execv|execvp|execvpe|execve|fexecve|posix_spawn|posix_spawnp|_popen|_wsystem|_wpopen|ShellExecute[AW]?|ShellExecuteEx[AW]?|CreateProcess[AW]?|CreateProcessAsUser[AW]?|WinExec)\s*\('''),
    ("cmd.cs", "sink", "cmd", "CWE-78", 3.0, "cs", r'''\bProcess\.Start\s*\(|\bnew\s+ProcessStartInfo\b|\bProcessStartInfo\s*\{'''),
    ("cmd.rb", "sink", "cmd", "CWE-78", 2.5, "rb",
     r'''(?:^|[^.\w])(?:system|exec|spawn|syscall)\s*[( ]|`[^`]*#\{|%x[(\{\[]|\bIO\.popen\b|\bOpen3\.\w+|\bKernel\.(?:system|exec|spawn|open)\b|\bPTY\.spawn\b'''),
    ("cmd.rb.open", "sink", "cmd", "CWE-78", 2.0, "rb", r'''(?:^|[^.\w])open\s*\(\s*(?:params|request|"\|)'''),
    ("cmd.rs", "sink", "cmd", "CWE-78", 2.5, "rs", r'''\bCommand::new\s*\(|\bprocess::Command\b'''),
    ("cmd.ex", "sink", "cmd", "CWE-78", 2.5, "ex", r'''\bSystem\.(?:cmd|shell)\s*\(|:os\.cmd\s*\(|\bPort\.open\s*\(|\bMuonTrap\.cmd\s*\('''),
    ("cmd.erl", "sink", "cmd", "CWE-78", 2.5, "erl", r'''\bos:cmd\s*\(|\bopen_port\s*\('''),
    ("cmd.pl", "sink", "cmd", "CWE-78", 2.5, "pl",
     r'''(?:^|[^.\w$>])(?:system|exec)\s*[( ]|\bqx\s*[(\{\[/!|]|`[^`]*\$|\bopen\s*\(\s*(?:my\s+)?[$\w]+\s*,\s*['"]\s*\||\bopen\s*\(\s*(?:my\s+)?[$\w]+\s*,\s*['"][^'"]*\|\s*['"]|\bopen\s*\(\s*(?:my\s+)?\$?\w+\s*,\s*\$\w+\s*\)'''),
    ("cmd.clj", "sink", "cmd", "CWE-78", 2.5, "clj", r'''\bclojure\.java\.shell/sh\b|\(sh\s|\bRuntime/getRuntime\b|\(\.exec\s'''),
    ("cmd.lua", "sink", "cmd", "CWE-78", 2.5, "lua", r'''\bos\.execute\s*\(|\bio\.popen\s*\('''),
    ("cmd.swift", "sink", "cmd", "CWE-78", 2.0, "swift", r'''\bProcess\s*\(\s*\)|\bNSTask\b|\bposix_spawn\s*\(|\.launchPath\b|\.executableURL\b'''),
    ("cmd.sh", "sink", "code", "CWE-78", 1.5, "sh", r'''\beval\s+\S|\$\(\s*\$\w+'''),
    ("cmd.gha", "sink", "cmd", "CWE-78", 3.0, "gha",
     r'''\$\{\{\s*(?:github\.event\.(?:issue|pull_request|comment|review|review_comment|head_commit|commits|pages|discussion|workflow_run|inputs)\b|github\.head_ref|inputs\.)'''),
    ("cmd.gha_trigger", "sink", "authz", "CWE-284", 2.0, "gha", r'''\bpull_request_target\b|\bworkflow_run\b'''),

    # Dynamic code, reflection, template injection
    ("code.py.eval", "sink", "code", "CWE-95", 3.0, "py", r'''(?:^|[^.\w])(?:eval|exec|execfile)\s*\('''),
    ("code.py.compile", "sink", "code", "CWE-94", 1.5, "py", r'''(?:^|[^.\w])compile\s*\('''),
    ("code.py.import", "sink", "reflect", "CWE-470", 1.5, "py",
     r'''\b__import__\s*\(|\bimportlib\.import_module\s*\(|\bimp\.load_source\s*\(|\brunpy\.run_\w+\s*\('''),
    ("code.py.getattr", "sink", "reflect", "CWE-470", 1.0, "py", r'''\b(?:getattr|setattr)\s*\(\s*[\w.]+\s*,\s*[a-z_]\w*'''),
    ("code.py.ssti", "sink", "ssti", "CWE-1336", 2.5, "py",
     r'''\brender_template_string\s*\(|\bjinja2\.Template\s*\(|\.from_string\s*\(|\bmako\.template\.Template\s*\(|\bTemplate\s*\(\s*[a-z_]\w*\s*\)\.render\b'''),
    ("code.js.eval", "sink", "code", "CWE-95", 3.0, "js",
     r'''(?:^|[^.\w$])eval\s*\(|\bnew\s+Function\s*\(|(?:^|[^.\w$])Function\s*\(\s*['"`a-z]'''),
    ("code.js.timer", "sink", "code", "CWE-95", 2.0, "js", r'''\bset(?:Timeout|Interval|Immediate)\s*\(\s*['"`]'''),
    ("code.js.vm", "sink", "code", "CWE-94", 3.0, "js",
     r'''\bvm\.(?:runInNewContext|runInContext|runInThisContext|compileFunction|Script|SourceTextModule)\b|\bvm2\b|\bNodeVM\b'''),
    ("code.js.require", "sink", "code", "CWE-94", 1.5, "js", r'''\brequire\s*\(\s*[^'"`)\s]|\bimport\s*\(\s*[^'"`)\s]'''),
    ("code.js.ssti", "sink", "ssti", "CWE-1336", 2.0, "js",
     r'''\b(?:_\.template|lodash\.template|ejs\.render|ejs\.compile|pug\.compile|pug\.render|Handlebars\.compile|handlebars\.compile|nunjucks\.renderString|doT\.template|Mustache\.render)\s*\('''),
    ("code.php.eval", "sink", "code", "CWE-95", 3.0, "php", r'''(?:^|[^>\w$:])(?:eval|assert|create_function)\s*\('''),
    ("code.php.include", "sink", "code", "CWE-98", 3.0, "php", r'''\b(?:include|require|include_once|require_once)\s*\(?\s*\$'''),
    ("code.php.callable", "sink", "reflect", "CWE-470", 1.5, "php",
     r'''\bcall_user_func(?:_array)?\s*\(|\bforward_static_call(?:_array)?\s*\(|\bnew\s+\$\w+|\$\w+\s*\(\s*\$|\bnew\s+ReflectionClass\s*\(|::\$\w+\s*\('''),
    ("code.php.extract", "sink", "code", "CWE-621", 2.0, "php",
     r'''\bextract\s*\(\s*\$|\bparse_str\s*\(\s*[^,()]+\)|\$\$\w+|\bimport_request_variables\s*\('''),
    ("code.php.preg_e", "sink", "code", "CWE-95", 2.5, "php", r'''\bpreg_replace\s*\(\s*['"][^'"]*/[a-zA-Z]*e[a-zA-Z]*['"]'''),
    ("code.go.tmpl", "sink", "xss", "CWE-79", 2.5, "go", r'''\btemplate\.(?:HTML|JS|JSStr|URL|HTMLAttr|CSS|Srcset)\s*\('''),
    ("code.go.texttmpl", "sink", "xss", "CWE-79", 1.0, "go", r'''"text/template"'''),
    ("code.go.plugin", "sink", "code", "CWE-94", 2.0, "go", r'''\bplugin\.Open\s*\(|\byaegi\b|\bgoja\.\w+|\botto\.\w+'''),
    ("code.jvm.script", "sink", "code", "CWE-94", 2.5, "jvm",
     r'''\bScriptEngineManager\b|\bgetEngineByName\s*\(|\bSpelExpressionParser\b|\bparseExpression\s*\(|\bStandardEvaluationContext\b|\bOgnl\.\w+|\bMVEL\.\w+|\bGroovyShell\b|\bGroovyClassLoader\b|\bJexlBuilder\b|\bJexlEngine\b|\bELProcessor\b|\bExpressionFactory\b|\bNashorn\w*|\bScriptService\b|\bcompileTemplate\s*\('''),
    ("code.jvm.reflect", "sink", "reflect", "CWE-470", 1.5, "jvm",
     r'''\bClass\.forName\s*\(|\.getDeclaredMethod\s*\(|\.getMethod\s*\(|\.newInstance\s*\(|\bMethodHandles\.\w+|\.loadClass\s*\(|\bURLClassLoader\b|\bdefineClass\s*\('''),
    ("code.jvm.jndi", "sink", "code", "CWE-74", 2.0, "jvm",
     r'''\bInitialContext\s*\(|\bInitialDirContext\s*\(|\.lookup\s*\(\s*[a-z]|\bJndiTemplate\b'''),
    ("code.jvm.ssti", "sink", "ssti", "CWE-1336", 2.0, "jvm",
     r'''\bVelocity\.evaluate\s*\(|\bVelocityEngine\b|\bfreemarker\.template\b|\bnew\s+Template\s*\(|\bTemplateEngine\b|\bPebbleEngine\b|\bMustacheFactory\b'''),
    ("code.c.dl", "sink", "code", "CWE-114", 1.5, "c",
     r'''\bdlopen\s*\(|\bdlsym\s*\(|\bLoadLibrary(?:Ex)?[AW]?\s*\(|\bGetProcAddress\s*\('''),
    ("code.cs", "sink", "code", "CWE-94", 2.5, "cs",
     r'''\bCSharpCodeProvider\b|\bCompileAssemblyFromSource\b|\bCSharpScript\.\w+|\bAssembly\.(?:Load|LoadFrom|LoadFile|UnsafeLoadFrom)\s*\(|\bActivator\.CreateInstance\s*\(|\bType\.GetType\s*\(|\.InvokeMember\s*\(|\bDynamicMethod\b'''),
    ("code.rb.eval", "sink", "code", "CWE-95", 2.5, "rb",
     r'''(?:^|[^.\w])(?:eval|instance_eval|class_eval|module_eval|instance_exec|class_exec)\b|\bbinding\.eval\b'''),
    ("code.rb.send", "sink", "reflect", "CWE-470", 1.5, "rb",
     r'''\.(?:send|public_send|__send__|try)\s*\(\s*(?:params|[a-z_]\w*\s*[,)])|\b(?:constantize|safe_constantize)\b|\bconst_get\s*\(|\.method\s*\(\s*params'''),
    ("code.rb.ssti", "sink", "ssti", "CWE-1336", 2.0, "rb",
     r'''\bERB\.new\s*\(|\brender\s*\(?\s*inline:|\bLiquid::Template\.parse\b|\bHaml::Engine\.new\b|\bSlim::Template\.new\b'''),
    ("code.ex", "sink", "code", "CWE-94", 3.0, "ex",
     r'''\bCode\.(?:eval_string|eval_quoted|eval_file|compile_string|compile_quoted|require_file|string_to_quoted)\s*\(|\bEEx\.(?:eval_string|eval_file|compile_string)\s*\(|\bapply\s*\(\s*[A-Za-z_]\w*\s*,\s*[a-z]'''),
    ("code.erl", "sink", "code", "CWE-94", 2.0, "erl", r'''\berl_eval:\w+|\berl_scan:\w+|\berl_parse:\w+|\bcompile:forms\b|\bapply\s*\(\s*[A-Z]'''),
    ("code.pl", "sink", "code", "CWE-95", 2.5, "pl", r'''\beval\s*[$"']|\beval\s*\(\s*\$|\bdo\s+\$\w+|\brequire\s+\$\w+'''),
    ("code.clj", "sink", "code", "CWE-95", 2.5, "clj", r'''\((?:read-string|load-string|eval|load-file|clojure\.core/read-string)\s'''),
    ("code.lua", "sink", "code", "CWE-95", 2.5, "lua", r'''\b(?:loadstring|load|dofile|loadfile)\s*\('''),

    # SQL and NoSQL
    ("sql.concat", "sink", "sql", "CWE-89", 2.5, "any",
     r'''(?i:["'`]\s*(?:SELECT\s[^"'`]*\bFROM|INSERT\s+INTO|UPDATE\s+[\w.`"\[\]]+\s+SET|DELETE\s+FROM|REPLACE\s+INTO|MERGE\s+INTO|ORDER\s+BY|GROUP\s+BY|WHERE|LIMIT|OFFSET|VALUES|AND|OR|IN\s*\()\b[^"'`]*["'`]\s*(?:\+|\.|%|\|\|))'''),
    ("sql.fstring", "sink", "sql", "CWE-89", 2.5, "py",
     r'''(?i:\bf["']\s*(?:SELECT|INSERT|UPDATE|DELETE|WITH|REPLACE|MERGE)\b[^"']*\{|["']\s*(?:SELECT|INSERT|UPDATE|DELETE|WITH)\b[^"']*["']\s*\.format\s*\()'''),
    ("sql.template", "sink", "sql", "CWE-89", 2.5, "js", r'''(?i:`\s*(?:SELECT|INSERT|UPDATE|DELETE|WITH|REPLACE)\b[^`]*\$\{)'''),
    ("sql.interp_cs", "sink", "sql", "CWE-89", 2.5, "cs", r'''(?i:\$@?"\s*(?:SELECT|INSERT|UPDATE|DELETE|WITH)\b[^"]*\{)'''),
    ("sql.interp_php", "sink", "sql", "CWE-89", 2.5, "php", r'''(?i:"\s*(?:SELECT|INSERT|UPDATE|DELETE|REPLACE)\b[^"]*\$\w)'''),
    ("sql.interp_rb", "sink", "sql", "CWE-89", 2.5, "rb ex", r'''(?i:"\s*(?:SELECT|INSERT|UPDATE|DELETE|WITH)\b[^"]*#\{)'''),
    ("sql.interp_jvm", "sink", "sql", "CWE-89", 2.5, "jvm",
     r'''(?i:"\s*(?:SELECT|INSERT|UPDATE|DELETE)\b[^"]*\$\{?\w|\bString\.format\s*\(\s*"\s*(?:SELECT|INSERT|UPDATE|DELETE|WITH)\b)'''),
    ("sql.sprintf_go", "sink", "sql", "CWE-89", 3.0, "go", r'''(?i:\bfmt\.Sprintf\s*\(\s*["`]\s*(?:SELECT|INSERT|UPDATE|DELETE|WITH|REPLACE)\b)'''),
    ("sql.format_rs", "sink", "sql", "CWE-89", 3.0, "rs", r'''(?i:\bformat!\s*\(\s*"\s*(?:SELECT|INSERT|UPDATE|DELETE|WITH)\b)'''),
    ("sql.sprintf_c", "sink", "sql", "CWE-89", 2.0, "c", r'''(?i:\bs?n?printf\s*\([^;]*"\s*(?:SELECT|INSERT|UPDATE|DELETE)\b)'''),
    ("sql.py.execute_fmt", "sink", "sql", "CWE-89", 3.0, "py",
     r'''\.(?:execute|executemany|executescript|raw|extra|mogrify)\s*\(\s*(?:f["']|["'][^"']*["']\s*(?:%|\+|\.format)|[a-z_]\w*\s*(?:%|\+))'''),
    ("sql.py.api", "sink", "sql", "CWE-89", 1.5, "py",
     r'''\b(?:cursor|cur|conn|connection|db|session|engine)\.(?:execute|executemany|executescript)\s*\(|\.raw\s*\(|\bRawSQL\s*\(|\.extra\s*\(|\btext\s*\(\s*f?["']'''),
    ("sql.js.api", "sink", "sql", "CWE-89", 2.0, "js",
     r'''\.(?:\$queryRawUnsafe|\$executeRawUnsafe|whereRaw|orWhereRaw|orderByRaw|havingRaw|joinRaw|selectRaw|fromRaw|groupByRaw|unsafe)\s*\(|\bsequelize\.query\s*\(|\bknex\.raw\s*\(|\.raw\s*\(\s*[`'"]|\bsql\.raw\s*\('''),
    ("sql.js.query", "sink", "sql", "CWE-89", 1.2, "js",
     r'''\.(?:query|execute)\s*\(\s*(?:`|['"]\s*(?i:SELECT|INSERT|UPDATE|DELETE|WITH)|[a-z_]\w*\s*[,)])'''),
    ("sql.php.api", "sink", "sql", "CWE-89", 2.0, "php",
     r'''\b(?:mysql_query|mysqli_query|mysqli_multi_query|mysqli_real_query|pg_query|pg_send_query|sqlite_query|odbc_exec|db2_exec|oci_parse|mssql_query)\s*\(|->(?:query|exec|multi_query|rawQuery|real_query|unprepared|statement|selectRaw|whereRaw|orWhereRaw|orderByRaw|havingRaw|groupByRaw|fromRaw|executeQuery|executeStatement|fetchAll|fetchAssoc|fetchOne|fetchColumn|createQuery|createNativeQuery)\s*\(|\bDB::(?:raw|select|statement|unprepared|insert|update|delete)\s*\(|\$wpdb->(?:query|get_results|get_var|get_row|get_col)\s*\('''),
    ("sql.php.where", "sink", "sql", "CWE-89", 1.2, "php",
     r'''->(?:where|orWhere|whereIn|orderBy|having|select|join|leftJoin|groupBy|andWhere|addSelect|addOrderBy)\s*\(\s*(?:\$|["'][^"']*\$|["'][^"']*["']\s*\.)'''),
    ("sql.go.api", "sink", "sql", "CWE-89", 1.5, "go",
     r'''\.(?:Query|QueryRow|QueryContext|QueryRowContext|Exec|ExecContext|Prepare|PrepareContext|Raw|Select|Get|NamedExec|NamedQuery|MustExec|Where|Or|Not|Order|Group|Having|Joins)\s*\(\s*(?:ctx\s*,\s*)?(?:fmt\.Sprintf|[a-z]\w*\s*[,)+]|"[^"]*"\s*\+)'''),
    ("sql.jvm.api", "sink", "sql", "CWE-89", 1.5, "jvm",
     r'''\b(?:createStatement|prepareStatement|prepareCall|executeQuery|executeUpdate|executeLargeUpdate|addBatch|createQuery|createNativeQuery|createSQLQuery|createSqlQuery|nativeQuery|queryForObject|queryForList|queryForMap|queryForRowSet|batchUpdate)\s*\('''),
    ("sql.jvm.concat", "sink", "sql", "CWE-89", 3.0, "jvm",
     r'''\.(?:executeQuery|executeUpdate|execute|createQuery|createNativeQuery|prepareStatement|query|queryForObject|queryForList|update)\s*\(\s*(?:"[^"]*"\s*\+|[a-z]\w*\s*\+|String\.format)'''),
    ("sql.cs.api", "sink", "sql", "CWE-89", 1.5, "cs",
     r'''\bnew\s+(?:SqlCommand|OleDbCommand|OdbcCommand|NpgsqlCommand|MySqlCommand|SqliteCommand|SQLiteCommand|OracleCommand)\s*\(|\.(?:FromSqlRaw|ExecuteSqlRaw|ExecuteSqlRawAsync|FromSqlInterpolated|ExecuteSqlCommand|SqlQuery|SqlQueryRaw)\s*\(|\.CommandText\s*='''),
    ("sql.rb.api", "sink", "sql", "CWE-89", 1.5, "rb",
     r'''\.(?:find_by_sql|count_by_sql|exec_query|exec_update|exec_delete|exec_insert|select_all|select_one|select_value|select_values|select_rows|execute)\s*\(|\bArel\.sql\s*\('''),
    ("sql.rb.interp", "sink", "sql", "CWE-89", 3.0, "rb",
     r'''\.(?:where|order|reorder|group|having|pluck|select|joins|from|lock|calculate|exists\?|find_by|update_all|delete_all|destroy_all)\s*\(?\s*"[^"]*#\{'''),
    ("sql.ex", "sink", "sql", "CWE-89", 2.0, "ex",
     r'''\bEcto\.Adapters\.SQL\.query!?\s*\(|\bRepo\.query!?\s*\(|\bfragment\s*\(\s*"[^"]*#\{|\bPostgrex\.query!?\s*\('''),
    ("sql.rs", "sink", "sql", "CWE-89", 2.0, "rs",
     r'''\bsqlx::query(?:_as|_scalar)?\s*\(\s*&?(?:format!|[a-z_]\w*\s*[,)])|\.execute\s*\(\s*&?format!|\bsql_query\s*\(\s*&?format!'''),
    ("sql.c", "sink", "sql", "CWE-89", 1.5, "c",
     r'''\bsqlite3_(?:exec|prepare|prepare_v2|prepare_v3|mprintf|vmprintf)\s*\(|\b(?:mysql_query|mysql_real_query|PQexec|PQexecParams|PQsendQuery|SQLExecDirect\w*)\s*\('''),
    ("sql.nosql", "sink", "nosql", "CWE-943", 2.5, "any",
     r'''['"]\$where['"]|\$where\s*:|\bmapReduce\s*\(|['"]\$(?:regex|expr|function|accumulator)['"]'''),
    ("sql.nosql_find", "sink", "nosql", "CWE-943", 2.5, "any",
     r'''\.(?:find|findOne|find_one|findOneAndUpdate|findOneAndDelete|updateOne|update_one|updateMany|update_many|deleteOne|delete_one|deleteMany|delete_many|aggregate|countDocuments|count_documents|distinct)\s*\(\s*(?:req\.|request\.|ctx\.|params|body|query|json\.loads|JSON\.parse|\$_)'''),

    # Paths, files, archives, uploads
    ("path.py.open", "sink", "path", "CWE-22", 1.5, "py",
     r'''(?:^|[^.\w])open\s*\(\s*(?:os\.path\.join|f["']|[a-z_][\w.]*\s*[+%]|request\.|self\.\w*path|\w*path\w*\s*[,)]|\w*file\w*\s*[,)]|\w*name\w*\s*[,)])'''),
    ("path.py.send", "sink", "path", "CWE-22", 2.5, "py",
     r'''\b(?:send_file|send_from_directory|FileResponse|static_file|FileWrapper)\s*\('''),
    ("path.py.fsops", "sink", "path", "CWE-22", 1.2, "py",
     r'''\b(?:shutil\.(?:copy|copy2|copyfile|copytree|move|rmtree)|os\.(?:remove|unlink|rmdir|removedirs|rename|renames|replace|makedirs|mkdir|chmod|chown|lchown|symlink|link|listdir|scandir|walk|open)|pathlib\.Path)\s*\('''),
    ("path.py.pathlib", "sink", "path", "CWE-22", 1.0, "py",
     r'''\.(?:write_text|write_bytes|read_text|read_bytes|unlink|rmdir|symlink_to|hardlink_to|mkdir|touch)\s*\('''),
    ("path.py.join", "sink", "path", "CWE-22", 0.7, "py",
     r'''\bos\.path\.(?:join|abspath|realpath|normpath|expanduser|commonpath|commonprefix)\s*\('''),
    ("path.py.archive", "sink", "archive", "CWE-22", 2.5, "py",
     r'''\btarfile\.open\s*\(|\bzipfile\.ZipFile\s*\(|\.extractall\s*\(|\.extract\s*\(|\bshutil\.unpack_archive\s*\(|\bpy7zr\b|\brarfile\b'''),
    ("path.py.upload", "sink", "upload", "CWE-434", 2.0, "py",
     r'''\brequest\.files\b|\bUploadFile\b|\bFileStorage\b|\.save\s*\(\s*os\.path\.join|\bsecure_filename\s*\(|\bInMemoryUploadedFile\b|\bdefault_storage\.save\s*\('''),
    ("path.js.fs", "sink", "path", "CWE-22", 1.3, "js",
     r'''\b(?:fs|fse|fsp|fsPromises|fsExtra)(?:\.promises)?\.(?:readFile|readFileSync|writeFile|writeFileSync|appendFile|appendFileSync|createReadStream|createWriteStream|unlink|unlinkSync|rm|rmSync|rmdir|rmdirSync|rename|renameSync|mkdir|mkdirSync|copyFile|copyFileSync|cp|cpSync|readdir|readdirSync|open|openSync|symlink|symlinkSync|link|linkSync|outputFile|copy|move|remove|ensureDir|emptyDir|realpath|realpathSync)\s*\('''),
    ("path.js.path", "sink", "path", "CWE-22", 0.7, "js", r'''\bpath\.(?:join|resolve|normalize|relative)\s*\('''),
    ("path.js.send", "sink", "path", "CWE-22", 2.5, "js",
     r'''\.(?:sendFile|download|sendfile|attachment)\s*\(|\bexpress\.static\s*\(|\bserveStatic\s*\(|\bsend\s*\(\s*req\s*,'''),
    ("path.js.archive", "sink", "archive", "CWE-22", 2.5, "js",
     r'''\b(?:unzipper|AdmZip|extract-zip|yauzl|jszip|JSZip|tar-fs|tar-stream|unzipStream|decompress)\b|\btar\.(?:x|extract|t|list)\s*\(|\.extractAllTo\s*\(|\.extractEntryTo\s*\('''),
    ("path.js.upload", "sink", "upload", "CWE-434", 2.0, "js",
     r'''\bmulter\s*\(|\bformidable\b|\bbusboy\b|\bBusboy\b|\.mv\s*\(|\breq\.files?\b|\bupload\.(?:single|array|fields|any)\s*\('''),
    ("path.php.read", "sink", "path", "CWE-22", 1.5, "php",
     r'''\b(?:file_get_contents|file_put_contents|fopen|readfile|file|fpassthru|parse_ini_file|highlight_file|show_source|gzopen|bzopen|opendir|scandir|glob|is_file|is_dir|file_exists|filesize|filemtime|touch|tempnam)\s*\(\s*(?:\$|[^)'"]*\.\s*\$)|\bnew\s+(?:SplFileObject|SplFileInfo|DirectoryIterator|RecursiveDirectoryIterator)\s*\('''),
    ("path.php.write", "sink", "path", "CWE-22", 1.8, "php",
     r'''\b(?:unlink|rmdir|mkdir|rename|copy|symlink|link|chmod|chown|chgrp|file_put_contents|fwrite|fputs)\s*\('''),
    ("path.php.upload", "sink", "upload", "CWE-434", 2.5, "php",
     r'''\$_FILES\b|\bmove_uploaded_file\s*\(|->(?:getClientOriginalName|getClientOriginalExtension|getClientMimeType|storeAs|storePubliclyAs|hashName|getMimeType|guessExtension)\s*\(|\bUploadedFile\b|\bwp_handle_upload\s*\('''),
    ("path.php.archive", "sink", "archive", "CWE-22", 2.5, "php",
     r'''\bZipArchive\b|\bPharData\b|->extractTo\s*\(|phar://|\bnew\s+Phar\s*\(|\bunzip_file\s*\(|\bgzinflate\s*\(|\bgzuncompress\s*\('''),
    ("path.go.os", "sink", "path", "CWE-22", 1.3, "go",
     r'''\b(?:os\.(?:Open|OpenFile|Create|ReadFile|WriteFile|Remove|RemoveAll|Rename|Mkdir|MkdirAll|Symlink|Link|Chmod|Chown|Lchown|ReadDir|Truncate|OpenRoot|DirFS|CopyFS)|ioutil\.(?:ReadFile|WriteFile|ReadDir))\s*\('''),
    ("path.go.join", "sink", "path", "CWE-22", 0.7, "go", r'''\b(?:filepath|path)\.(?:Join|Clean|Abs|Rel|EvalSymlinks)\s*\('''),
    ("path.go.serve", "sink", "path", "CWE-22", 2.5, "go",
     r'''\bhttp\.(?:ServeFile|ServeContent|FileServer|Dir|ServeFileFS|FileServerFS)\b|\bc\.(?:File|FileAttachment|Attachment|SendFile|Download)\s*\(|\.Static\s*\('''),
    ("path.go.archive", "sink", "archive", "CWE-22", 2.5, "go",
     r'''\b(?:zip\.(?:OpenReader|NewReader)|tar\.NewReader|gzip\.NewReader|zlib\.NewReader|flate\.NewReader|bzip2\.NewReader|xz\.NewReader|zstd\.NewReader)\s*\('''),
    ("path.go.upload", "sink", "upload", "CWE-434", 2.0, "go", r'''\.FormFile\s*\(|\bmultipart\.(?:FileHeader|NewReader)\b|\.SaveUploadedFile\s*\('''),
    ("path.jvm.file", "sink", "path", "CWE-22", 1.5, "jvm",
     r'''\bnew\s+(?:File|FileInputStream|FileOutputStream|FileReader|FileWriter|RandomAccessFile|PrintWriter|ZipFile|JarFile)\s*\('''),
    ("path.jvm.nio", "sink", "path", "CWE-22", 1.2, "jvm",
     r'''\b(?:Paths\.get|Path\.of|Files\.(?:newInputStream|newOutputStream|newBufferedReader|newBufferedWriter|readAllBytes|readAllLines|readString|write|writeString|copy|move|delete|deleteIfExists|createFile|createDirectory|createDirectories|createSymbolicLink|createLink|walk|list|lines|newByteChannel))\s*\(|\.resolve\s*\(\s*[a-z]'''),
    ("path.jvm.serve", "sink", "path", "CWE-22", 2.0, "jvm",
     r'''\bResourceUtils\.getFile\s*\(|\bnew\s+FileSystemResource\s*\(|\bnew\s+UrlResource\s*\(|\.getResource(?:AsStream)?\s*\(\s*[a-z]|\.getRealPath\s*\('''),
    ("path.jvm.archive", "sink", "archive", "CWE-22", 2.5, "jvm",
     r'''\b(?:ZipInputStream|JarInputStream|TarArchiveInputStream|ZipArchiveInputStream|ArchiveStreamFactory|SevenZFile)\b|\.getNextEntry\s*\(|\.getNextTarEntry\s*\(|\.getNextZipEntry\s*\('''),
    ("path.jvm.upload", "sink", "upload", "CWE-434", 2.0, "jvm",
     r'''\bMultipartFile\b|\.transferTo\s*\(|\.getOriginalFilename\s*\(|\bFileItem\b|\bServletFileUpload\b|\.getSubmittedFileName\s*\('''),
    ("path.c.fs", "sink", "path", "CWE-22", 0.8, "c",
     r'''\b(?:fopen|fopen64|open|open64|openat|creat|freopen|unlink|unlinkat|remove|rename|renameat|mkdir|mkdirat|rmdir|chmod|fchmodat|chown|lchown|fchownat|symlink|symlinkat|link|linkat|realpath|opendir|truncate|mknod|mkfifo|vn_open|vn_openat|lookupname|lookuppn|lookupnameat|namei|kern_path|filp_open)\s*\('''),
    ("path.cs", "sink", "path", "CWE-22", 1.5, "cs",
     r'''\b(?:File\.(?:ReadAllText|ReadAllBytes|ReadAllLines|ReadLines|WriteAllText|WriteAllBytes|WriteAllLines|AppendAllText|Open|OpenRead|OpenWrite|OpenText|Create|CreateText|Delete|Copy|Move|Replace|Exists)|Directory\.(?:Delete|CreateDirectory|GetFiles|GetDirectories|Move|EnumerateFiles|Exists)|Path\.(?:Combine|GetFullPath|Join)|new\s+(?:FileStream|StreamReader|StreamWriter|FileInfo|DirectoryInfo))\s*\('''),
    ("path.cs.serve", "sink", "path", "CWE-22", 2.0, "cs",
     r'''\b(?:PhysicalFile|File)\s*\(\s*[a-z]|\bPhysicalFileProvider\b|\bIFormFile\b|\.CopyToAsync\s*\(|\bZipFile\.ExtractToDirectory\b|\.ExtractToFile\s*\(|\bZipArchive\b'''),
    ("path.rb", "sink", "path", "CWE-22", 1.5, "rb",
     r'''\b(?:File\.(?:open|read|write|binread|binwrite|readlines|foreach|new|delete|unlink|rename|symlink|link|chmod|chown|expand_path|join|absolute_path|realpath)|FileUtils\.\w+|IO\.(?:read|write|readlines|binread|binwrite|copy_stream|foreach)|Dir\.(?:glob|entries|children|each_child|mkdir|rmdir|chdir)|Pathname\.new)\b'''),
    ("path.rb.send", "sink", "path", "CWE-22", 2.5, "rb",
     r'''\bsend_file\b|\bsend_data\b|\bZip::File\b|\bZip::InputStream\b|\bGem::Package\b|\bArchive::Tar\b|\bMinitar\b'''),
    ("path.rs", "sink", "path", "CWE-22", 1.3, "rs",
     r'''\b(?:fs::(?:read|read_to_string|write|remove_file|remove_dir|remove_dir_all|create_dir|create_dir_all|rename|copy|read_dir|canonicalize|symlink_metadata|hard_link|set_permissions)|File::(?:open|create|options)|OpenOptions::new)\s*\('''),
    ("path.rs.archive", "sink", "archive", "CWE-22", 2.5, "rs",
     r'''\bzip::ZipArchive\b|\btar::Archive\b|\.unpack_in\s*\(|\.enclosed_name\s*\(|\.mangled_name\s*\('''),
    ("path.ex", "sink", "path", "CWE-22", 1.3, "ex",
     r'''\bFile\.(?:read|write|rm|rm_rf|cp|cp_r|rename|mkdir|mkdir_p|open|stream!|ls|ln_s|exists\?|regular\?|dir\?)\b|\bPath\.(?:join|expand|safe_relative|safe_relative_to|wildcard|absname)\s*\('''),
    ("path.ex.serve", "sink", "path", "CWE-22", 2.5, "ex",
     r'''\bsend_file\s*\(|\bsend_download\s*\(|\bPlug\.Static\b|\bPlug\.Upload\b|:zip\.(?:unzip|extract|zip|create)\b|:erl_tar\.(?:extract|create)\b'''),
    ("path.erl", "sink", "path", "CWE-22", 1.3, "erl",
     r'''\bfile:(?:read_file|write_file|open|delete|rename|make_dir|del_dir|del_dir_r|list_dir|read_link|make_symlink|consult|copy)\s*\(|\bfilename:(?:join|absname|safe_relative_path)\s*\(|\bzip:(?:unzip|extract)\s*\(|\berl_tar:extract\s*\('''),
    ("path.pl", "sink", "path", "CWE-22", 1.3, "pl", r'''\b(?:open|sysopen|unlink|rename|mkdir|rmdir|opendir|chmod|chown|symlink|link)\s*[( ]'''),
    ("path.clj", "sink", "path", "CWE-22", 1.3, "clj",
     r'''\((?:slurp|spit|io/file|clojure\.java\.io/file|io/input-stream|io/output-stream|io/reader|io/writer|io/copy|io/delete-file|io/resource)\s'''),
    ("path.lua", "sink", "path", "CWE-22", 1.3, "lua", r'''\bio\.(?:open|lines|input|output)\s*\(|\bos\.(?:remove|rename|tmpname)\s*\('''),
    ("path.swift", "sink", "path", "CWE-22", 1.3, "swift",
     r'''\bFileManager\b|\bURL\s*\(\s*fileURLWithPath:|\bFileHandle\b|\.appendingPathComponent\s*\(|contentsOfFile:'''),
    ("path.dotdot", "sink", "path", "CWE-22", 0.8, "any", r'''['"]\.\.[/\\]?['"]|\.\./'''),
    ("path.check", "sink", "path", "CWE-22", 1.0, "any",
     r'''\.(?:startswith|startsWith|HasPrefix|starts_with)\s*\(\s*[a-z_$]|\bstrings\.HasPrefix\s*\(|\bis_relative_to\s*\(|\bsafe_join\s*\(|\bsecure_join\b|\bSecureJoin\b|\bfilepath\.IsLocal\s*\(|\bisabs\s*\(|\bIsAbs\s*\('''),

    # Deserialization
    ("deser.py", "sink", "deser", "CWE-502", 3.0, "py",
     r'''\b(?:pickle|cPickle|_pickle|dill|shelve|marshal|jsonpickle|cloudpickle)\.(?:loads?|Unpickler|open|decode)\b|\bread_pickle\b|\bjoblib\.load\b|\btorch\.load\s*\(|\bnp\.load\s*\(|\bnumpy\.load\s*\('''),
    ("deser.py.yaml", "sink", "deser", "CWE-502", 2.5, "py",
     r'''\byaml\.(?:load|load_all|unsafe_load|unsafe_load_all|full_load|full_load_all)\s*\(|\bLoader\s*=\s*yaml\.(?:Loader|UnsafeLoader|FullLoader)\b'''),
    ("deser.js", "sink", "deser", "CWE-502", 2.5, "js",
     r'''\b(?:node-serialize|serialize-javascript|funcster|cryo)\b|\bunserialize\s*\(|\bv8\.deserialize\s*\(|\byaml\.load\s*\(|\.unflatten\s*\(|\bdevalue\b|\bflatted\b|\bBSON\.deserialize\b'''),
    ("deser.js.json", "sink", "deser", "CWE-502", 0.6, "js", r'''\bJSON\.parse\s*\('''),
    ("deser.php", "sink", "deser", "CWE-502", 3.0, "php",
     r'''\b(?:unserialize|maybe_unserialize|igbinary_unserialize|msgpack_unpack|yaml_parse|yaml_parse_file)\s*\(|\b__wakeup\b|\b__unserialize\b'''),
    ("deser.go", "sink", "deser", "CWE-502", 1.0, "go",
     r'''\bgob\.NewDecoder\s*\(|\b(?:yaml|json|xml|toml|msgpack|proto|cbor|bson|gob|protojson)\.(?:Unmarshal|NewDecoder)\s*\('''),
    ("deser.jvm", "sink", "deser", "CWE-502", 3.0, "jvm",
     r'''\bObjectInputStream\b|\.readObject\s*\(|\.readUnshared\s*\(|\bXMLDecoder\b|\bXStream\b|\benableDefaultTyping\s*\(|\bactivateDefaultTyping\s*\(|\bSerializationUtils\.deserialize\b|\bKryo\b|\bHessian2?Input\b|\bBurlapInput\b|\bnew\s+Yaml\s*\(|\.loadAs\s*\(|\bJSON\.parseObject\s*\(|\bJsonTypeInfo\.Id\.CLASS\b'''),
    ("deser.jvm.json", "sink", "deser", "CWE-502", 0.8, "jvm", r'''\.readValue\s*\(|\.fromJson\s*\(|\.readTree\s*\('''),
    ("deser.cs", "sink", "deser", "CWE-502", 3.0, "cs",
     r'''\b(?:BinaryFormatter|SoapFormatter|NetDataContractSerializer|ObjectStateFormatter|LosFormatter|JavaScriptSerializer|SimpleTypeResolver|XamlReader|BinaryMessageFormatter)\b|\bTypeNameHandling\.(?:All|Auto|Objects|Arrays)\b'''),
    ("deser.cs.json", "sink", "deser", "CWE-502", 0.8, "cs",
     r'''\bJsonConvert\.DeserializeObject\b|\bJsonSerializer\.Deserialize\b|\bDataContractSerializer\b|\bXmlSerializer\b'''),
    ("deser.rb", "sink", "deser", "CWE-502", 3.0, "rb",
     r'''\bMarshal\.(?:load|restore)\b|\bYAML\.(?:load|unsafe_load|load_file|load_stream|unsafe_load_file)\b|\bPsych\.(?:load|unsafe_load|load_file)\b|\bOj\.(?:load|object_load)\b|\bJSON\.load\b|\bOx\.load\b'''),
    ("deser.ex", "sink", "deser", "CWE-502", 3.0, "ex erl", r'''\bbinary_to_term\s*\('''),
    ("deser.rs", "sink", "deser", "CWE-502", 1.0, "rs",
     r'''\bbincode::(?:deserialize|decode_from_slice)\b|\bserde_pickle\b|\brmp_serde::(?:from_slice|from_read|decode)\b|\bserde_yaml::from_\w+'''),
    ("deser.clj", "sink", "deser", "CWE-502", 2.0, "clj", r'''\bnippy/thaw\b|\(read\s|\bclojure\.core/read\b'''),

    # XSS and template output
    ("xss.py", "sink", "xss", "CWE-79", 2.0, "py",
     r'''\b(?:mark_safe|Markup|SafeString|SafeText)\s*\(|\bautoescape\s*=\s*False\b|\|\s*safe\b|\bHttpResponse\s*\(\s*(?:f["']|[a-z_]\w*\s*[+%])|\bmake_response\s*\(\s*(?:f["']|[a-z_]\w*\s*\+)|\bHTMLResponse\s*\('''),
    ("xss.js.dom", "sink", "xss", "CWE-79", 2.5, "js",
     r'''\.(?:innerHTML|outerHTML)\s*\+?=|\binsertAdjacentHTML\s*\(|\bdocument\.write(?:ln)?\s*\(|\bdangerouslySetInnerHTML\b|\bv-html\b|\{@html\s|\[innerHTML\]|\bbypassSecurityTrust\w*\s*\(|\bcreateContextualFragment\s*\(|\bsrcdoc\b|\.html\s*\(\s*[a-z_$][\w$.]*\s*\)|\.(?:append|prepend|after|before|replaceWith|wrap)\s*\(\s*['"`]\s*<'''),
    ("xss.js.server", "sink", "xss", "CWE-79", 1.2, "js",
     r'''\b(?:res|response|reply|ctx)\.(?:send|write|end|type|body)\s*\(\s*(?:`|['"]\s*<|[a-z_$][\w$]*\s*\+)|\bctx\.body\s*=|\bnew\s+Response\s*\(\s*(?:`|[a-z_$])'''),
    ("xss.js.md", "sink", "xss", "CWE-79", 1.5, "js",
     r'''\b(?:marked|markdownIt|showdown|remarkable|micromark|rehypeRaw|allowDangerousHtml|escapeMarkup)\b|\bsanitize\s*:\s*false\b'''),
    ("xss.js.url", "sink", "xss", "CWE-79", 1.5, "js",
     r'''['"]javascript:|\.setAttribute\s*\(\s*['"](?:href|src|action|formaction|on\w+|style|srcdoc)['"]|\bhref\s*=\s*\{|:href\s*=|\[href\]\s*='''),
    ("xss.php.echo", "sink", "xss", "CWE-79", 3.0, "php", r'''\b(?:echo|print)\s*\(?\s*\$_(?:GET|POST|REQUEST|COOKIE|SERVER)'''),
    ("xss.php.out", "sink", "xss", "CWE-79", 0.8, "php", r'''\b(?:echo|print)\s+[^;'"]*\$\w+|<\?=\s*\$\w+|\bprintf\s*\(\s*\$'''),
    ("xss.raw", "sink", "xss", "CWE-79", 2.5, "php tpl", r'''\{!!|\|\s*raw\b|\bnew\s+HtmlString\b|->toHtml\s*\('''),
    ("xss.go", "sink", "xss", "CWE-79", 1.0, "go",
     r'''\bfmt\.Fprint(?:f|ln)?\s*\(\s*(?:w|rw|resp|writer)\b|\b(?:w|rw|resp|writer)\.Write\s*\(\s*\[\]byte\s*\(|\bio\.WriteString\s*\(\s*(?:w|rw)\b|\bc\.(?:HTML|String|Data)\s*\('''),
    ("xss.jvm", "sink", "xss", "CWE-79", 1.2, "jvm",
     r'''\.getWriter\s*\(\s*\)\s*\.(?:print|println|write|append)\s*\(|\bth:utext\b|\?no_esc\b|\bescapeXml\s*=\s*"false"|<%=|\bHtml\.fromHtml\s*\(|\bsetJavaScriptEnabled\s*\(\s*true|\baddJavascriptInterface\s*\(|\bevaluateJavascript\s*\(|\bloadData(?:WithBaseURL)?\s*\('''),
    ("xss.cs", "sink", "xss", "CWE-79", 2.5, "cs",
     r'''\bHtml\.Raw\s*\(|\bnew\s+HtmlString\s*\(|\bMvcHtmlString\.Create\s*\(|\bResponse\.Write\s*\(|\bMarkupString\b'''),
    ("xss.rb", "sink", "xss", "CWE-79", 2.5, "rb",
     r'''\.html_safe\b|(?:^|[^.\w])raw\s*[( ]|<%==|\bsafe_concat\b|\brender\s*\(?\s*(?:html|text|plain|inline):'''),
    ("xss.ex", "sink", "xss", "CWE-79", 2.5, "ex", r'''(?:^|[^.\w])raw\s*\(|\bPhoenix\.HTML\.raw\b|\{:safe,|\bhtml\s*\(\s*conn\s*,'''),
    ("xss.tpl", "sink", "xss", "CWE-79", 2.5, "tpl",
     r'''\|\s*safe\b|\{\{\{|<%==|<%-|\bv-html\b|\{@html\b|\bth:utext\b|\binnerHTML\b|\bautoescape\s+(?:false|off)\b'''),
    ("xss.rs", "sink", "xss", "CWE-79", 2.0, "rs",
     r'''\bHtml\s*\(\s*format!|\bPreEscaped\b|\bdangerous_inner_html\b|\.set_inner_html\s*\(|\binner_html\s*='''),
    ("xss.sanitizer", "guard", "xss", "CWE-79", 0.5, "any",
     r'''\b(?:htmlspecialchars|htmlentities|esc_html|esc_attr|esc_url|esc_js|wp_kses\w*|strip_tags|escapeHtml|escape_html|html_escape|bleach\.clean|DOMPurify\.sanitize|sanitizeHtml|sanitize_html|filterXSS|HtmlEncoder|HtmlEncode|escapeHtml4|forHtml\w*)\b'''),

    # Redirects
    ("redirect.py", "sink", "redirect", "CWE-601", 1.5, "py",
     r'''\b(?:redirect|HttpResponseRedirect|HttpResponsePermanentRedirect|RedirectResponse)\s*\('''),
    ("redirect.py.next", "sink", "redirect", "CWE-601", 2.5, "py",
     r'''\bredirect\s*\(\s*request\.|\brequest\.(?:args|GET|form|POST|query_params)\.get\s*\(\s*['"](?:next|url|redirect|return|returnTo|return_to|redirect_uri|redirect_url|continue|goto|dest|destination|target|callback)['"]'''),
    ("redirect.js", "sink", "redirect", "CWE-601", 1.5, "js",
     r'''\b(?:res|reply|ctx|response)\.redirect\s*\(|\bNextResponse\.redirect\s*\(|(?:^|[^.\w$])redirect\s*\(|\b(?:window\.)?location(?:\.href)?\s*=[^=]|\blocation\.(?:assign|replace)\s*\(|\bwindow\.open\s*\('''),
    ("redirect.php", "sink", "redirect", "CWE-601", 2.0, "php",
     r'''\bheader\s*\(\s*['"]Location\s*:|->redirect(?:To)?\s*\(\s*\$|\bwp_redirect\s*\(|\bredirect\s*\(\s*\$|\bRedirect::(?:to|away)\s*\(|->away\s*\('''),
    ("redirect.go", "sink", "redirect", "CWE-601", 1.5, "go", r'''\bhttp\.Redirect\s*\(|\bc\.Redirect\s*\('''),
    ("redirect.jvm", "sink", "redirect", "CWE-601", 1.8, "jvm",
     r'''\.sendRedirect\s*\(|"redirect:"\s*\+|\bnew\s+RedirectView\s*\(|\bHttpStatus\.(?:FOUND|SEE_OTHER|TEMPORARY_REDIRECT|MOVED_PERMANENTLY)\b'''),
    ("redirect.cs", "sink", "redirect", "CWE-601", 1.8, "cs", r'''(?:^|[^.\w])Redirect\s*\(|\.Redirect\s*\(|\bRedirectPermanent\s*\(|\bRedirectResult\s*\('''),
    ("redirect.rb", "sink", "redirect", "CWE-601", 1.5, "rb", r'''\bredirect_to\b|\bredirect_back\b|\bredirect\s*\(?\s*(?:params|request)'''),
    ("redirect.ex", "sink", "redirect", "CWE-601", 1.5, "ex", r'''\bredirect\s*\(\s*conn\s*,\s*(?:external|to):|\bpush_redirect\b|\bpush_navigate\b'''),
    ("redirect.guard", "guard", "redirect", "CWE-601", 0.6, "any",
     r'''\b(?:url_has_allowed_host_and_scheme|is_safe_url|wp_safe_redirect|IsLocalUrl|LocalRedirect|isSafeRedirect\w*|safe_redirect\w*|allowed_redirect\w*)\b'''),

    # Outbound requests (SSRF) and URL handling
    ("ssrf.py", "sink", "ssrf", "CWE-918", 1.5, "py",
     r'''\brequests\.(?:get|post|put|delete|head|patch|request|Session)\s*\(|\b(?:urllib\.request\.urlopen|urlopen|urllib2\.urlopen|urllib\.request\.Request|httpx\.(?:get|post|put|delete|request|stream|AsyncClient|Client)|aiohttp\.ClientSession|http\.client\.HTTPS?Connection|pycurl\.Curl|urllib3\.PoolManager)\b'''),
    ("ssrf.js", "sink", "ssrf", "CWE-918", 1.3, "js",
     r'''(?:^|[^.\w$])fetch\s*\(\s*[a-z_$`]|\baxios(?:\.(?:get|post|put|delete|patch|head|request|create))?\s*\(|\bhttps?\.(?:get|request)\s*\(|\b(?:got|needle|superagent)\s*\(\s*[a-z_$`{]|\bnet\.(?:connect|createConnection)\s*\('''),
    ("ssrf.php", "sink", "ssrf", "CWE-918", 1.5, "php",
     r'''\b(?:curl_init|curl_exec|curl_multi_exec|fsockopen|pfsockopen|stream_socket_client|get_headers|wp_remote_get|wp_remote_post|wp_remote_request|wp_safe_remote_get|download_url)\s*\(|\bCURLOPT_URL\b|\bnew\s+SoapClient\b|\bfile_get_contents\s*\(\s*\$\w*(?:url|uri|link|src|href)'''),
    ("ssrf.go", "sink", "ssrf", "CWE-918", 1.5, "go",
     r'''\bhttp\.(?:Get|Post|PostForm|Head|NewRequest|NewRequestWithContext)\s*\(|\.Do\s*\(\s*req\b|\bnet\.(?:Dial|DialTimeout|DialTCP|DialUDP)\s*\(|\bDialContext\s*\(|\bwebsocket\.Dial\w*\s*\(|\bgrpc\.Dial\w*\s*\('''),
    ("ssrf.jvm", "sink", "ssrf", "CWE-918", 1.5, "jvm",
     r'''\bnew\s+URL\s*\(|\.openConnection\s*\(|\.openStream\s*\(|\bHttpClient\b|\bRestTemplate\b|\bWebClient\b|\bOkHttpClient\b|\bHttpURLConnection\b|\.(?:getForObject|getForEntity|postForObject|postForEntity|exchange)\s*\(|\bJsoup\.connect\s*\(|\bHttpRequest\.newBuilder\b|\bClientBuilder\b|\bnew\s+HttpGet\s*\(|\bnew\s+HttpPost\s*\(|\bURI\.create\s*\('''),
    ("ssrf.cs", "sink", "ssrf", "CWE-918", 1.5, "cs",
     r'''\bnew\s+HttpClient\b|\.(?:GetAsync|PostAsync|PutAsync|SendAsync|GetStringAsync|GetStreamAsync|GetByteArrayAsync|DownloadString|DownloadData|DownloadFile|UploadString)\s*\(|\bWebRequest\.Create\s*\(|\bnew\s+WebClient\b'''),
    ("ssrf.rb", "sink", "ssrf", "CWE-918", 1.5, "rb", r'''\bNet::HTTP\b|\bopen-uri\b|\bURI\.open\b|\bHTTParty\b|\bFaraday\b|\bRestClient\b|\bExcon\b|\bTyphoeus\b'''),
    ("ssrf.rs", "sink", "ssrf", "CWE-918", 1.5, "rs", r'''\breqwest::\w+|\bhyper::Client\b|\bureq::\w+|\bTcpStream::connect\s*\('''),
    ("ssrf.ex", "sink", "ssrf", "CWE-918", 1.5, "ex",
     r'''\bHTTPoison\.\w+|\bTesla\.\w+|\bFinch\.\w+|\bReq\.(?:get|post|request|new)\b|:httpc\.request\b|\bMint\.HTTP\.\w+|:gen_tcp\.connect\b'''),
    ("ssrf.c", "sink", "ssrf", "CWE-918", 1.0, "c",
     r'''\bcurl_easy_(?:setopt|perform)\s*\(|\b(?:connect|getaddrinfo|gethostbyname|gethostbyname2|getnameinfo)\s*\('''),
    ("ssrf.pl", "sink", "ssrf", "CWE-918", 1.5, "pl", r'''\bLWP::\w+|\bHTTP::Tiny\b|\bIO::Socket::INET\b'''),
    ("url.parse", "sink", "ssrf", "CWE-918", 0.8, "any",
     r'''\burlparse\s*\(|\burlsplit\s*\(|\burl\.Parse\s*\(|\bnew\s+URL\s*\(|\bparse_url\s*\(|\bURI\.(?:parse|create)\s*\(|\bUri\.TryCreate\b|\bUrl::parse\s*\(|\bFILTER_VALIDATE_URL\b|\bis_private\b|\bIsPrivate\s*\(|\bIsLoopback\s*\(|\bip_address\s*\(|\binet_pton\s*\(|\bisLoopbackAddress\b|\bisSiteLocalAddress\b'''),

    # XML parsers (XXE)
    ("xxe.py", "sink", "xxe", "CWE-611", 1.5, "py",
     r'''\b(?:etree\.(?:parse|fromstring|XML|XMLParser|iterparse|XMLPullParser)|minidom\.parse(?:String)?|xml\.sax\.\w+|pulldom\.\w+|xmltodict\.parse)\s*\(|\bresolve_entities\s*=\s*True\b|\bno_network\s*=\s*False\b'''),
    ("xxe.js", "sink", "xxe", "CWE-611", 1.5, "js",
     r'''\blibxmljs\d?\b|\bnoent\s*:\s*true\b|\bxml2js\b|\bxmldom\b|\bnew\s+DOMParser\b|\bXMLParser\b|\bsax\.parser\b|\bparseXml\w*\s*\('''),
    ("xxe.php", "sink", "xxe", "CWE-611", 1.8, "php",
     r'''\b(?:simplexml_load_string|simplexml_load_file|simplexml_import_dom|xml_parse|xml_parser_create)\s*\(|\bnew\s+(?:DOMDocument|SimpleXMLElement|XMLReader)\b|->(?:loadXML|loadHTML)\s*\(|\bLIBXML_NOENT\b|\bLIBXML_DTDLOAD\b'''),
    ("xxe.go", "sink", "xxe", "CWE-611", 0.8, "go", r'''\bxml\.(?:NewDecoder|Unmarshal)\s*\(|\bxmlquery\.\w+'''),
    ("xxe.jvm", "sink", "xxe", "CWE-611", 1.8, "jvm",
     r'''\b(?:DocumentBuilderFactory|SAXParserFactory|XMLInputFactory|TransformerFactory|SAXReader|SAXBuilder|XMLReaderFactory|SchemaFactory|XPathFactory|Unmarshaller|JAXBContext|Digester)\b|\bDocumentHelper\.parseText\b'''),
    ("xxe.jvm.guard", "guard", "xxe", "CWE-611", 0.4, "jvm",
     r'''\bdisallow-doctype-decl\b|\bFEATURE_SECURE_PROCESSING\b|\bACCESS_EXTERNAL_(?:DTD|SCHEMA|STYLESHEET)\b|\bsetExpandEntityReferences\s*\(\s*false|\bexternal-general-entities\b|\bSUPPORT_DTD\b|\bIS_SUPPORTING_EXTERNAL_ENTITIES\b'''),
    ("xxe.cs", "sink", "xxe", "CWE-611", 1.8, "cs",
     r'''\bXmlDocument\b|\bXmlReader\.Create\b|\bXmlTextReader\b|\bDtdProcessing\.Parse\b|\bXmlResolver\b|\bXPathDocument\b|\bXmlUrlResolver\b|\bXslCompiledTransform\b'''),
    ("xxe.rb", "sink", "xxe", "CWE-611", 1.8, "rb",
     r'''\bNokogiri::XML\b|\bREXML::Document\b|\bLibXML::XML\b|\bOx\.parse\b|\bNOENT\b|\bXmlSimple\b|\bHash\.from_xml\b'''),
    ("xxe.c", "sink", "xxe", "CWE-611", 1.5, "c",
     r'''\b(?:xmlReadMemory|xmlReadFile|xmlReadDoc|xmlParseMemory|xmlParseFile|xmlParseDoc|xmlCtxtReadMemory|xmlCtxtUseOptions|htmlReadMemory|XML_ParserCreate|XML_Parse)\s*\(|\bXML_PARSE_NOENT\b|\bXML_PARSE_DTDLOAD\b'''),
    ("xxe.ex", "sink", "xxe", "CWE-611", 1.5, "ex erl", r''':xmerl_scan\.\w+|\bxmerl_scan:\w+|\bSweetXml\.\w+|\bSaxy\.\w+'''),

    # Randomness, hashes, ciphers, TLS
    ("rand.py", "sink", "random", "CWE-338", 1.0, "py",
     r'''\brandom\.(?:random|randint|choice|choices|randrange|shuffle|getrandbits|sample|uniform|seed)\s*\(|\buuid\.uuid1\s*\('''),
    ("rand.js", "sink", "random", "CWE-338", 1.0, "js", r'''\bMath\.random\s*\('''),
    ("rand.php", "sink", "random", "CWE-338", 1.0, "php",
     r'''\b(?:rand|mt_rand|srand|mt_srand|uniqid|lcg_value|array_rand|str_shuffle|shuffle)\s*\('''),
    ("rand.go", "sink", "random", "CWE-338", 1.0, "go",
     r'''"math/rand(?:/v2)?"|\brand\.(?:Int|Intn|Int31|Int31n|Int63|Int63n|Float64|Float32|Seed|Perm|Shuffle|Uint32|Uint64|N|IntN)\s*\('''),
    ("rand.jvm", "sink", "random", "CWE-338", 1.0, "jvm",
     r'''\bnew\s+Random\s*\(|\bMath\.random\s*\(|\bThreadLocalRandom\b|\bRandomStringUtils\.random\w*\s*\(|\bRandom\.Default\b'''),
    ("rand.c", "sink", "random", "CWE-338", 0.8, "c", r'''\b(?:rand|random|srand|srandom|drand48|erand48|lrand48|nrand48|mrand48|rand_r)\s*\('''),
    ("rand.cs", "sink", "random", "CWE-338", 1.0, "cs", r'''\bnew\s+Random\s*\(|\bRandom\.Shared\b'''),
    ("rand.rb", "sink", "random", "CWE-338", 0.8, "rb", r'''(?:^|[^.\w])(?:rand|srand)\s*[( ]|\bRandom\.(?:rand|new)\b|\bKernel\.rand\b'''),
    ("rand.ex", "sink", "random", "CWE-338", 1.0, "ex erl", r''':rand\.(?:uniform|seed)\b|\bEnum\.random\s*\(|\brand:uniform\b|:random\.uniform\b'''),
    ("rand.rs", "sink", "random", "CWE-338", 0.6, "rs", r'''\brand::(?:thread_rng|random)\b|\bSmallRng\b|\bseed_from_u64\b'''),
    ("hash.weak", "sink", "crypto", "CWE-328", 0.6, "any", r'''(?i:\b(?:md5|md4|sha1|crc32|ripemd160)\b)'''),
    ("cipher.weak", "sink", "crypto", "CWE-327", 1.5, "any",
     r'''\b(?:DES|3DES|DESede|TripleDES|RC2|RC4|ARC4|Blowfish)\b|\bECB\b|\bMODE_ECB\b|\bCipherMode\.ECB\b|(?i:aes-\d+-ecb)|/ECB/|\bPKCS1v15\b|\bRSA_PKCS1_PADDING\b'''),
    ("crypto.iv", "sink", "crypto", "CWE-329", 1.0, "any",
     r'''(?i:\b(?:iv|nonce|salt)\s*=\s*(?:b?['"][^'"]*['"]|bytes\s*\(\s*\d+\s*\)|new\s+byte\s*\[\s*\d+\s*\]))'''),
    ("tls.verify", "sink", "tls", "CWE-295", 2.5, "any",
     r'''\bverify\s*=\s*False\b|\bCERT_NONE\b|\bcheck_hostname\s*=\s*False\b|\b_create_unverified_context\b|\brejectUnauthorized\s*:\s*false\b|\bNODE_TLS_REJECT_UNAUTHORIZED\b|\bInsecureSkipVerify\s*:\s*true\b|\bCURLOPT_SSL_VERIFYPEER\s*,\s*(?:false|0)\b|\bCURLOPT_SSL_VERIFYHOST\s*,\s*(?:false|0)\b|\bSSL_VERIFY_NONE\b|\bVERIFY_NONE\b|\bverify_mode\s*=|\bdanger_accept_invalid_certs\b|\bdanger_accept_invalid_hostnames\b|\bTrustAllCerts?\b|\bALLOW_ALL_HOSTNAME_VERIFIER\b|\bNoopHostnameVerifier\b|\bServerCertificateCustomValidationCallback\b|\bServerCertificateValidationCallback\b|\bDangerousAcceptAnyServerCertificateValidator\b|\bverify_none\b'''),
    ("tls.check", "sink", "tls", "CWE-295", 1.2, "any",
     r'''\b(?:X509_verify_cert|SSL_get_verify_result|SSL_CTX_set_verify|SSL_set_verify|X509_STORE_CTX_\w+|X509_check_host|X509_VERIFY_PARAM_\w+|checkServerTrusted|checkClientTrusted|HostnameVerifier|X509TrustManager|getPeerCertificate|verify_callback|wolfSSL_CTX_set_verify|wolfSSL_X509_\w+|mbedtls_x509_crt_verify\w*|gnutls_certificate_verify_peers\w*|ParseCertificate|VerifyOptions|VerifyPeerCertificate|VerifyHostname|ProcessPeerCerts|DoCertificate\w*|ParseCertRelative|ConfirmSignature|CheckCertSignature\w*)\b'''),
    ("crypto.compare", "sink", "authn", "CWE-208", 1.2, "any",
     r'''(?i:\b\w*(?:token|signature|digest|hmac|secret|password|passwd|api_?key|otp|nonce|csrf)\w*\s*(?:===?|!==?)\s*[\w$.\[\]'"]+|\bmemcmp\s*\([^;]*(?:mac|tag|digest|hmac|signature|sig|hash|token|auth))'''),
    ("jwt.weak", "sink", "authn", "CWE-347", 2.0, "any",
     r'''(?i:\balgorithms?\s*[:=]\s*\[?\s*['"]none['"]|\bverify_signature['"]?\s*:\s*False|\bignoreExpiration\s*:\s*true|\bSkipClaimsValidation\b|\bParseUnverified\b|\bjwt\.decode\s*\(|\bjwt_decode\s*\(|\bdecode_complete\b|\binsecure_decode\b|\bdangerous_insecure_decode\w*)'''),

    # Memory safety (C, C++, Rust, Go, C#)
    ("mem.unsafe_copy", "sink", "mem", "CWE-120", 2.0, "c",
     r'''\b(?:strcpy|strcat|sprintf|vsprintf|gets|stpcpy|wcscpy|wcscat|lstrcpy[AW]?|lstrcat[AW]?|StrCpy\w*|StrCat\w*|_mbscpy|_mbscat|swprintf)\s*\('''),
    ("mem.copy", "sink", "mem", "CWE-787", 1.5, "c",
     r'''\b(?:memcpy|memmove|wmemcpy|wmemmove|bcopy|CopyMemory|RtlCopyMemory|MoveMemory|memcpy_s|memmove_s|__builtin_memcpy|ovbcopy|XMEMCPY|XMEMMOVE)\s*\('''),
    ("mem.bounded_copy", "sink", "mem", "CWE-787", 1.0, "c",
     r'''\b(?:strncpy|strncat|snprintf|vsnprintf|strlcpy|strlcat|wcsncpy|wcsncat|strncpy_s|strcpy_s|strcat_s|sprintf_s|g_strlcpy|g_snprintf|XSTRNCPY|XSNPRINTF)\s*\('''),
    ("mem.alloc_arith", "sink", "intovf", "CWE-190", 2.0, "c",
     r'''\b(?:malloc|calloc|realloc|reallocarray|alloca|kmalloc|kzalloc|kcalloc|vmalloc|vzalloc|kvmalloc|kmem_alloc|kmem_zalloc|g_malloc|g_malloc0|g_realloc|xmalloc|xcalloc|xrealloc|emalloc|ecalloc|erealloc|av_malloc|av_mallocz|OPENSSL_malloc|XMALLOC|XREALLOC|umem_alloc|umem_zalloc)\s*\([^;]*[*+]'''),
    ("mem.alloc", "sink", "mem", "CWE-789", 0.7, "c",
     r'''\b(?:malloc|calloc|realloc|reallocarray|alloca|kmalloc|kzalloc|kcalloc|vmalloc|kmem_alloc|kmem_zalloc|g_malloc|g_malloc0|xmalloc|emalloc|umem_alloc|umem_zalloc|OPENSSL_malloc|XMALLOC)\s*\('''),
    ("mem.free", "sink", "free", "CWE-416", 0.8, "c",
     r'''\b(?:free|kfree|kvfree|vfree|kmem_free|umem_free|g_free|xfree|efree|av_free|av_freep|OPENSSL_free|XFREE|kmem_cache_free|freemsg|freeb)\s*\('''),
    ("mem.release", "sink", "free", "CWE-416", 0.5, "c", r'''\b\w+_(?:free|release|destroy|put|unref|decref|rele)\s*\('''),
    ("mem.delete", "sink", "free", "CWE-416", 0.8, "c", r'''(?:^|[^.\w])delete\s*(?:\[\s*\])?\s*[A-Za-z_(*]'''),
    ("mem.scanf", "sink", "mem", "CWE-120", 1.5, "c", r'''\b(?:sscanf|fscanf|scanf|vsscanf|vfscanf|swscanf)\s*\('''),
    ("mem.format1", "sink", "format", "CWE-134", 2.0, "c", r'''\b(?:printf|vprintf|NSLog|warn|warnx|panic)\s*\(\s*[a-z_]\w*\s*[,)]'''),
    ("mem.format2", "sink", "format", "CWE-134", 2.0, "c",
     r'''\b(?:fprintf|vfprintf|dprintf|syslog|vsyslog|cmn_err|err|errx|sprintf|vsprintf)\s*\(\s*[\w.>-]+\s*,\s*[a-z_]\w*\s*[,)]'''),
    ("mem.index", "sink", "mem", "CWE-129", 0.6, "c",
     r'''\w\s*\[\s*[a-z_]\w*(?:len|length|size|count|cnt|num|idx|index|offset|off|pos)\w*\s*(?:[-+]\s*\w+\s*)?\]'''),
    ("mem.assert", "sink", "assert", "CWE-617", 0.4, "c",
     r'''\b(?:assert|ASSERT|ASSERT3U|ASSERT3S|ASSERT3P|ASSERT0|VERIFY|VERIFY0|VERIFY3U|VERIFY3S|VERIFY3P|BUG_ON|WARN_ON|g_assert|g_assert_not_reached|DCHECK|CHECK|CHECK_EQ|CHECK_LT|CHECK_LE|CHECK_GT|CHECK_GE|NOTREACHED|GGML_ASSERT|GGML_ABORT)\s*\('''),
    ("mem.cast", "sink", "mem", "CWE-704", 0.4, "c",
     r'''\breinterpret_cast\s*<|\bconst_cast\s*<|\bstatic_cast\s*<\s*(?:u?int\d*_t|size_t|unsigned|int|short|char)\b'''),
    ("mem.cpp_raw", "sink", "mem", "CWE-787", 0.6, "c",
     r'''\.data\s*\(\s*\)\s*\+|\bnew\s+\w+\s*\[|\bstd::(?:copy|memcpy|fill_n|copy_n)\s*\(|\.resize\s*\(\s*[a-z]'''),
    ("mem.cpp_life", "sink", "free", "CWE-416", 0.5, "c",
     r'''\bstd::move\s*\(|\.release\s*\(\s*\)|\.reset\s*\(|\bweak_ptr\b|\.erase\s*\(|\.clear\s*\(\s*\)'''),
    ("mem.rust", "sink", "mem", "CWE-119", 1.5, "rs",
     r'''\b(?:from_raw_parts|from_raw_parts_mut|transmute|transmute_copy|get_unchecked|get_unchecked_mut|set_len|copy_nonoverlapping|from_utf8_unchecked|assume_init|zeroed|uninitialized|read_unaligned|write_unaligned|from_raw)\s*[(:<]'''),
    ("mem.rust_unsafe", "sink", "mem", "CWE-119", 1.0, "rs", r'''\bunsafe\s*\{|\bunsafe\s+fn\b|\bunsafe\s+impl\b'''),
    ("mem.rust_panic", "sink", "dos", "CWE-248", 0.3, "rs",
     r'''\.unwrap\s*\(\s*\)|\.expect\s*\(|\bpanic!\s*\(|\bunreachable!\s*\(|\bas\s+(?:u8|u16|u32|i8|i16|i32|usize|isize)\b'''),
    ("mem.go_unsafe", "sink", "mem", "CWE-119", 1.5, "go",
     r'''\bunsafe\.(?:Pointer|Slice|String|StringData|SliceData|Add)\b|\breflect\.SliceHeader\b|\breflect\.StringHeader\b'''),
    ("mem.go_index", "sink", "mem", "CWE-129", 0.5, "go",
     r'''\w\[\s*[a-z_]\w*\s*(?:[-+]\s*\w+\s*)?:\s*[a-z_]?\w*\s*(?:[-+]\s*\w+\s*)?\]|\w\[\s*[a-z_]\w*\s*[-+]\s*\d+\s*\]'''),
    ("mem.cs", "sink", "mem", "CWE-119", 1.5, "cs",
     r'''\bunsafe\s*\{|\bfixed\s*\(|\bstackalloc\b|\bMarshal\.(?:Copy|AllocHGlobal|PtrToStructure|ReadInt\d+|WriteInt\d+|ReadByte|WriteByte)\b|\bBuffer\.(?:BlockCopy|MemoryCopy)\b'''),
    ("mem.swift", "sink", "mem", "CWE-119", 1.0, "swift",
     r'''\bUnsafe(?:Mutable)?(?:Raw)?(?:Buffer)?Pointer\b|\bwithUnsafe\w+\b|\bunsafeBitCast\b|\bassumingMemoryBound\b'''),

    # Resource limits (CWE-400, 770, 789, 835, 409)
    ("dos.alloc_var", "sink", "dos", "CWE-789", 1.0, "any",
     r'''\bnew\s+(?:byte|char|int|long|short|Array|Buffer|ArrayBuffer|Uint8Array|Uint16Array|Uint32Array|Int32Array|Float64Array)\s*[\[(]\s*[a-z_$][\w$.]*\s*[\])]|\bmake\s*\(\s*\[\]\w+\s*,\s*[a-z_]\w*|\bBuffer\.(?:alloc|allocUnsafe|allocUnsafeSlow)\s*\(\s*[a-z_$]|\bByteBuffer\.allocate(?:Direct)?\s*\(\s*[a-z_]|\bbytearray\s*\(\s*[a-z_]|\bVec::with_capacity\s*\(\s*[a-z_]|\bstr_repeat\s*\(|\.repeat\s*\(\s*[a-z_]|\barray_fill\s*\('''),
    ("dos.readall", "sink", "dos", "CWE-770", 1.2, "any",
     r'''\bio(?:util)?\.ReadAll\s*\(|\.readAllBytes\s*\(\s*\)|\bIOUtils\.(?:toByteArray|toString|readFully)\s*\(|\bstream_get_contents\s*\(|\.read_to_end\s*\(|\.read_to_string\s*\(|\.readlines\s*\(\s*\)|\.read\s*\(\s*\)|\brequest\.get_data\s*\(|\bawait\s+\w+\.(?:text|json|arrayBuffer|formData|blob)\s*\(\s*\)|\bBuffer\.concat\s*\('''),
    ("dos.decompress", "sink", "dos", "CWE-409", 1.5, "any",
     r'''\b(?:gzip|zlib|bz2|lzma|brotli|zstd|snappy|lz4)\.(?:decompress|open|GzipFile|NewReader|inflate|gunzip|unzip|inflateSync|gunzipSync|createGunzip|createInflate|createBrotliDecompress|decompressobj)\b|\b(?:GZIPInputStream|InflaterInputStream|Inflater|GzipStream|DeflateStream|BrotliStream|GzDecoder|ZlibDecoder|DeflateDecoder)\b|\b(?:inflate|inflateInit\w*|uncompress|BZ2_bzDecompress\w*|ZSTD_decompress\w*|LZ4_decompress\w*)\s*\('''),
    ("dos.loop", "sink", "loop", "CWE-835", 0.5, "any",
     r'''\bwhile\s*\(\s*(?:true|1|TRUE|B_TRUE)\s*\)|\bfor\s*\(\s*;\s*;\s*\)|\bwhile\s+True\s*:|\bloop\s*\{|\bfor\s*\{|\bwhile\s+true\b|\bloop\s+do\b'''),
    ("dos.atom", "sink", "dos", "CWE-400", 2.0, "ex erl",
     r'''\bString\.to_atom\s*\(|\bList\.to_atom\s*\(|\bbinary_to_atom\s*\(|\blist_to_atom\s*\('''),
    ("dos.limit", "guard", "dos", "CWE-770", 0.8, "any",
     r'''(?i:\b(?:max_?(?:size|length|len|count|depth|items|entries|files|body|upload|request|nesting|recursion|bytes|memory|connections|retries|iterations|attempts|redirects|fields|parts|params|headers|line|lines|chars|keys|elements|children|level|levels|nodes|width|height|pixels|frames)|size_?limit|rate_?limit\w*|ratelimit\w*|throttl\w*|limit_?bytes|body_?limit|maxBodyLength|maxContentLength|MaxBytesReader|LimitReader|LimitedReader|max_input_vars|upload_max_filesize|post_max_size|client_max_body_size|DATA_UPLOAD_MAX_\w+|FILE_UPLOAD_MAX_\w+|maxFileSize|parameterLimit|arrayLimit|depthLimit)\b)'''),
    ("dos.regex_dyn", "sink", "regex", "CWE-1333", 1.5, "any",
     r'''\bnew\s+RegExp\s*\(\s*[a-z_$]|\bRegExp\s*\(\s*[a-z_$]|\bre\.(?:compile|match|search|fullmatch|findall|finditer|sub|subn|split)\s*\(\s*[a-z_]\w*\s*[,)]|\bpreg_(?:match|match_all|replace|replace_callback|split|grep)\s*\(\s*\$|\bPattern\.compile\s*\(\s*[a-z_]|\bRegexp\.new\s*\(|\bRegex\.(?:compile|run|replace|scan|split)\s*\(\s*[a-z_]|\bnew\s+Regex\s*\(\s*[a-z_]|\bregexp\.(?:MustCompile|Compile)\s*\(\s*[a-z_]|\bRegex::new\s*\(\s*&?[a-z_]|/#\{'''),
    ("dos.regex_nested", "sink", "regex", "CWE-1333", 1.2, "any", r'''\((?:[^()\\\n]|\\.)*[+*]\)[+*\{]'''),

    # Secrets, logs, information exposure
    ("log.secret", "sink", "logsecret", "CWE-532", 1.2, "any",
     r'''(?i:\b(?:log(?:ger)?|console|logging|print|println|printf|puts|fmt\.Print\w*|System\.out\.print\w*|System\.err\.print\w*|syslog|logrus\.\w+|zap\.\w+|slog\.\w+|error_log|var_dump|print_r|IO\.inspect|Logger\.\w+|debug|info|warn|warning|error)\b[^;\n]{0,80}\b(?:password|passwd|pwd|secret|token|api_?key|private_?key|credentials?|authorization|cookie|session_?id|ssn|credit_?card|card_?number|cvv)\b)'''),
    ("secret.hardcoded", "sink", "secret", "CWE-798", 0.8, "any",
     r'''(?i:\b(?:password|passwd|secret|api_?key|private_?key|access_?key|auth_?token|client_?secret)\w*['"]?\s*[:=]\s*['"][^'"\s]{6,}['"])'''),
    ("info.debug", "sink", "infoleak", "CWE-209", 0.6, "any",
     r'''\btraceback\.print_exc\s*\(|\.printStackTrace\s*\(\s*\)|\bDEBUG\s*=\s*True\b|\bdisplay_errors\b|\bphpinfo\s*\(|\bvar_dump\s*\(|\bUseDeveloperExceptionPage\b|\berr\.stack\b|\bex\.StackTrace\b|\bgetStackTrace\s*\('''),

    # CORS, cookies, CSRF, origin checks
    ("cors", "sink", "cors", "CWE-942", 1.5, "any",
     r'''(?i:Access-Control-Allow-Origin|Access-Control-Allow-Credentials|\bCORS_ORIGIN_ALLOW_ALL\b|\bCORS_ALLOW_ALL_ORIGINS\b|\bAllowAllOrigins\b|\ballowedOrigins\b|\ballow_origins\b|\bAllowAnyOrigin\b|\bcors\s*\(|@CrossOrigin\b|\borigin\s*:\s*(?:true|['"]\*['"])|\bsupports_credentials\b)'''),
    ("cookie.flags", "sink", "cookie", "CWE-1004", 1.5, "any",
     r'''(?i:\b(?:httpOnly|http_only|secure|samesite|same_site)['"]?\s*[:=]\s*(?:false|0|none|['"]none['"]|nil|null|['"]lax['"]))|\bsetcookie\s*\(|\bsetrawcookie\s*\(|\bres\.cookie\s*\(|\bnew\s+Cookie\s*\(|\bhttp\.Cookie\s*\{|\bhttp\.SetCookie\s*\(|\bSet-Cookie\b|\bset_cookie\s*\(|\bcookies\.set\s*\(|\bResponseCookie\b|\bCookieOptions\b'''),
    ("csrf", "sink", "csrf", "CWE-352", 1.5, "any",
     r'''(?i:\bcsrf_exempt\b|\bcsrf\s*:\s*false\b|\bskip_forgery_protection\b|\bprotect_from_forgery\b|\bVerifyCsrfToken\b|\bignoringRequestMatchers\b|\bignoringAntMatchers\b|csrf\s*\(\s*\)\s*\.\s*disable|\bcsrf\.disable\b|\bCsrfViewMiddleware\b|\bcsurf\b|\bValidateAntiForgeryToken\b|\bIgnoreAntiforgeryToken\b|\bcheck_csrf\w*|\bverify_csrf\w*|\bcsrf_token\b)'''),
    ("origin.check", "sink", "origin", "CWE-346", 1.5, "any",
     r'''(?i:\b(?:origin|referer|referrer)\b[^;\n]{0,40}(?:===?|!==?|\.startswith|\.startsWith|\.endswith|\.endsWith|\.includes|\.indexOf|\.contains|\.match)|\bevent\.origin\b|\be\.origin\b|\bpostMessage\s*\(|\btargetOrigin\b|\bHTTP_ORIGIN\b|\bHTTP_REFERER\b)'''),

    # Headers, mail, logs (injection)
    ("header.set", "sink", "header", "CWE-113", 0.8, "any",
     r'''\b(?:setHeader|addHeader|set_header|add_header)\s*\(\s*(?:[a-z_$][\w$]*|['"][\w-]+['"]\s*,\s*[a-z_$])|\.Header\s*\(\s*\)\s*\.(?:Set|Add)\s*\(|\bresponse\.headers\s*\['''),
    ("header.crlf", "sink", "header", "CWE-93", 0.6, "any", r'''\\r\\n'''),
    ("mail.header", "sink", "header", "CWE-93", 1.2, "any",
     r'''\b(?:mail|mb_send_mail|wp_mail)\s*\(|\bsmtplib\.\w+|\bPHPMailer\b|\bSwift_Message\b|\bMIMEText\s*\(|\bMimeMessage\b|\bnodemailer\b|\bsmtp\.SendMail\s*\(|\bMailMessage\b|\bActionMailer\b'''),
    ("log.inject", "sink", "loginject", "CWE-117", 0.6, "any",
     r'''(?i:\b(?:log(?:ger)?|logging)\.(?:info|warn|warning|error|debug|log|trace|fatal|critical)\s*\(\s*(?:f["']|["'`][^"'`]*["'`]\s*[+%]|[a-z_$][\w$]*\s*\+))'''),

    # LDAP, XPath, prototype pollution, mass assignment, IDOR
    ("ldap", "sink", "ldap", "CWE-90", 1.8, "any",
     r'''\b(?:ldap_search|ldap_list|ldap_read|ldap_bind|ldap_compare|search_s|search_ext_s|DirContext|InitialDirContext|LdapTemplate|DirectorySearcher|LdapConnection|ldap3\.\w+|ldap\.search\w*)\b'''),
    ("xpath", "sink", "xpath", "CWE-643", 1.5, "any",
     r'''\b(?:xpath|XPath|selectNodes|selectSingleNode|SelectNodes|SelectSingleNode|xpath_eval|DOMXPath|XPathExpression)\s*\(\s*(?:["'][^"']*["']\s*[+.]|[a-z_$])'''),
    ("proto.js", "sink", "proto", "CWE-1321", 2.0, "js",
     r'''\b__proto__\b|\bconstructor\s*\.\s*prototype\b|\bObject\.prototype\b|\[\s*[a-z_$][\w$]*\s*\]\s*\[\s*[a-z_$][\w$]*\s*\]\s*=|\b(?:merge|deepMerge|mergeDeep|deepExtend|defaultsDeep|setWith|setPath|setValue|assignDeep|zipObjectDeep)\s*\(|\b_\.(?:merge|mergeWith|set|setWith|defaultsDeep|zipObjectDeep)\s*\(|\$\.extend\s*\(\s*true'''),
    ("massassign", "sink", "massassign", "CWE-915", 1.5, "any",
     r'''\bparams\.permit!|\.update\s*\(\s*params\[|\.(?:update|create|new|assign_attributes|update_attributes)\s*\(\s*params\b|\battr_accessible\b|\$guarded\s*=\s*\[\s*\]|->fill\s*\(\s*\$request->all\s*\(|::(?:create|update|forceCreate)\s*\(\s*\$request->all\s*\(|->update\s*\(\s*\$request->all\s*\(|\bObject\.assign\s*\(\s*[a-z_$][\w$]*\s*,\s*req\.body|\.\.\.req\.body|\.(?:create|update|save|insert)\s*\(\s*req\.body|\*\*request\.(?:data|json|POST|form)|\bBeanUtils\.copyProperties\s*\(|@ModelAttribute\b|\bTryUpdateModel\w*\s*\('''),
    ("idor.lookup", "sink", "idor", "CWE-639", 1.2, "any",
     r'''\.(?:get|filter|get_object_or_404|get_or_404|first_or_404)\s*\(\s*(?:pk|id|\w+_id)\s*=\s*(?:request|kwargs|pk|id|\w+_id)\b|::(?:find|findOrFail|findMany|where)\s*\(\s*\$(?:id|request|_GET|_POST|_REQUEST|\w+Id|\w+_id)\b|\.(?:findById|findByPk|findOne|findUnique|findFirst|findByIdAndUpdate|findByIdAndDelete)\s*\(\s*(?:req\.|request\.|ctx\.|params\.|id\b|\{\s*where\s*:\s*\{\s*id)|\.(?:findById|getById|getOne|getReferenceById|deleteById)\s*\(\s*(?:id|\w+Id)\s*\)|\.(?:First|Find|Take|Delete)\s*\(\s*&\w+\s*,\s*(?:id|\w+ID|c\.Param)|\.find\s*\(\s*params\[|\.find_by\s*\(\s*id:\s*params|\bRepo\.(?:get|get!|get_by|get_by!|delete|delete!)\s*\(\s*\w+\s*,\s*(?:id|params)'''),

    # Race conditions, temporary files, links, permissions
    ("race.check", "sink", "race", "CWE-367", 0.8, "any",
     r'''\bos\.path\.(?:exists|isfile|isdir|islink|lexists)\s*\(|\bos\.access\s*\(|\b(?:access|faccessat|stat|lstat|fstatat|euidaccess)\s*\(|\bos\.(?:Stat|Lstat)\s*\(|\bfile_exists\s*\(|\bis_(?:file|dir|link|writable|readable)\s*\(|\.exists\s*\(\s*\)|\bFiles\.(?:exists|notExists|isRegularFile|isDirectory|isSymbolicLink)\s*\(|\bfs\.(?:existsSync|exists|accessSync|access|statSync|lstatSync)\s*\('''),
    ("race.tmp", "sink", "tmpfile", "CWE-377", 2.0, "any",
     r'''\btempfile\.mktemp\s*\(|\b(?:mktemp|tmpnam|tempnam|tmpnam_r)\s*\(|\bFile\.createTempFile\s*\(|['"]/tmp/'''),
    ("race.lock", "sink", "race", "CWE-362", 0.4, "any",
     r'''\b(?:pthread_mutex_lock|pthread_mutex_unlock|mutex_enter|mutex_exit|mutex_lock|mutex_unlock|spin_lock\w*|spin_unlock\w*|rw_enter|rw_exit|sync\.Mutex|sync\.RWMutex|ReentrantLock|lockForUpdate|sharedLock|select_for_update|with_lock)\b|\.Lock\s*\(\s*\)|\.Unlock\s*\(\s*\)'''),
    ("link.follow", "sink", "link", "CWE-59", 1.2, "any",
     r'''\b(?:symlink|readlink|os\.symlink|os\.readlink|os\.Readlink|os\.Symlink|EvalSymlinks|islink|is_symlink|isSymbolicLink|followSymlinks|follow_symlinks|FollowSymlinks|NOFOLLOW_LINKS|O_NOFOLLOW|AT_SYMLINK_NOFOLLOW|toRealPath|getCanonicalPath)\b'''),
    ("perm.mode", "sink", "perm", "CWE-276", 1.0, "any",
     r'''\b(?:chmod|os\.chmod|os\.Chmod|fchmod|Files\.setPosixFilePermissions|setReadable|setWritable|setExecutable|umask|os\.Umask)\s*\(|\b0o?(?:777|776|775|766|666|664|662)\b|\bos\.ModePerm\b|\bS_IRWXO\b|\bS_IWOTH\b'''),

    # Authentication and session
    ("auth.verify", "guard", "authn", "CWE-287", 1.2, "any",
     r'''(?i:\b\w*(?:verify|validate|check|compare|decode|authenticate|auth)_?(?:token|jwt|signature|sig|hmac|mac|password|passwd|pass|credentials?|otp|totp|code|session|nonce|csrf|xsrf|key|cert|certificate|user|login|digest|hash|cookie|request|webhook|origin|referer|referrer|captcha|mfa|2fa)\w*\s*\()'''),
    ("auth.session", "guard", "session", "CWE-384", 1.0, "any",
     r'''(?i:\b(?:session_regenerate_id|session_start|session_destroy|regenerate_session|cycle_key|reset_session|invalidate|logout|login_user|logout_user|signIn|signOut|sign_in|sign_out)\s*\()'''),
    ("auth.password", "guard", "authn", "CWE-287", 1.0, "any",
     r'''(?i:\b(?:password_hash|password_verify|bcrypt\w*|scrypt\w*|argon2\w*|pbkdf2\w*|check_password|make_password|hashpw|checkpw|compare_digest|timingSafeEqual|hash_equals|ConstantTimeCompare|secure_compare|PasswordEncoder|checkPassword|verifyPassword|comparePassword|compareSync)\b)'''),
    ("auth.jwt", "guard", "authn", "CWE-347", 1.4, "any",
     r'''(?i:\bjwt\.(?:verify|encode|sign|parse\w*)\b|\bJWT::(?:decode|encode)\b|\bJwts\.parser\w*|\bjsonwebtoken\b|\bJWTVerifier\b|\bDecodedJWT\b|\bverify_signature\b|\bverify_exp\b)'''),
    ("auth.bypass", "guard", "authn", "CWE-287", 1.4, "any",
     r'''(?i:\b(?:skip|bypass|disable|no|without|allow)_?(?:auth\w*|verification|verify|login|signature|ssl|tls)\b|\bAllowAnonymous\b|\bpermitAll\b|\banonymous\b)'''),
    ("auth.ip", "guard", "authn", "CWE-290", 1.3, "any",
     r'''(?i:X-Forwarded-For|X-Real-IP|X-Forwarded-Host|X-Original-URL|X-Rewrite-URL|X-Forwarded-Proto|X-Client-IP|CF-Connecting-IP|True-Client-IP|\bgetRemoteAddr\s*\(|\bREMOTE_ADDR\b|\bremote_addr\b|\bRemoteAddr\b|\bClientIP\s*\(|\bremote_ip\b|\btrusted_?proxies\b)'''),

    # Authorization decisions
    ("authz.call", "guard", "authz", "CWE-862", 1.2, "any",
     r'''(?i:\b\w*(?:is_?admin|is_?superuser|is_?staff|is_?owner|is_?member|is_?moderator|has_?role|has_?any_?role|has_?perm\w*|has_?access|has_?privilege|has_?scope|has_?capability|has_?right|can_?(?:view|edit|read|write|delete|access|manage|update|create|modify|admin|see|upload|download|invite|share|publish|export|import)|check_?(?:perm\w*|access|role|owner\w*|acl|auth\w*|scope|privilege\w*|right\w*|capabilit\w*)|authori[sz]e\w*|require_?(?:perm\w*|role|admin|auth\w*|login|scope|owner|capability)|ensure_?(?:perm\w*|admin|auth\w*|owner|access|can)|user_?can|current_user_can|is_?allowed|is_?granted|is_?permitted|is_?authori[sz]ed|access_?check|acl_?check|enforce\w*|verify_?access|validate_?access|deny_?access\w*|abort_?unless|abort_?if)\s*\()'''),
    ("authz.annot", "guard", "authz", "CWE-862", 1.2, "any",
     r'''@(?:login_required|permission_required|user_passes_test|staff_member_required|requires_auth|jwt_required|auth_required|admin_required|roles_required|role_required|require_login|PreAuthorize|PostAuthorize|Secured|RolesAllowed|DenyAll|PermitAll|Authenticated|UseGuards|Roles|Public|SkipAuth|AllowAnonymous|RequiresPermissions|RequiresRoles)\b|\[(?:Authorize|AllowAnonymous|RequireHttps|ValidateAntiForgeryToken|IgnoreAntiforgeryToken)\b'''),
    ("authz.php", "guard", "authz", "CWE-862", 1.2, "php",
     r'''->middleware\s*\(|\bGate::(?:allows|denies|authorize|check|any|none|inspect)\b|->authorize\s*\(|->can\s*\(|->cannot\s*\(|->cant\s*\(|\bcurrent_user_can\s*\(|\bcheck_admin_referer\s*\(|\bcheck_ajax_referer\s*\(|\bwp_verify_nonce\s*\(|\bis_user_logged_in\s*\(|\bAuth::(?:check|user|id|guard|guest|attempt|validate)\b|\bauth\(\)->(?:check|user|id|guest)\b|\$this->Auth->|\bisGranted\s*\(|\bdenyAccessUnlessGranted\s*\(|\bIsGranted\b|\bAcl\w*->(?:check|isAllowed)\b'''),
    ("authz.rb", "guard", "authz", "CWE-862", 1.0, "rb",
     r'''\bbefore_action\b|\bbefore_filter\b|\bskip_before_action\b|\bauthorize!?\s*[(:]|\bpolicy_scope\b|\bcan\?\s*[(:]|\bcannot\?\s*[(:]|\bload_and_authorize_resource\b|\bauthenticate_\w+|\bcurrent_user\b|\buser_signed_in\?'''),
    ("authz.py", "guard", "authz", "CWE-862", 1.0, "py",
     r'''\bpermission_classes\b|\bIsAuthenticated\b|\bIsAdminUser\b|\bDjangoModelPermissions\w*\b|\bhas_object_permission\b|\bhas_permission\b|\brequest\.user\.(?:is_authenticated|is_staff|is_superuser|has_perm|is_anonymous)\b|\bcurrent_user\.(?:is_authenticated|is_admin|id|role)\b|\bDepends\s*\(\s*\w*(?:auth|user|admin|permission|current)\w*'''),
    ("authz.js", "guard", "authz", "CWE-862", 1.0, "js",
     r'''\breq\.(?:user|session|auth|isAuthenticated)\b|\bpassport\.authenticate\s*\(|\bgetServerSession\s*\(|\bgetSession\s*\(|\bauth\s*\(\s*\)|\bcurrentUser\b|\bsession\.user\b|\bensureLoggedIn\b|\brequireAuth\b|\bisAuthenticated\b|\bcanActivate\s*\('''),
    ("authz.go", "guard", "authz", "CWE-862", 1.0, "go",
     r'''\b(?:RequireAuth|AuthMiddleware|Authenticate|Authorize|CheckPermission|IsAdmin|HasPermission|RequireRole|Enforce)\w*\s*\(|\bc\.Get\s*\(\s*"(?:user|userID|user_id|claims|role)"'''),
    ("authz.jvm", "guard", "authz", "CWE-862", 1.0, "jvm",
     r'''\bSecurityContextHolder\b|\bgetUserPrincipal\s*\(|\bisUserInRole\s*\(|\bhasRole\s*\(|\bhasAuthority\s*\(|\bhasAnyRole\s*\(|\bcheckPermission\s*\(|\bAccessDeniedException\b|\bForbiddenException\b|\bUnauthorizedException\b|\bauthorizeHttpRequests\b|\bauthorizeRequests\b|\bauthenticated\s*\(\s*\)|\bSecurityException\b|\bElasticsearchSecurityException\b'''),
    ("authz.cs", "guard", "authz", "CWE-862", 1.0, "cs",
     r'''\bUser\.(?:IsInRole|Identity|Claims|FindFirst)\b|\bAuthorizeAsync\s*\(|\bIAuthorizationService\b|\bClaimsPrincipal\b|\bRequireAuthorization\s*\('''),
    ("authz.ex", "guard", "authz", "CWE-862", 1.0, "ex",
     r'''\bplug\s+:?\w*(?:auth|require|ensure|admin|permission|role|verify)\w*|\bpipe_through\b|\bcurrent_user\b|\bconn\.assigns\.current_\w+|\bBodyguard\b|\bon_mount\b'''),
    ("authz.c", "guard", "authz", "CWE-862", 1.2, "c",
     r'''\b(?:secpolicy_\w+|priv_policy\w*|PRIV_POLICY\w*|crgetuid|crgetruid|crgetgid|crgetzoneid|drv_priv|suser|capable|ns_capable|inode_permission|may_open|getuid|geteuid|setuid|seteuid|setreuid|setgid|setegid|setgroups|chroot|priv_check\w*|kauth_authorize\w*|mac_\w+_check\w*|check_perm\w*|has_perm\w*|zone_check\w*|INGLOBALZONE|HAS_PRIVILEGE|secpolicy)\s*\('''),
    ("authz.owner", "guard", "idor", "CWE-639", 1.4, "any",
     r'''(?i:\b(?:owner_?id|user_?id|author_?id|creator_?id|created_?by|tenant_?id|org_?id|organization_?id|account_?id|workspace_?id|team_?id|project_?id|group_?id|company_?id|customer_?id|uid)\b\s*(?:===?|!==?|<>|\.equals\s*\(|\.Equals\s*\())'''),

    # Request handlers by signature (v2)
    ("route.sig_go", "route", "route", None, 0.8, "go",
     r'''\bfunc\s*(?:\([^)]*\)\s*)?\w+\s*\(\s*\w+\s+http\.ResponseWriter\s*,\s*\w+\s+\*http\.Request\s*\)|\bfunc\s*(?:\([^)]*\)\s*)?\w+\s*\(\s*\w+\s+(?:\*gin\.Context|echo\.Context|\*fiber\.Ctx|\*fasthttp\.RequestCtx|iris\.Context|\*web\.Context)\s*\)'''),
    ("route.sig_py", "route", "route", None, 0.8, "py",
     r'''\bdef\s+\w+\s*\(\s*(?:self\s*,\s*)?request\b|\basync\s+def\s+\w+\s*\(\s*(?:self\s*,\s*)?request\s*:'''),
    ("route.sig_js", "route", "route", None, 0.8, "js",
     r'''\(\s*req\s*(?::\s*[\w.<>]+)?\s*,\s*res\b|\(\s*(?:request|req)\s*:\s*(?:NextRequest|NextApiRequest|Request|FastifyRequest|IncomingMessage|ExpressRequest)\b'''),
    ("route.sig_php", "route", "route", None, 0.8, "php",
     r'''\bfunction\s+\w+\s*\(\s*(?:\??\\?[\w\\]*Request\s+)\$request\b'''),
    ("route.sig_cs", "route", "route", None, 0.8, "cs",
     r'''\bpublic\s+(?:virtual\s+|override\s+)?(?:async\s+)?(?:Task\s*<\s*)?(?:IActionResult|ActionResult|JsonResult|ViewResult|IResult|ContentResult|FileResult|RedirectResult|PartialViewResult)\b'''),
    ("route.sig_ex", "route", "route", None, 0.8, "ex", r'''\bdef\s+\w+\s*\(\s*conn\s*,|\bdef\s+handle_event\s*\('''),
    ("route.sig_rs", "route", "route", None, 0.8, "rs",
     r'''\basync\s+fn\s+\w+\s*\([^)]*(?:web::|Json\s*<|Query\s*<|Path\s*<|Form\s*<|HttpRequest|State\s*<|Extension\s*<|Multipart)'''),
    ("route.spring_controller", "route", "route", None, 0.4, "jvm", r'''@(?:Rest)?Controller\b|@RequestMapping\s*\('''),
    # Loops bounded by a length field, templates (v2)
    ("dos.loop_bound", "sink", "loop", "CWE-834", 0.6, "c go jvm cs rs",
     r'''\bfor\s*\([^;]*;\s*\w+\s*<=?\s*[\w.>\[\]-]*(?:len|length|size|count|cnt|num|total|nr|max)\w*\s*(?:[-+]\s*\w+\s*)?;|\bwhile\s*\(\s*\w+--\s*(?:>\s*0\s*)?\)'''),
    ("xss.tpl.handler", "sink", "xss", "CWE-79", 1.0, "tpl php jvm",
     r'''\bon(?:click|load|error|mouseover|mouseout|mouseenter|focus|blur|submit|change|input|keyup|keydown|keypress)\s*=\s*["']'''),
    ("xss.tpl.script", "sink", "xss", "CWE-79", 0.5, "tpl php jvm", r'''<script\b'''),
    ("xss.tpl.attr", "sink", "xss", "CWE-79", 1.2, "tpl",
     r'''\b(?:href|src|action|formaction|style)\s*=\s*["']?\s*(?:\{\{|<%=|\{!!|\$\{)'''),

    # Entry points of system code, lookups, casts (v2)
    ("route.c_ipc", "route", "route", None, 0.9, "c",
     r'''\bdoor_(?:return|ucred|create|server_create|cred)\s*\(|\bsvc_(?:getargs|sendreply|freeargs)\s*\(|\bsvcerr_\w+\s*\(|\bdbus_message_get_args\s*\(|\bxpc_dictionary_get_\w+\s*\(|\bmach_msg\s*\('''),
    ("route.c_ioctl", "route", "route", None, 0.9, "c",
     r'''\b\w+_ioctl\s*\(\s*(?:dev_t|struct\s+(?:file|inode|block_device|net_device|socket)|vnode_t|queue_t)\b|\.(?:unlocked_ioctl|compat_ioctl)\s*=|\bSYSCALL_DEFINE\d\s*\('''),
    ("route.c_table", "route", "route", None, 0.7, "c",
     r'''\{\s*[A-Z][A-Z0-9_]*\s*,[^{};]*\b\w+_(?:handler|cb|callback|func|fn|cmd|op|proc|hdlr)\s*\}'''),
    ("idor.request_id", "sink", "idor", "CWE-639", 1.3, "any",
     r'''\b(?:find|get|load|lookup|fetch|read|delete|remove|update|resolve)\w*\s*\(\s*\$?(?:request|req|params|ctx|context|input|body|query|args)\s*(?:\.|->|\[)\s*['"]?\w*(?:Id|ID|_id|Key|_key|Uuid|uuid)\b'''),
    ("idor.yii", "sink", "idor", "CWE-639", 1.2, "php",
     r'''->(?:findByPk|findByAttributes|findAllByAttributes|findAllByPk|deleteByPk|deleteAllByAttributes|updateByPk|updateAll|deleteAll)\s*\(\s*\$'''),
    ("xss.concat", "sink", "xss", "CWE-79", 1.0, "php js py rb jvm cs go ex",
     r''''[^'\n]*<[a-zA-Z][^'\n]*'\s*(?:\.|\+)\s*[$\w(]|"[^"\n]*<[a-zA-Z][^"\n]*"\s*(?:\.|\+)\s*[$\w(]'''),
    ("xss.dom_clobber", "sink", "xss", "CWE-79", 0.8, "js",
     r'''\b(?:window|document|self|globalThis)\.[A-Za-z_$][\w$]*\s*(?:!==?|===?)\s*(?:void\s+0|undefined|null)\b|\btypeof\s+(?:window|document)\.[A-Za-z_$][\w$]*'''),
    ("mem.bounds", "sink", "mem", "CWE-125", 0.4, "c go rs jvm cs",
     r'''\b\w*(?i:len|length|size|count|cnt|offset|remain|avail)\w*\s*(?:<=?|>=?)\s*(?:\(\s*(?:int|long|short|unsigned|size_t|ssize_t|u?int\d+_t)\s*\)\s*)?[\w(]'''),
    ("intovf.cast", "sink", "intovf", "CWE-195", 0.8, "c",
     r'''\(\s*(?:int|long|short|char|signed|int8_t|int16_t|int32_t|int64_t|ssize_t|off_t)\s*\)\s*[\w.>-]+\s*(?:<=|>=|[-+*<>])'''),
    ("mem.ptrcast", "sink", "mem", "CWE-822", 0.6, "c",
     r'''\(\s*volatile\s+[\w\s]+\*\s*\)|\(\s*(?:void|char|u?int\d*_t|unsigned\s+char|\w*uint\d+_t)\s*\*\s*\)\s*\(?\s*(?:\(\s*)?(?:uintptr_t|intptr_t|\w*addr_t|ulong|unsigned\s+long|size_t)\b'''),

    # Structural signals (no scan pattern; the unit pass adds them)
    ("struct.recursion", "sink", "recursion", "CWE-674", 1.0, "", r'''struct-recursion'''),
    ("struct.unguarded", "sink", "authz", "CWE-862", 1.5, "", r'''struct-unguarded'''),
    ("struct.controller_method", "route", "route", None, 0.6, "", r'''struct-controller-method'''),

    ("call.security", "guard", "check", "CWE-693", 0.4, "any",
     r'''(?i:\b\w*(?:trust|verif|authori[sz]|authentic|permi|privileg|validat|sanitiz|escape|signature|lockdown|allowlist|whitelist|denylist|blacklist)\w*\s*\()'''),

    # Security names of definitions
    ("name.def", "name", "name", None, 0.5, "any",
     r'''(?i:\b(?:def|func|function|fn|fun|sub|defp|proc|void|int|bool|boolean|static|public|private|protected|async)\s+[\w.*$]*?(?:auth|login|logon|logout|signin|signup|session|token|passw|credential|secret|admin|permission|privilege|role|acl|policy|owner|access|upload|download|import|export|install|unzip|extract|unpack|archive|backup|restore|exec|command|shell|spawn|query|sql|deserial|unserial|unmarshal|pickle|parse|decode|render|template|redirect|proxy|fetch|webhook|callback|crypt|sign|verify|hash|random|nonce|csrf|cors|cookie|sanitiz|escape|validat|whitelist|allowlist|blacklist|denylist)\w*\s*\()'''),
)


class Rule:
    __slots__ = ("index", "id", "kind", "cls", "cwe", "weight", "groups", "regex", "compiled")

    def __init__(self, index, spec):
        self.index = index
        self.id, self.kind, self.cls, self.cwe, self.weight, groups, self.regex = spec
        self.groups = frozenset(groups.split())
        # ASCII semantics in both engines: rg runs with --no-unicode (the fast DFA keeps working on
        # non-ASCII text) and Python uses re.ASCII, so the classifier sees the same matches.
        self.compiled = re.compile(self.regex, re.ASCII)


RULES = tuple(Rule(i, spec) for i, spec in enumerate(_RULE_SPECS))
RULE_BY_ID = {rule.id: rule for rule in RULES}
assert len(RULE_BY_ID) == len(RULES), "rule ids must be unique"
assert len(RULES) < 1024, "the packed signal format holds 10 bits of rule index"


def family_rules(family):
    groups = set(FAMILY_GROUPS[family])
    return [rule.index for rule in RULES if rule.groups & groups]


FAMILY_RULES = {family: family_rules(family) for family in FAMILY_GROUPS}

CLASS_CWE = {
    "cmd": "CWE-78", "code": "CWE-94", "reflect": "CWE-470", "ssti": "CWE-1336", "sql": "CWE-89",
    "nosql": "CWE-943", "path": "CWE-22", "archive": "CWE-22", "upload": "CWE-434", "deser": "CWE-502",
    "xss": "CWE-79", "redirect": "CWE-601", "ssrf": "CWE-918", "xxe": "CWE-611", "random": "CWE-338",
    "crypto": "CWE-327", "tls": "CWE-295", "authn": "CWE-287", "session": "CWE-384", "authz": "CWE-862",
    "idor": "CWE-639", "massassign": "CWE-915", "mem": "CWE-119", "intovf": "CWE-190", "free": "CWE-416",
    "format": "CWE-134", "assert": "CWE-617", "regex": "CWE-1333", "dos": "CWE-400", "loop": "CWE-835",
    "logsecret": "CWE-532", "secret": "CWE-798", "infoleak": "CWE-200", "cors": "CWE-942",
    "cookie": "CWE-1004", "csrf": "CWE-352", "origin": "CWE-346", "header": "CWE-113", "loginject": "CWE-117",
    "ldap": "CWE-90", "xpath": "CWE-643", "proto": "CWE-1321", "race": "CWE-367", "tmpfile": "CWE-377",
    "link": "CWE-59", "perm": "CWE-276",
}

# Words of a symbol or path that mark security-relevant code (prefix match).
STRONG_WORDS = (
    "auth", "login", "logon", "logout", "signin", "signup", "session", "token", "passw", "credential",
    "secret", "admin", "permission", "privilege", "role", "acl", "policy", "owner", "upload", "download",
    "exec", "command", "shell", "spawn", "query", "sql", "deserial", "unserial", "unmarshal", "pickle",
    "decode", "render", "redirect", "proxy", "fetch", "crypt", "sign", "verify", "nonce", "csrf", "cors",
    "cookie", "jwt", "oauth", "saml", "sso", "ldap", "otp", "mfa", "sanitiz", "escape", "unzip",
    "extract", "unpack", "archive", "webhook", "impersonat", "invite", "reset", "register",
    "trust", "tls", "ssl", "handshake", "x509", "certificate", "lockdown", "grant", "tenant", "superuser",
)
WEAK_WORDS = (
    "parse", "path", "file", "import", "export", "install", "template", "hash", "random", "valid",
    "access", "url", "uri", "host", "callback", "request", "handler", "packet", "pkt", "recv", "buffer",
    "header", "cert", "key", "user", "account", "share", "public", "plugin", "backup", "restore",
    "safe", "encod", "purif", "clean", "cache", "middleware", "mmio", "emul", "guest", "door", "ioctl",
    "rpc", "ipc", "socket", "proto", "msg", "message", "frame", "hdr", "payload", "codepoint", "utf",
    "unicode", "charset", "scope", "visib",
)
ACCESS_WORDS = (
    "auth", "permission", "privilege", "role", "admin", "policy", "acl", "owner", "trust", "grant",
    "tenant", "access", "lockdown", "superuser", "visib", "scope", "guard", "allow", "deny", "forbid",
)
WORD_SPLIT_RE = re.compile(r"[A-Z]?[a-z]+|[A-Z]+(?![a-z])|\d+")


class Budget:
    """The deadline of one inventory run; each step stops at a fraction of it."""

    def __init__(self, seconds):
        self.seconds = max(1.0, float(seconds))
        self.t0 = time.monotonic()
        self.reserve = min(30.0, max(0.5, 0.03 * self.seconds))
        self.end = self.t0 + self.seconds - self.reserve

    def at(self, fraction):
        return min(self.end, self.t0 + fraction * self.seconds)

    def left(self, fraction=1.0):
        return self.at(fraction) - time.monotonic()

    def elapsed(self):
        return time.monotonic() - self.t0


def _cpu_count():
    try:
        with open("/sys/fs/cgroup/cpu.max", encoding="ascii") as handle:
            quota, period = handle.read().split()[:2]
            if quota != "max":
                return max(1, int(math.ceil(int(quota) / int(period))))
    except (OSError, ValueError):
        pass
    try:
        return max(1, len(os.sched_getaffinity(0)))
    except (AttributeError, OSError):
        return max(1, os.cpu_count() or 1)


def _memory_stats():
    stats = {}
    try:
        import resource

        scale = 1024 if sys.platform != "darwin" else 1
        stats["max_rss_mb"] = round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * scale / 2**20, 1)
        stats["children_max_rss_mb"] = round(
            resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss * scale / 2**20, 1
        )
    except (ImportError, OSError, ValueError):
        pass
    for name in ("memory.peak", "memory.max_usage_in_bytes"):
        try:
            with open("/sys/fs/cgroup/" + name, encoding="ascii") as handle:
                stats["cgroup_peak_mb"] = round(int(handle.read().strip()) / 2**20, 1)
                break
        except (OSError, ValueError):
            continue
    return stats


def _symbol_words(text):
    words = []
    for part in re.split(r"[^A-Za-z0-9]+", text or ""):
        words.extend(word.lower() for word in WORD_SPLIT_RE.findall(part))
    return words


MAIN_RE = re.compile(r"^(?:\w*_)?main$", re.IGNORECASE)
MAIN_FACTOR = 0.6                     # program main functions (CLI input) rank lower


def _access_words(text):
    return [word for word in _symbol_words(text) if any(word.startswith(prefix) for prefix in ACCESS_WORDS)]


def _security_words(text):
    strong, weak = [], []
    for word in _symbol_words(text):
        if any(word.startswith(prefix) for prefix in STRONG_WORDS):
            strong.append(word)
        elif any(word.startswith(prefix) for prefix in WEAK_WORDS):
            weak.append(word)
    return strong, weak


class FileRec:
    __slots__ = ("path", "size", "lang", "tags", "family", "lines")

    def __init__(self, path, size, lang, tags):
        self.path = path
        self.size = size
        self.lang = lang
        self.tags = tags
        self.family = None
        self.lines = 0


def path_tags(path):
    """Path tags of a repository path (a set of names of TAG_DIRS and file rules)."""
    original_name = path.rsplit("/", 1)[-1]
    parts = path.lower().split("/")
    directories, name = parts[:-1], parts[-1]
    tags = set()
    joined = "/".join(directories)
    for tag, names in TAG_DIRS.items():
        if any(part in names for part in directories):
            tags.add(tag)
        elif "/" in "".join(names) and any(entry in joined for entry in names if "/" in entry):
            tags.add(tag)
    if TEST_FILE_RE.match(original_name) or TEST_FILE_RE.match(name):
        tags.add("test")
    if GENERATED_FILE_RE.match(name):
        tags.add("generated")
    if name.endswith(".d.ts"):
        tags.add("declarations")
    if DOC_FILE_RE.match(name) or name.rsplit(".", 1)[-1] in ("md", "markdown", "rst", "adoc", "txt"):
        tags.add("docs")
    if "/.github/workflows/" in "/" + path.lower():
        tags.discard("tooling")
    if "build" in tags:
        # "build", "dist" or "out" below a source folder is source code (a build system),
        # not build output.
        first_build = min(i for i, part in enumerate(directories) if part in TAG_DIRS["build"])
        if any(part in SOURCE_DIRS for part in directories[:first_build]):
            tags.discard("build")
    return tags


def _language(path, name, full, size):
    lowered = name.lower()
    if lowered in SPECIAL_NAMES:
        return SPECIAL_NAMES[lowered]
    if lowered.endswith(".blade.php"):
        return "php"
    dot = lowered.rfind(".")
    if dot > 0:
        ext = lowered[dot:]
        if ext[1:] in BINARY_EXTENSIONS:
            return "binary"
        lang = EXTENSIONS.get(ext)
        if lang:
            return lang
        return "other"
    if size and size < 1_000_000:
        try:
            with open(full, "rb") as handle:
                head = handle.read(96)
        except OSError:
            return "other"
        if head.startswith(b"#!"):
            first = head.split(b"\n", 1)[0].decode("latin-1").lower()
            for needle, lang in SHEBANGS:
                if needle in first:
                    return lang
    return "other"


def census(root, budget, log):
    """Walk the repository; return the file records and the census counts."""
    stop_at = budget.at(0.25)
    files = []
    counts = Counter()
    stack = [""]
    partial = False
    visited = 0
    while stack:
        rel_dir = stack.pop()
        visited += 1
        if visited % 256 == 0 and time.monotonic() > stop_at:
            partial = True
            counts["dirs_not_walked"] += len(stack) + 1
            break
        full_dir = os.path.join(root, rel_dir) if rel_dir else root
        try:
            entries = sorted(os.scandir(full_dir), key=lambda entry: entry.name)
        except OSError:
            counts["unreadable_dirs"] += 1
            continue
        for entry in entries:
            name = entry.name
            rel = rel_dir + "/" + name if rel_dir else name
            try:
                rel.encode("utf-8")
            except UnicodeEncodeError:
                counts["bad_names"] += 1
                continue
            try:
                if entry.is_symlink():
                    counts["symlinks"] += 1
                    continue
                if entry.is_dir(follow_symlinks=False):
                    if name in SKIP_DIRS:
                        counts["skipped_dirs"] += 1
                        continue
                    stack.append(rel)
                    continue
                if not entry.is_file(follow_symlinks=False):
                    counts["special_files"] += 1
                    continue
                size = entry.stat(follow_symlinks=False).st_size
            except OSError:
                counts["unreadable_files"] += 1
                continue
            lang = _language(rel, name, entry.path, size)
            files.append(FileRec(rel, size, lang, path_tags(rel)))
    # Ambiguous extensions follow the majority of the repository.
    by_lang = Counter(rec.lang for rec in files)
    header_lang = "cpp" if by_lang["cpp"] > by_lang["c"] else "c"
    inc_lang = "php" if by_lang["php"] else ("c" if by_lang["c"] + by_lang["cpp"] else "other")
    for rec in files:
        if rec.lang == "c?":
            rec.lang = header_lang
        elif rec.lang == "php?":
            rec.lang = inc_lang
    files.sort(key=lambda rec: rec.path)
    if log:
        log(f"census: {len(files)} files, partial={partial}")
    return files, counts, partial


def _scan_family(rec):
    if rec.lang == "yaml" and "/.github/workflows/" in "/" + rec.path:
        return "gha"
    return FAMILY_OF_LANGUAGE.get(rec.lang)


class Classifier:
    """Maps a matched text to the rules of a family that match it in full."""

    def __init__(self, rule_indexes):
        self.rules = [RULES[i] for i in rule_indexes]
        self.cache = {}

    def classify(self, text):
        found = self.cache.get(text)
        if found is None:
            found = tuple(rule.index for rule in self.rules if rule.compiled.fullmatch(text))
            if not found:
                found = tuple(rule.index for rule in self.rules if rule.compiled.search(text))
            if len(self.cache) < 300_000:
                self.cache[text] = found
        return found


def _rg_path():
    # The scan runs in the audited repository: only the absolute entries of PATH count.
    from ..programs import which

    path = which("rg")
    if path:
        return path
    for candidate in ("/usr/local/bin/rg", "/usr/bin/rg"):
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


def _batches(paths, limit):
    batch, size = [], 0
    for path in paths:
        cost = len(path.encode("utf-8")) + 1
        if batch and size + cost > limit:
            yield batch
            batch, size = [], 0
        batch.append(path)
        size += cost
    if batch:
        yield batch


def scan(root, files, budget, log, force_python=False):
    """Scan the files of each family; return {file index: [packed signal]} and stats."""
    stop_at = budget.at(0.6)
    by_family = defaultdict(list)
    skipped = Counter()
    for index, rec in enumerate(files):
        family = _scan_family(rec)
        rec.family = family
        if family is None:
            continue
        if rec.size > MAX_SCAN_BYTES:
            skipped["too_large"] += 1
            continue
        if rec.size == 0:
            continue
        by_family[family].append(index)
    # Production files first: the deadline cuts tagged files first.
    for family in by_family:
        by_family[family].sort(key=lambda i: (bool(files[i].tags - {"tooling"}), files[i].path))
    signals = defaultdict(list)
    state = {"partial": False, "total": 0, "files_scanned": 0}
    rg = None if force_python else _rg_path()
    engine = "rg" if rg else "python"
    families = [family for family in FAMILY_ORDER if by_family.get(family)]
    # Two passes: untagged files of each family first, then tagged files.
    for tagged_pass in (False, True):
        for family in families:
            indexes = [i for i in by_family[family] if bool(files[i].tags - {"tooling"}) == tagged_pass]
            if not indexes:
                continue
            if time.monotonic() > stop_at or state["total"] > MAX_SIGNALS_TOTAL:
                state["partial"] = True
                skipped["not_scanned_deadline"] += len(indexes)
                continue
            if rg:
                _scan_rg(rg, root, files, family, indexes, signals, state, stop_at)
            else:
                _scan_python(root, files, family, indexes, signals, state, stop_at)
    if log:
        log(f"scan ({engine}): {state['total']} signals in {len(signals)} files, partial={state['partial']}")
    return signals, {"engine": engine, "skipped": dict(skipped), "partial": state["partial"],
                     "files_scanned": state["files_scanned"], "signals": state["total"]}


def _scan_rg(rg, root, files, family, indexes, signals, state, stop_at):
    rule_indexes = FAMILY_RULES[family]
    classifier = Classifier(rule_indexes)
    jobs = str(_cpu_count())
    base = [rg, "--no-config", "--no-ignore", "--hidden", "--no-messages", "--no-unicode", "--only-matching",
            "--line-number", "--with-filename", "--null", "--no-heading", "--color", "never",
            "--max-count", str(MAX_LINES_PER_FILE), "--max-columns", "400",
            "--max-filesize", str(MAX_SCAN_BYTES), "--threads", jobs]
    for i in rule_indexes:
        base += ["-e", RULES[i].regex]
    base.append("--")
    by_path = {}
    for i in indexes:
        by_path[files[i].path.encode("utf-8")] = i
    paths = [files[i].path for i in indexes]
    for batch in _batches(paths, ARG_BYTES_PER_BATCH):
        remaining = stop_at - time.monotonic()
        if remaining <= 0 or state["total"] > MAX_SIGNALS_TOTAL:
            state["partial"] = True
            break
        try:
            proc = subprocess.Popen(base + batch, cwd=root, stdin=subprocess.DEVNULL,
                                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        except OSError:
            _scan_python(root, files, family, [by_path[p.encode("utf-8")] for p in batch], signals, state, stop_at)
            continue
        killed = threading.Event()

        def _kill(proc=proc, killed=killed):
            killed.set()
            proc.kill()

        timer = threading.Timer(remaining, _kill)
        timer.daemon = True
        timer.start()
        last_path, last_index = None, None
        try:
            for raw in proc.stdout:
                nul = raw.find(b"\0")
                if nul < 0:
                    continue
                path = raw[:nul]
                rest = raw[nul + 1:]
                colon = rest.find(b":")
                if colon < 0:
                    continue
                try:
                    line = int(rest[:colon])
                except ValueError:
                    continue
                if path != last_path:
                    last_path, last_index = path, by_path.get(path)
                if last_index is None:
                    continue
                text = rest[colon + 1:].rstrip(b"\r\n").decode("utf-8", "replace")
                found = classifier.classify(text)
                if found:
                    bucket = signals[last_index]
                    for rule_index in found:
                        bucket.append((line << 10) | rule_index)
                    state["total"] += len(found)
        finally:
            proc.stdout.close()
            proc.wait()
            timer.cancel()
        state["files_scanned"] += len(batch)
        if killed.is_set():
            state["partial"] = True
            break


_COMBINED_PY = {}


def _combined_python(family):
    combined = _COMBINED_PY.get(family)
    if combined is None:
        combined = re.compile("|".join("(?:%s)" % RULES[i].regex for i in FAMILY_RULES[family]), re.ASCII)
        _COMBINED_PY[family] = combined
    return combined


def _scan_python(root, files, family, indexes, signals, state, stop_at):
    combined = _combined_python(family)
    classifier = Classifier(FAMILY_RULES[family])
    for count, i in enumerate(indexes):
        if count % 64 == 0 and (time.monotonic() > stop_at or state["total"] > MAX_SIGNALS_TOTAL):
            state["partial"] = True
            return
        rec = files[i]
        try:
            with open(os.path.join(root, rec.path), "rb") as handle:
                data = handle.read(MAX_SCAN_BYTES + 1)
        except OSError:
            continue
        state["files_scanned"] += 1
        if len(data) > MAX_SCAN_BYTES or b"\0" in data[:8192]:
            continue
        text = data.decode("utf-8", "replace")
        try:
            with TimeLimit(min(PARSE_SECONDS, max(0.2, stop_at - time.monotonic()))):
                _scan_text_python(text, combined, classifier, signals, i, state)
        except _Timeout:
            state["python_scan_timeouts"] = state.get("python_scan_timeouts", 0) + 1


def _scan_text_python(text, combined, classifier, signals, i, state):
    matched_lines = 0
    bucket = None
    for number, line in enumerate(text.split("\n"), 1):
        hit = False
        for match in combined.finditer(line[:MINIFIED_LINE * 4]):
            matched = match.group(0)
            if not matched:
                continue
            found = classifier.classify(matched[:400])
            if found:
                if bucket is None:
                    bucket = signals[i]
                for rule_index in found:
                    bucket.append((number << 10) | rule_index)
                state["total"] += len(found)
                hit = True
        if hit:
            matched_lines += 1
            if matched_lines >= MAX_LINES_PER_FILE:
                break


class Block:
    __slots__ = ("start", "end", "name", "kind", "parent")

    def __init__(self, start, end, name, kind, parent):
        self.start = start
        self.end = end
        self.name = name
        self.kind = kind          # function | closure
        self.parent = parent      # index of the enclosing function block or None


# Possessive and unrolled patterns (Python 3.11+): no backtracking state grows with a long
# match, so a minified or unterminated token costs linear time and constant memory.
_CMT_LINE = r"//[^\n]*+"
_CMT_BLOCK = r"/\*(?:[^*]++|\*(?!/))*+(?:\*/|\Z)"
_DQ = r'"(?:[^"\\\n]++|\\.)*+"'
_SQ = r"'(?:[^'\\\n]++|\\.)*+'"
_CHAR = r"'(?:\\[^'\n]{1,10}+|[^'\\\n])'"
_TRIPLE = r'"""(?:[^"]++|"(?!""))*+"""'
_BT_JS = r"`(?:[^`\\]++|\\[\s\S])*+`"
_BT_GO = r"`[^`]*+`"
_HASH = r"#[^\n]*+"
_PHP_HASH = r"#(?!\[)[^\n]*+"
_CS_VERBATIM = r'@"(?:[^"]++|"")*+"'
_PHP_HEREDOC = r"<<<[ \t]*+['\"]?(\w+)['\"]?\n(?:[^\n]*+\n)*?[ \t]*\1\b"
_JS_REGEX = r"(?<=[(,=:\[!&|?{};])\s*+/(?![*/])(?:[^/\\\n\[]++|\\.|\[(?:[^\]\\\n]++|\\.)*+\])++/[gimsuyd]*+"
_RS_RAW = r'r#*"[\s\S]*?"#*'
MINIFIED_LINE = 5000                  # a longer line marks a minified file: windows only, no block parse
BLOCK_PARSE_MAX_BYTES = 3 * 1024 * 1024
PARSE_SECONDS = 15.0                  # time limit of the block parse of one file (then windows only)


class _Timeout(Exception):
    pass


def _on_alarm(signum, frame):
    raise _Timeout()


class TimeLimit:
    """A time limit for one step (SIGALRM; only in the main thread, no limit elsewhere).

    CPython's regex engine checks for signals during a long match, so the limit also
    stops a slow regular expression."""

    def __init__(self, seconds):
        self.seconds = seconds
        self.active = False
        self.previous = None

    def __enter__(self):
        if (self.seconds and self.seconds > 0 and hasattr(signal, "setitimer")
                and threading.current_thread() is threading.main_thread()):
            self.previous = signal.signal(signal.SIGALRM, _on_alarm)
            signal.setitimer(signal.ITIMER_REAL, max(0.05, float(self.seconds)))
            self.active = True
        return self

    def __exit__(self, *exc_info):
        if self.active:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, self.previous)
            self.active = False
        return False

_TOKENIZERS = {
    "c": re.compile("|".join((_CMT_LINE, _CMT_BLOCK, _DQ, _CHAR))),
    "jvm": re.compile("|".join((_TRIPLE, _CMT_LINE, _CMT_BLOCK, _DQ, _CHAR))),
    "groovy": re.compile("|".join((_TRIPLE, _CMT_LINE, _CMT_BLOCK, _DQ, _SQ))),
    "cs": re.compile("|".join((_CS_VERBATIM, _TRIPLE, _CMT_LINE, _CMT_BLOCK, _DQ, _CHAR))),
    "go": re.compile("|".join((_BT_GO, _CMT_LINE, _CMT_BLOCK, _DQ, _CHAR))),
    "rust": re.compile("|".join((_RS_RAW, _CMT_LINE, _CMT_BLOCK, _DQ, _CHAR))),
    "js": re.compile("|".join((_BT_JS, _CMT_LINE, _CMT_BLOCK, _DQ, _SQ, _JS_REGEX))),
    "php": re.compile("|".join((_PHP_HEREDOC, _CMT_LINE, _CMT_BLOCK, _DQ, _SQ, _PHP_HASH))),
    "hash": re.compile("|".join((_HASH, _DQ, _SQ))),
}
_BRACE_LANG = {
    "c": "c", "cpp": "c", "objc": "c", "java": "jvm", "kotlin": "jvm", "scala": "jvm", "swift": "jvm",
    "dart": "groovy", "groovy": "groovy", "csharp": "cs", "go": "go", "rust": "rust",
    "javascript": "js", "typescript": "js", "vue": "js", "svelte": "js", "php": "php",
    "perl": "hash", "shell": "hash",
}
_CONTROL = frozenset(
    "if else for foreach while do switch case default try catch finally synchronized using lock fixed "
    "unsafe checked unchecked match loop select return sizeof typeof alignof decltype with when defer go "
    "elif elsif elseif until unless new throw yield await in of static_assert __attribute__ assert "
    "foreach_reverse forEach each map filter".split()
)
_CONTAINER_RE = re.compile(
    r"\b(class|interface|enum|struct|union|namespace|record|object|trait|extension|protocol|impl|module|mod)\b"
    r"\s*([A-Za-z_$][\w$]*)?"
)
_C_NAME_RE = re.compile(r"([A-Za-z_~$][\w$]*(?:\s*(?:::|\.)\s*~?[A-Za-z_$][\w$]*)*)\s*(?:<[^<>(){};]*>)?\s*\(")
_TRAIL_OK_RE = re.compile(
    r"\)\s*(?:const|noexcept(?:\s*\([^)]*\))?|override|final|mutable|volatile|&{1,2}|throws\s+[\w.,\s<>]+"
    r"|->\s*[^{;=]+|:\s*[^{;]+|where\s+[^{;]+|async|throw\s*\(\s*\)|requires\s+[^{;]+)*\s*$"
)
_ARROW_END_RE = re.compile(r"(?:=>|->)\s*$")
_JS_FUNC_RE = re.compile(r"\bfunction\b\s*\*?\s*([A-Za-z_$][\w$]*)?\s*(?:<[^()]*>)?\s*\(")
_JS_ARROW_NAME_RE = re.compile(
    r"([A-Za-z_$][\w$]*)\s*(?::\s*[^=]+?)?\s*[:=]\s*(?:async\s+)?(?:\([^()]*(?:\([^()]*\)[^()]*)*\)|[A-Za-z_$][\w$]*)"
    r"\s*(?::\s*[^=]+?)?\s*=>\s*$"
)
_JS_METHOD_RE = re.compile(
    r"^(?:(?:static|async|get|set|public|private|protected|readonly|override|abstract|declare|export|default)\s+|\*\s*)*"
    r"(#?[A-Za-z_$][\w$]*|\[[^\]]+\])\s*(?:<[^>]*>)?\s*\((?:[^()]|\([^()]*\))*\)\s*(?::\s*[^{;]+)?$"
)
_GO_FUNC_RE = re.compile(r"\bfunc\b\s*(?:\(\s*(?:\w+\s+)?\*?\s*([\w.]+)(?:\[[^\]]*\])?\s*\)\s*)?([A-Za-z_]\w*)?\s*[\[(]")
_RS_FN_RE = re.compile(r"\bfn\s+([A-Za-z_]\w*)")
_RS_CLOSURE_RE = re.compile(r"(?:move\s*)?\|[^|]*\|\s*(?:->\s*[^{]+)?$")
_PHP_FUNC_RE = re.compile(r"\bfunction\b\s*&?\s*([A-Za-z_]\w*)?\s*\(")
_PERL_SUB_RE = re.compile(r"\bsub\s+([\w:]+)")
_SHELL_FUNC_RE = re.compile(r"(?:\bfunction\s+([\w.-]+)|([\w.-]+)\s*\(\s*\))\s*$")
_KW_FUNC_RE = re.compile(r"\b(?:fun|func|def)\s+(?:<[^>]*>\s*)?(?:[\w.]+\.)?([A-Za-z_]\w*)")


def _blank_text(text):
    if "\n" not in text:
        return " " * len(text)
    return "\n".join(" " * len(part) for part in text.split("\n"))


def _strip_preprocessor(text):
    """Blank C preprocessor lines and, in each #if chain, every branch but the longest one.

    The longest branch (in non-blank lines) is usually the real code: a file that is
    wrapped in "#if !defined(X_INCLUDED) ... #else <the file> #endif" keeps its body,
    and two alternative headers of one function keep one header."""
    lines = text.split("\n")
    directive_lines = set()
    conditionals = []          # each: list of (first line, end line) branch ranges, 0-based
    stack = []
    continued = False
    for number, line in enumerate(lines):
        stripped = line.lstrip()
        if continued:
            directive_lines.add(number)
            continued = line.endswith("\\")
            continue
        if not stripped.startswith("#"):
            continue
        directive_lines.add(number)
        continued = line.endswith("\\")
        word = stripped[1:].lstrip()
        if word.startswith("if"):
            stack.append([[number + 1, None]])
        elif word.startswith(("else", "elif")) and stack:
            stack[-1][-1][1] = number
            stack[-1].append([number + 1, None])
        elif word.startswith("endif") and stack:
            branches = stack.pop()
            branches[-1][1] = number
            conditionals.append(branches)
    while stack:
        branches = stack.pop()
        branches[-1][1] = len(lines)
        conditionals.append(branches)
    blank = set(directive_lines)
    for branches in conditionals:
        if len(branches) < 2:
            continue
        sizes = [sum(1 for i in range(a, b) if lines[i].strip()) for a, b in branches]
        keep = max(range(len(branches)), key=lambda i: (sizes[i], -i))
        for index, (a, b) in enumerate(branches):
            if index != keep:
                blank.update(range(a, b))
    return "\n".join(" " * len(line) if number in blank else line for number, line in enumerate(lines))


def _strip_annotations(header):
    lines = [line for line in header.split("\n") if line.strip()]
    kept = []
    for line in lines:
        stripped = line.strip()
        if not kept and (stripped.startswith("@") or stripped.startswith("#[") or
                         (stripped.startswith("[") and stripped.endswith("]"))):
            continue
        kept.append(stripped)
    return " ".join(kept)


_ACCESS_RE = re.compile(r"\s*(?:(?:public|private|protected|internal)\s*(?:slots\s*|Q_SLOTS\s*)?:(?!:))+")


def _header_kind(header, lang, nested_in_function, parent_kind, raw_header=""):
    """Classify the text before an opening brace: (kind, name)."""
    text = header.strip()
    if not text:
        return "block", None
    flat = " ".join(text.split())
    if lang == "go":
        match = _GO_FUNC_RE.search(flat)
        if match and flat.rstrip().endswith((")", "]")) or (match and re.search(r"\)\s*[\w.*\[\]()\s,]*$", flat)):
            if match.group(2) and not nested_in_function:
                receiver = match.group(1)
                return "function", (receiver + "." + match.group(2)) if receiver else match.group(2)
            if re.search(r"\bfunc\s*\(", flat):
                return "closure", None
        if re.search(r"\b(?:struct|interface)\s*$", flat):
            return "container", None
        return "block", None
    if lang == "rust":
        match = _RS_FN_RE.search(flat)
        if match and not re.search(r"[;=]\s*$", flat):
            return "function", match.group(1)
        if _RS_CLOSURE_RE.search(flat):
            return "closure", None
        container = re.search(r"\b(impl|trait|mod)\b\s*(?:<[^>]*>\s*)?([\w:<>, ]*)", flat)
        if container:
            return "container", container.group(2).strip().split(" ")[-1] if container.group(2) else None
        return "block", None
    if lang == "php":
        match = _PHP_FUNC_RE.search(flat)
        if match:
            return ("function", match.group(1)) if match.group(1) else ("closure", None)
        container = _CONTAINER_RE.search(flat)
        if container and container.group(1) in ("class", "interface", "trait", "enum", "namespace"):
            return "container", container.group(2)
        return "block", None
    if lang == "perl":
        match = _PERL_SUB_RE.search(flat)
        if match:
            return "function", match.group(1)
        if re.search(r"\bsub\s*$", flat):
            return "closure", None
        return "block", None
    if lang == "shell":
        match = _SHELL_FUNC_RE.search(flat)
        if match and not nested_in_function:
            return "function", match.group(1) or match.group(2)
        return "block", None
    if lang in ("javascript", "typescript", "vue", "svelte"):
        match = _JS_FUNC_RE.search(flat)
        if match and _TRAIL_OK_RE.search(flat):
            return ("function", match.group(1)) if match.group(1) else ("closure", _js_callback_name(raw_header))
        if _ARROW_END_RE.search(flat):
            named = _JS_ARROW_NAME_RE.search(flat)
            if named and named.group(1) not in _CONTROL:
                return "function", named.group(1)
            return "closure", _js_callback_name(raw_header)
        container = _CONTAINER_RE.search(flat)
        if container and container.group(1) in ("class", "interface", "enum", "namespace", "module"):
            if not flat.endswith(")"):
                return "container", container.group(2)
        if parent_kind in (None, "container", "objlit"):
            method = _JS_METHOD_RE.match(_strip_annotations(text))
            if method and method.group(1).lstrip("#") not in _CONTROL and not flat.startswith(("if", "for", "while")):
                return "function", method.group(1)
        if re.search(r"(?:[=(,:\[?]|\breturn|=>)\s*$", flat) or flat.endswith("export default"):
            return "objlit", None
        return "block", None
    # C, C++, Objective-C, Java, Kotlin, Scala, Swift, Dart, Groovy, C#
    if _ARROW_END_RE.search(flat):
        return "closure", None
    if re.search(r"\]\s*\([^()]*\)\s*(?:mutable\s*)?(?:noexcept\s*)?(?:->\s*[\w:<>*&\s]+)?$", flat) and "[" in flat:
        return "closure", None
    if re.search(r"\bnew\s+[\w.<>\[\]]+\s*\([^)]*\)\s*$", flat):
        return "container", None
    signature = _strip_annotations(text)
    signature_flat = " ".join(signature.split())
    kw = _KW_FUNC_RE.search(signature_flat)
    if kw and lang in ("kotlin", "swift", "scala", "groovy") and not nested_in_function:
        return "function", kw.group(1)
    if _TRAIL_OK_RE.search(signature_flat) and not nested_in_function:
        for match in _C_NAME_RE.finditer(signature_flat):
            name = match.group(1).replace(" ", "")
            last = re.split(r"::|\.", name)[-1].lstrip("~")
            if last in _CONTROL:
                return "control", None
            before = signature_flat[:match.start()]
            if re.search(r"\bnew\s*$", before) or "=" in before.replace("==", "").replace("<=", "").replace(">=", ""):
                break
            return "function", name
    container = _CONTAINER_RE.search(signature_flat)
    if container:
        return "container", container.group(2)
    first = re.match(r"([A-Za-z_]+)", signature_flat)
    if first and first.group(1) in _CONTROL:
        return "control", None
    return "block", None


def _js_callback_name(raw):
    flat = " ".join((raw or "").split())
    route = re.search(r"\.(get|post|put|patch|delete|all|use)\s*\(\s*['\"`]([^'\"`]*)['\"`]", flat)
    if route:
        return route.group(1).upper() + " " + route.group(2)
    call = re.search(r"([A-Za-z_$][\w$.]*)\s*\([^()]*$", flat)
    if call:
        return call.group(1).split(".")[-1] + ".callback"
    return None


def _line_starts(text):
    return [m.start() for m in re.finditer("\n", text)]


def _comment_lines(text, spans):
    """Lines that hold only comment text (1-based), from comment spans of the text."""
    if not spans:
        return set()
    pieces = []
    last = 0
    for start, end in spans:
        pieces.append(text[last:start])
        pieces.append(_blank_text(text[start:end]))
        last = end
    pieces.append(text[last:])
    cleaned = "".join(pieces).split("\n")
    original = text.split("\n")
    candidates = set()
    newlines = _line_starts(text)
    for start, end in spans:
        first = bisect.bisect_right(newlines, start) + 1
        last_line = bisect.bisect_right(newlines, max(start, end - 1)) + 1
        candidates.update(range(first, last_line + 1))
    return {line for line in candidates
            if line <= len(original) and original[line - 1].strip() and not cleaned[line - 1].strip()}


def brace_blocks(text, lang):
    """Function and closure blocks of a brace language (1-based inclusive lines) and comment lines."""
    tokenizer = _TOKENIZERS[_BRACE_LANG[lang]]
    spans = []

    def blank(match):
        token = match.group(0)
        if token.startswith(("//", "/*", "#")):
            spans.append((match.start(), match.end()))
        return _blank_text(token)

    try:
        clean = tokenizer.sub(blank, text)
    except RecursionError:
        return [], set()
    comments = _comment_lines(text, spans)
    if lang in ("c", "cpp", "objc", "csharp"):
        clean = _strip_preprocessor(clean)
    newlines = _line_starts(clean)
    blocks = []
    stack = []      # (block index or -1, kind)
    boundary = 0
    for match in re.finditer(r"[{};]", clean):
        char = match.group(0)
        pos = match.start()
        if char == "{":
            header_start = max(boundary, pos - 800)
            header = clean[header_start:pos]
            parent = None
            nested = False
            for index, kind in reversed(stack):
                if kind in ("function", "closure", "control", "block"):
                    nested = True
                if index >= 0:
                    parent = index
                    break
            parent_kind = stack[-1][1] if stack else None
            access = _ACCESS_RE.match(header)
            if access:
                header_start += access.end()
                header = clean[header_start:pos]
            kind, name = _header_kind(header, lang, nested, parent_kind, text[header_start:pos])
            if kind in ("function", "closure"):
                stripped = len(header) - len(header.lstrip())
                start_line = bisect.bisect_right(newlines, header_start + stripped) + 1
                blocks.append(Block(start_line, None, name, kind, parent))
                stack.append((len(blocks) - 1, kind))
            else:
                stack.append((-1, kind))
            boundary = pos + 1
        elif char == "}":
            if stack:
                index, _kind = stack.pop()
                if index >= 0:
                    blocks[index].end = bisect.bisect_right(newlines, pos) + 1
            boundary = pos + 1
        else:
            boundary = pos + 1
    return _closed_blocks(blocks), comments


def _closed_blocks(blocks):
    """The blocks with an end line; parent indexes point into the returned list."""
    kept = {}
    result = []
    for index, block in enumerate(blocks):
        if block.end is not None and block.end >= block.start:
            kept[index] = len(result)
            result.append(block)
    for block in result:
        parent = block.parent
        while parent is not None and parent not in kept:
            parent = blocks[parent].parent
        block.parent = kept.get(parent) if parent is not None else None
    return result


def python_blocks(text):
    """Function blocks of a Python file (ast) and its comment and docstring lines."""
    comments = _prefix_comment_lines(text, ("#",))
    try:
        with warnings.catch_warnings():
            # Repository code can hold invalid escape sequences; the parse must stay quiet.
            warnings.simplefilter("ignore")
            tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return indent_blocks(text, "python"), comments
    blocks = []
    stack = [(tree.body, "", None)]
    while stack:
        body, prefix, parent = stack.pop()
        for node in body:
            if (isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant)
                    and isinstance(node.value.value, str)):
                comments.update(range(node.lineno, (node.end_lineno or node.lineno) + 1))
                continue
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                start = min([d.lineno for d in node.decorator_list] + [node.lineno])
                name = prefix + node.name
                blocks.append(Block(start, node.end_lineno or node.lineno, name, "function", parent))
                stack.append((node.body, name + ".", len(blocks) - 1))
            elif isinstance(node, ast.ClassDef):
                stack.append((node.body, prefix + node.name + ".", parent))
            else:
                for field in ("body", "orelse", "finalbody"):
                    inner = getattr(node, field, None)
                    if isinstance(inner, list) and inner and isinstance(inner[0], ast.stmt):
                        stack.append((inner, prefix, parent))
                for handler in getattr(node, "handlers", None) or ():
                    stack.append((handler.body, prefix, parent))
                for case in getattr(node, "cases", None) or ():
                    stack.append((case.body, prefix, parent))
    return blocks, comments


def _prefix_comment_lines(text, prefixes):
    return {number for number, line in enumerate(text.split("\n"), 1) if line.lstrip().startswith(prefixes)}


def _doc_heredoc_lines(text):
    """Elixir @doc and @moduledoc heredocs (documentation text with code examples)."""
    lines = text.split("\n")
    found = set()
    inside = False
    for number, line in enumerate(lines, 1):
        stripped = line.strip()
        if not inside and re.match(r'@(?:moduledoc|doc|typedoc)\s+(?:~[sS])?"""', stripped):
            inside = True
            found.add(number)
            continue
        if inside:
            found.add(number)
            if stripped.startswith('"""'):
                inside = False
    return found


_INDENT_DEF = {
    "python": re.compile(r"^([ \t]*)(?:async\s+)?def\s+(\w+)"),
    "ruby": re.compile(r"^([ \t]*)(?:(?:private|protected|public)\s+)?def\s+((?:self\.)?[\w?!=\[\]<>+\-*/%]+)"),
    "elixir": re.compile(r"^([ \t]*)(?:def|defp|defmacro|defmacrop|defguard|defguardp)\s+([\w?!]+)"),
    "lua": re.compile(r"^([ \t]*)(?:local\s+)?function\s+([\w.:]+)"),
}
_RUBY_BLOCK_RE = re.compile(r"^([ \t]*)(?:get|post|put|patch|delete|options|head)\s+['\"]([^'\"]*)['\"].*\bdo\b")
_ELIXIR_BLOCK_RE = re.compile(r"^([ \t]*)(?:test|describe|scope|pipeline|live_session)\s+.*\bdo\s*$")


def indent_blocks(text, lang):
    lines = text.split("\n")
    pattern = _INDENT_DEF[lang]
    uses_end = lang in ("ruby", "elixir", "lua")
    blocks = []
    for number, line in enumerate(lines):
        match = pattern.match(line)
        kind = "function"
        name = None
        if match:
            name = match.group(2)
        elif lang == "ruby":
            match = _RUBY_BLOCK_RE.match(line)
            if match:
                kind, name = "closure", match.group(2)
        if not match:
            continue
        indent = len(match.group(1).expandtabs(4))
        stripped = line.strip()
        if uses_end and (re.search(r"\bend\s*$", stripped) and stripped.count(" end") >= 1 or
                         (lang == "ruby" and re.search(r"\bdef\s+[\w.?!]+(?:\([^)]*\))?\s*=", stripped)) or
                         (lang == "elixir" and re.search(r",\s*do:", stripped))):
            end = number
            if lang == "elixir" and ", do:" in stripped:
                j = number + 1
                while j < len(lines) and (not lines[j].strip() or
                                          len(lines[j]) - len(lines[j].lstrip()) > indent):
                    j += 1
                end = j - 1
            blocks.append(Block(number + 1, end + 1, name, kind, None))
            continue
        end = None
        last_body = number
        for j in range(number + 1, len(lines)):
            other = lines[j]
            body = other.strip()
            if not body or body.startswith("#") or (lang == "lua" and body.startswith("--")):
                continue
            other_indent = len(other[: len(other) - len(other.lstrip())].expandtabs(4))
            if other_indent <= indent:
                if uses_end and body.startswith("end"):
                    end = j
                elif uses_end and other_indent == indent and body.startswith(
                        ("rescue", "ensure", "else", "elsif", "when", "catch", "after")):
                    last_body = j
                    continue
                else:
                    end = last_body
                break
            last_body = j
        if end is None:
            end = last_body
        blocks.append(Block(number + 1, end + 1, name, kind, None))
    _set_parents(blocks)
    return blocks


def erlang_blocks(text):
    lines = text.split("\n")
    blocks = []
    start = None
    name = None
    for number, line in enumerate(lines):
        code = line.split("%", 1)[0].rstrip()
        if start is None:
            match = re.match(r"^([a-z][\w]*)\s*\(", line)
            if match:
                start, name = number, match.group(1)
            else:
                continue
        if code.endswith("."):
            blocks.append(Block(start + 1, number + 1, name, "function", None))
            start = None
    return blocks


def lisp_blocks(text):
    lines = text.split("\n")
    starts = []
    for number, line in enumerate(lines):
        if line.startswith("("):
            match = re.match(r"^\((?:defn-?|defmethod|defmacro|defroutes|defhandler|def|deftest|defrecord|defprotocol|"
                             r"extend-type|extend-protocol|GET|POST|PUT|DELETE)\s+([^\s()\[\]]+)", line)
            starts.append((number, match.group(1) if match else None))
    blocks = []
    for k, (number, name) in enumerate(starts):
        end = starts[k + 1][0] - 1 if k + 1 < len(starts) else len(lines) - 1
        while end > number and not lines[end].strip():
            end -= 1
        if name:
            blocks.append(Block(number + 1, end + 1, name, "function", None))
    return blocks


def _set_parents(blocks):
    order = sorted(range(len(blocks)), key=lambda i: (blocks[i].start, -blocks[i].end))
    open_stack = []
    for i in order:
        block = blocks[i]
        while open_stack and blocks[open_stack[-1]].end < block.start:
            open_stack.pop()
        block.parent = open_stack[-1] if open_stack else None
        open_stack.append(i)


_LINE_COMMENT_PREFIXES = {
    "ruby": ("#",), "elixir": ("#",), "lua": ("--",), "erlang": ("%",), "clojure": (";",),
    "shell": ("#",), "perl": ("#",), "yaml": ("#",), "sql": ("--",), "html": ("<!--",),
    "template": ("<!--", "{#", "{{!", "<%#"), "erb": ("<%#",), "heex": ("<%#", "#"),
}


_SCRIPT_RE = re.compile(r"(<script\b[^>]*+>)(.*?)</script\s*>", re.IGNORECASE | re.DOTALL)
SCRIPT_HOSTS = frozenset({"html", "template", "vue", "svelte", "erb", "heex", "razor", "jsp"})


def script_blocks(text):
    """Blocks of the <script> parts of a template; the other text is masked."""
    pieces = []
    last = 0
    for match in _SCRIPT_RE.finditer(text):
        pieces.append(_blank_text(text[last:match.start(2)]))
        pieces.append(match.group(2))
        last = match.end(2)
    if not pieces:
        return [], _prefix_comment_lines(text, ("<!--",))
    pieces.append(_blank_text(text[last:]))
    blocks, comments = brace_blocks("".join(pieces), "javascript")
    return blocks, comments | _prefix_comment_lines(text, ("<!--",))


def function_blocks(text, lang):
    """(function and closure blocks, comment-only lines) of a file; no blocks without a rule."""
    if lang == "python":
        return python_blocks(text)
    if lang in SCRIPT_HOSTS:
        return script_blocks(text)
    if lang in _BRACE_LANG:
        return brace_blocks(text, lang)
    comments = _prefix_comment_lines(text, _LINE_COMMENT_PREFIXES[lang]) if lang in _LINE_COMMENT_PREFIXES else set()
    if lang == "elixir":
        comments |= _doc_heredoc_lines(text)
    if lang in ("ruby", "elixir", "lua"):
        return indent_blocks(text, lang), comments
    if lang == "erlang":
        return erlang_blocks(text), comments
    if lang == "clojure":
        return lisp_blocks(text), comments
    return [], comments


_METHOD_WORDS = ("get", "post", "put", "patch", "delete", "head", "options", "all", "any")
ROUTE_LINE_MAX = 1000                 # route and guard parsing reads at most this part of a line
_STRING_RE = re.compile(r"""'((?:[^'\\]++|\\.)*+)'|"((?:[^"\\]++|\\.)*+)"|`((?:[^`\\]++|\\.)*+)`""")
_GUARD_TOKEN_RE = re.compile(
    r"(?i)\b[\w.]*(?:auth|login|logged|permission|perm|role|admin|guard|policy|acl|csrf|verified|session|jwt|"
    r"token|protect|secure|require|ensure|signed|owner|privilege|access|can\b|middleware)[\w.]*"
)
_ROUTE_FRAMEWORK = {
    "route.express": "express", "route.nest": "nestjs", "route.nest_controller": "nestjs",
    "route.next_handler": "nextjs", "route.next_default": "nextjs", "route.server_action": "nextjs",
    "route.trpc": "trpc", "route.js_lambda": "lambda", "route.js_ws": "websocket",
    "route.flask": "flask", "route.fastapi": "fastapi", "route.django": "django", "route.py_view": "python-view",
    "route.aiohttp": "aiohttp", "route.py_lambda": "lambda", "route.spring": "spring", "route.jaxrs": "jax-rs",
    "route.servlet": "servlet", "route.ktor": "ktor", "route.jvm_queue": "message-listener",
    "route.jvm_grpc": "grpc", "route.es_rest": "elasticsearch-rest", "route.laravel": "laravel",
    "route.symfony": "symfony", "route.wp": "wordpress", "route.php_app": "php-router",
    "route.php_controller": "php-controller", "route.rails": "rails", "route.sinatra": "sinatra",
    "route.rails_controller": "rails-controller", "route.go_router": "go-router", "route.go_grpc": "grpc",
    "route.aspnet": "aspnet", "route.aspnet_controller": "aspnet-controller", "route.phoenix": "phoenix",
    "route.phoenix_module": "phoenix-module", "route.rust_web": "rust-web", "route.clj": "clojure-ring",
    "route.perl": "perl-web", "route.erl": "cowboy", "route.cli": "cli",
    "route.sig_go": "handler-signature", "route.sig_py": "handler-signature", "route.sig_js": "handler-signature",
    "route.sig_php": "handler-signature", "route.sig_cs": "handler-signature", "route.sig_ex": "handler-signature",
    "route.sig_rs": "handler-signature", "route.spring_controller": "spring",
    "route.c_ipc": "ipc", "route.c_ioctl": "ioctl", "route.c_table": "dispatch-table",
}
_DECORATOR_ROUTES = frozenset({
    "route.nest", "route.flask", "route.fastapi", "route.py_view", "route.spring", "route.jaxrs",
    "route.symfony", "route.aspnet", "route.rust_web", "route.jvm_queue", "route.servlet",
    "route.next_handler", "route.next_default", "route.py_lambda",
})


def parse_route(rule_id, line_text, path):
    """A route record from a route declaration line (method, route, framework, handler, guards)."""
    text = line_text.strip()[:ROUTE_LINE_MAX]
    method = None
    route = None
    handler = None
    framework = _ROUTE_FRAMEWORK.get(rule_id, "other")
    strings = [m.group(1) or m.group(2) or m.group(3) or "" for m in _STRING_RE.finditer(text)]
    if strings:
        route = next((s for s in strings if s.startswith("/")), strings[0])
    verb = re.search(r"(?i)(?:\.|@|::|\[Http|#\[|^\s*|\bMap)(get|post|put|patch|delete|del|head|options|all|any)"
                     r"(?:Mapping)?\b", text)
    if verb:
        method = verb.group(1).upper()
        if method == "DEL":
            method = "DELETE"
    if rule_id == "route.spring" and "RequestMapping" in text:
        explicit = re.search(r"RequestMethod\.(\w+)", text)
        method = explicit.group(1).upper() if explicit else None
    if rule_id in ("route.flask", "route.fastapi"):
        methods = re.search(r"methods\s*=\s*\[([^\]]*)\]", text)
        if methods:
            method = ",".join((m.group(1) or m.group(2) or m.group(3) or "").upper()
                              for m in _STRING_RE.finditer(methods.group(1))) or method
        elif rule_id == "route.flask":
            method = "GET"
    if rule_id == "route.next_handler":
        named = re.search(r"\b(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b", text)
        method = named.group(1) if named else None
        route = _next_route(path)
    elif rule_id == "route.next_default":
        route = _next_route(path)
    if rule_id == "route.laravel":
        pair = re.search(r"\[\s*([\w\\]+)::class\s*,\s*['\"](\w+)['\"]\s*\]", text)
        at = re.search(r"['\"]([\w\\]+)@(\w+)['\"]", text)
        if pair:
            handler = pair.group(1).split("\\")[-1] + "@" + pair.group(2)
        elif at:
            handler = at.group(1).split("\\")[-1] + "@" + at.group(2)
    elif rule_id == "route.rails":
        to = re.search(r"(?:to:|=>)\s*['\"](\w+)#(\w+)['\"]", text)
        if to:
            handler = to.group(1) + "#" + to.group(2)
    elif rule_id == "route.phoenix":
        to = re.search(r"\"\s*,\s*([\w.]+)\s*,\s*:(\w+)", text)
        if to:
            handler = to.group(1).split(".")[-1] + "#" + to.group(2)
    elif rule_id == "route.django":
        view = re.search(r"['\"]\s*,\s*([\w.]+)(?:\.as_view)?", text)
        if view:
            handler = view.group(1)
    elif rule_id == "route.c_table":
        row = re.search(r",\s*&?(\w+)\s*\}", text)
        if row:
            handler = row.group(1)
        command = re.search(r"\{\s*([A-Z][A-Z0-9_]*)", text)
        route = command.group(1) if command else route
    elif rule_id in ("route.express", "route.go_router", "route.php_app", "route.aspnet", "route.ktor"):
        if not re.search(r"=>|\bfunction\b|\bfunc\s*\(", text):
            tail = re.search(r",\s*([A-Za-z_$][\w$.]*)\s*\)*\s*;?\s*$", text)
            if tail and tail.group(1) not in ("true", "false", "null", "nil"):
                handler = tail.group(1)
    guard_text = _STRING_RE.sub(" ", text)
    guards = sorted({m.group(0) for m in _GUARD_TOKEN_RE.finditer(guard_text)
                     if m.group(0).lower() not in ("route", "router")})[:8]
    return {"method": method, "route": route, "framework": framework, "handler": handler, "guards": guards}


def _next_route(path):
    match = re.search(r"(?:^|/)(?:src/)?(pages|app)(/.*)$", path)
    if not match:
        return None
    rest = match.group(2)
    rest = re.sub(r"/(?:route|page|index)\.[cm]?[jt]sx?$", "", rest)
    rest = re.sub(r"\.[cm]?[jt]sx?$", "", rest)
    return rest or "/"


class Unit:
    __slots__ = ("path", "fid", "start", "end", "symbol", "lang", "kind", "signals", "tags", "raw",
                 "score", "features", "file_rank", "calls", "entry_depth")

    def __init__(self, fid, path, start, end, symbol, lang, kind, tags):
        self.fid = fid
        self.path = path
        self.start = start
        self.end = end
        self.symbol = symbol
        self.lang = lang
        self.kind = kind
        self.signals = []    # (kind, cls, cwe, line, rule id, text, weight)
        self.tags = tags
        self.raw = 0.0
        self.score = 0.0
        self.features = {}
        self.file_rank = 0
        self.calls = ()
        self.entry_depth = -1


def _windows(lines_with_signals, nlines, low=1, high=None):
    """Windows of nearby signal lines inside [low, high]."""
    high = high or nlines
    lines = sorted(set(lines_with_signals))
    groups = []
    current = [lines[0]]
    for line in lines[1:]:
        if line - current[-1] <= WINDOW_GAP and line - current[0] < WINDOW_MAX - 2 * WINDOW_PAD:
            current.append(line)
        else:
            groups.append(current)
            current = [line]
    groups.append(current)
    windows = []
    for group in groups:
        start = max(low, group[0] - WINDOW_PAD)
        end = min(high, group[-1] + WINDOW_PAD)
        windows.append((start, end, group))
    return windows


class FileContext:
    """Per-file facts that the unit score uses."""

    __slots__ = ("has_source", "has_route", "routes", "tags", "lines", "lang", "parse_timeout")

    def __init__(self):
        self.parse_timeout = False
        self.has_source = False
        self.has_route = False
        self.routes = []
        self.tags = set()
        self.lines = 0
        self.lang = None


def build_file_units(fid, rec, text, packed, parse_seconds=PARSE_SECONDS):
    """Units, route records and a context for one file with signals."""
    lines = text.split("\n")
    nlines = len(lines)
    context = FileContext()
    context.lines = nlines
    context.lang = rec.lang
    tags = set(rec.tags)
    head = text[:4096]
    if GENERATED_MARK_RE.search(head):
        tags.add("generated")
    if (nlines <= 5 and len(text) > 20_000) or (nlines and len(text) / nlines > 400 and len(text) > 20_000):
        tags.add("minified")
    context.tags = tags
    longest = max(map(len, lines)) if lines else 0
    if longest > MINIFIED_LINE:
        tags.add("minified")
    if longest > MINIFIED_LINE or len(text) > BLOCK_PARSE_MAX_BYTES:
        blocks, comment_lines = [], set()
    else:
        try:
            with TimeLimit(parse_seconds):
                blocks, comment_lines = function_blocks(text, rec.lang)
        except (_Timeout, RecursionError, MemoryError):
            blocks, comment_lines = [], set()
            context.parse_timeout = True
    entries = []
    seen = set()
    for value in packed:
        line, rule_index = value >> 10, value & 1023
        if (line, rule_index) in seen or line < 1 or line > nlines or line in comment_lines:
            continue
        seen.add((line, rule_index))
        rule = RULES[rule_index]
        if rule.kind == "route":
            if not _route_allowed(rule.id, rec.path, lines[line - 1]):
                continue
            if rule.id != "route.cli":
                context.has_route = True
        elif rule.kind == "source":
            context.has_source = True
        entries.append((line, rule))
    if not entries:
        return [], [], context, []
    controller = any(rule.id in CONTROLLER_RULES for _line, rule in entries)
    entries.extend(_structural_entries(blocks, lines, text, comment_lines, controller))
    owner = [-1] * (nlines + 2)
    for index in sorted(range(len(blocks)), key=lambda i: (blocks[i].start, -blocks[i].end)):
        block = blocks[index]
        start, end = max(1, block.start), min(nlines, block.end)
        if end >= start:
            owner[start:end + 1] = [index] * (end - start + 1)

    def unit_block(line):
        index = owner[line] if 0 <= line < len(owner) else -1
        for _step in range(64):
            if index < 0:
                break
            block = blocks[index]
            parent = block.parent
            if (block.kind == "closure" and parent is not None and block.end - block.start + 1 < SMALL_CLOSURE_LINES
                    and blocks[parent].end - blocks[parent].start + 1 <= MAX_FUNCTION_LINES):
                index = parent
                continue
            break
        return index

    by_block = defaultdict(list)
    loose = []
    for line, rule in entries:
        index = unit_block(line)
        if index >= 0:
            by_block[index].append((line, rule))
        else:
            loose.append((line, rule))
    units = []
    for index, items in by_block.items():
        block = blocks[index]
        length = block.end - block.start + 1
        if length <= MAX_FUNCTION_LINES:
            unit = Unit(fid, rec.path, block.start, block.end, block.name, rec.lang, "function", tags)
            _add_signals(unit, items, lines)
            units.append(unit)
        else:
            for start, end, group in _windows([line for line, _ in items], nlines, block.start, block.end):
                unit = Unit(fid, rec.path, start, end, block.name, rec.lang, "window", tags)
                _add_signals(unit, [item for item in items if start <= item[0] <= end], lines)
                units.append(unit)
    if loose:
        for start, end, group in _windows([line for line, _ in loose], nlines):
            unit = Unit(fid, rec.path, start, end, None, rec.lang, "window", tags)
            _add_signals(unit, [item for item in loose if start <= item[0] <= end], lines)
            units.append(unit)
    # Route records; a decorator or inline route makes its unit a route handler.
    routes = []
    route_lines = {}
    for line, rule in sorted(entries, key=lambda item: (item[0], item[1].id.startswith("route.sig_"), item[1].index)):
        if rule.kind != "route":
            continue
        if line in route_lines and not rule.id.startswith("struct."):
            continue
        if rule.id.startswith("struct."):
            for unit in units:
                if unit.start == line and unit.kind != "window":
                    unit.kind = "route-handler"
            continue
        record = parse_route(rule.id, lines[line - 1], rec.path)
        record["path"] = rec.path
        record["line"] = line
        route_lines[line] = record
        handler_unit = None
        for unit in units:
            if unit.start <= line <= unit.end and unit.kind != "window":
                if handler_unit is None or unit.end - unit.start < handler_unit.end - handler_unit.start:
                    handler_unit = unit
        if handler_unit is not None and (rule.id in _DECORATOR_ROUTES or handler_unit.start == line or
                                         line - handler_unit.start <= 3):
            handler_unit.kind = "route-handler"
            if not record["handler"]:
                record["handler"] = handler_unit.symbol
            record["guards"] = sorted(set(record["guards"]) | _block_guards(lines, handler_unit))[:8]
        routes.append(record)
    context.routes = routes
    _mark_unguarded_handlers(units)
    # Name-only units: functions with security or parser names and no signal.
    name_units = []
    covered = set(by_block)
    for index, block in enumerate(blocks):
        if index in covered or block.kind != "function" or not block.name:
            continue
        length = block.end - block.start + 1
        if length < 3 or length > MAX_FUNCTION_LINES:
            continue
        short = re.split(r"[.:]+", block.name)[-1]
        strong, _weak = _security_words(short)
        if strong or _parser_words(short):
            unit = Unit(fid, rec.path, block.start, block.end, block.name, rec.lang, "function", tags)
            name_units.append(unit)
    blocks_index = [(block.name, block.start, block.end) for block in blocks
                    if block.kind == "function" and block.name]
    all_units = units + name_units
    _attach_calls(all_units, text)
    return all_units, routes, context, blocks_index


CONTROLLER_RULES = frozenset({
    "route.php_controller", "route.rails_controller", "route.aspnet_controller", "route.nest_controller",
    "route.phoenix_module", "route.spring_controller",
})
_CALL_RE = re.compile(r"(?:^|[^.\w>$:])([A-Za-z_]\w{2,})\s*\(|\b(?:self|this)\s*(?:\.|->)\s*([A-Za-z_]\w{2,})\s*\(")
_NOT_HANDLER = frozenset({"constructor", "__construct", "__init__", "initialize", "init", "setup", "setUp",
                          "tearDown", "dispose", "ngOnInit", "ngOnDestroy", "toString", "equals", "hashCode"})
PARSER_WORDS = ("parse", "decode", "unpack", "inflate", "decompress", "deserial", "unmarshal", "read", "load",
                "recv", "receive", "scan", "lex", "import", "convert", "handle", "dispatch", "process", "check",
                "valid", "verify", "filter", "normaliz", "resolve")


def _parser_words(name):
    return [word for word in _symbol_words(name) if any(word.startswith(prefix) for prefix in PARSER_WORDS)]


def _structural_entries(blocks, lines, text, comment_lines, controller):
    """Signals that come from the structure of the code: recursion and controller methods."""
    found = []
    calls = defaultdict(list)
    for match in _CALL_RE.finditer(text):
        name = match.group(1) or match.group(2)
        calls[name].append(match.start())
    if calls:
        newlines = _line_starts(text)
        recursion = RULE_BY_ID["struct.recursion"]
        for block in blocks:
            if block.kind != "function" or not block.name:
                continue
            short = re.split(r"[.:]+", block.name)[-1]
            positions = calls.get(short)
            if not positions:
                continue
            hits = []
            for position in positions:
                line = bisect.bisect_right(newlines, position) + 1
                if block.start <= line <= block.end and line not in comment_lines:
                    hits.append(line)
            if hits and hits[0] <= block.start + 2:
                hits = hits[1:]
            if hits:
                found.append((hits[0], recursion))
    if controller:
        method = RULE_BY_ID["struct.controller_method"]
        for block in blocks:
            if block.kind != "function" or not block.name or block.parent is not None:
                continue
            short = re.split(r"[.:]+", block.name)[-1]
            if short.startswith("_") or short in _NOT_HANDLER or block.end - block.start < 1:
                continue
            header = " ".join(lines[block.start - 1:min(len(lines), block.start + 1)])
            if re.search(r"\b(?:private|protected)\b", header):
                continue
            found.append((block.start, method))
    return found


MAX_CALLS_PER_UNIT = 60
_COMMON_CALLS = frozenset(
    "len str int print printf sprintf format append push pop get set put add map filter list dict range "
    "assert require sizeof typeof isset empty count array keys values items string bool float char new "
    "return free malloc memcpy memset strlen strcmp strncmp error errorf log debug info warn panic make "
    "close open read write then catch resolve reject json parse equals tostring hashcode".split()
)


def _attach_calls(units, text):
    """The names that each function unit calls (for the entry-point distance)."""
    targets = [unit for unit in units if unit.kind != "window"]
    if not targets:
        return
    sites = []
    newlines = _line_starts(text)
    for match in _CALL_RE.finditer(text):
        name = (match.group(1) or match.group(2)).lower()
        if len(name) < 4 or name in _COMMON_CALLS:
            continue
        sites.append((bisect.bisect_right(newlines, match.start()) + 1, name))
    if not sites:
        return
    lines = [line for line, _name in sites]
    for unit in targets:
        low = bisect.bisect_left(lines, unit.start + 1)
        high = bisect.bisect_right(lines, unit.end)
        own = re.split(r"[.:#]+", unit.symbol)[-1].lower() if unit.symbol else ""
        names = []
        seen = set()
        for _line, name in sites[low:high]:
            if name != own and name not in seen:
                seen.add(name)
                names.append(sys.intern(name))
                if len(names) >= MAX_CALLS_PER_UNIT:
                    break
        unit.calls = tuple(names)


def _entry_depths(units, function_index):
    """Distance (0, 1, 2) of each function unit from an entry point by a name-based call graph.

    Entry units: route handlers, units with a route signal (not a CLI main) and units that read
    request input. A name with more than three definitions gives no edge."""
    by_block = {(unit.fid, unit.start, unit.end): unit for unit in units if unit.kind != "window"}
    frontier = []
    for unit in units:
        if unit.kind == "route-handler" or any(
                (s[0] == "route" and s[4] != "route.cli") or s[0] == "source" for s in unit.signals):
            unit.entry_depth = 0
            frontier.append(unit)
    for depth in (1, 2):
        following = []
        for unit in frontier:
            for name in unit.calls:
                definitions = function_index.get(name)
                if not definitions or len(definitions) > 3:
                    continue
                for fid, start, end, _name in definitions:
                    target = by_block.get((fid, start, end))
                    if target is not None and target.entry_depth < 0:
                        target.entry_depth = depth
                        following.append(target)
        frontier = following


def _mark_unguarded_handlers(units):
    """A handler without a guard, where most handlers of the file have one, gets a signal."""
    handlers = [unit for unit in units if unit.kind == "route-handler"]
    if len(handlers) < 3:
        return
    guarded = [unit for unit in handlers
               if any(s[0] == "guard" and s[1] in ("authz", "authn", "idor", "session") for s in unit.signals)]
    if len(guarded) * 2 < len(handlers) or len(guarded) == len(handlers):
        return
    note = f"no guard; {len(guarded)} of {len(handlers)} handlers of the file have one"
    for unit in handlers:
        if unit not in guarded:
            unit.signals.append(("sink", "authz", "CWE-862", unit.start, "struct.unguarded", note, 1.5))


def _route_allowed(rule_id, path, line_text):
    lowered = path.lower()
    if rule_id == "route.next_default":
        return bool(re.search(r"(?:^|/)pages/api/|(?:^|/)api/", lowered))
    if rule_id == "route.django":
        return "url" in lowered.rsplit("/", 1)[-1] or "route" in lowered
    if rule_id == "route.rails":
        return "route" in lowered
    if rule_id == "route.ktor":
        return lowered.endswith((".kt", ".kts"))
    if rule_id == "route.go_router":
        return '"/' in line_text or "HandleFunc" in line_text or "Handle(" in line_text
    return True


def _block_guards(lines, unit):
    found = set()
    for number in range(max(1, unit.start - 3), min(len(lines), unit.start + 2) + 1):
        text = lines[number - 1].strip()[:ROUTE_LINE_MAX]
        if text.startswith(("@", "#[", "[")) or "middleware" in text or "before_action" in text:
            for match in _GUARD_TOKEN_RE.finditer(text):
                found.add(match.group(0))
    return found


def _add_signals(unit, items, lines):
    for line, rule in sorted(items, key=lambda item: (item[0], item[1].index)):
        text = lines[line - 1].strip()[:TEXT_MAX] if 0 < line <= len(lines) else ""
        unit.signals.append((rule.kind, rule.cls, rule.cwe or CLASS_CWE.get(rule.cls), line, rule.id, text,
                             rule.weight))


def _aggregate(weights):
    if not weights:
        return 0.0
    ordered = sorted(weights, reverse=True)
    total = ordered[0]
    if len(ordered) > 1:
        total += 0.35 * ordered[1]
    if len(ordered) > 2:
        total += 0.2 * ordered[2]
    if len(ordered) > 3:
        total += 0.1 * sum(ordered[3:6])
    return total


def tag_multiplier(tags):
    value = 1.0
    for tag in tags:
        value *= TAG_MULTIPLIER.get(tag, 1.0)
    return max(value, 0.01)


def score_unit(unit, context):
    """The deterministic score of one unit and its feature values (score-v1)."""
    sink_classes = defaultdict(list)
    guard_weights = []
    source_weights = []
    route_weights = []
    semgrep_count = 0
    cli_entry = False
    classes = set()
    for kind, cls, _cwe, _line, _rule, _text, weight in unit.signals:
        if kind in ("sink", "semgrep"):
            sink_classes[cls].append(weight)
            classes.add(cls)
            if kind == "semgrep":
                semgrep_count += 1
        elif kind == "guard":
            guard_weights.append(weight)
            classes.add(cls)
        elif kind == "source":
            source_weights.append(weight)
        elif kind == "route":
            if _rule == "route.cli":
                cli_entry = True
            else:
                route_weights.append(weight)
    class_scores = sorted((_aggregate(ws) for ws in sink_classes.values()), reverse=True)
    sink_part = sum(score * (1.0 if k == 0 else 0.6) for k, score in enumerate(class_scores[:4]))
    guard_part = 0.6 * _aggregate(guard_weights)
    source_part = min(2.0, 0.5 * _aggregate(source_weights))
    if route_weights:
        route_part = 1.2 * max(route_weights)
    elif unit.kind == "route-handler":
        route_part = 1.0
    else:
        route_part = 0.3 if cli_entry else 0.0
    symbol_short = re.split(r"[.:]+", unit.symbol)[-1] if unit.symbol else ""
    strong, weak = _security_words(symbol_short)
    path_stem = unit.path.rsplit(".", 1)[0]
    path_strong, path_weak = _security_words(path_stem)
    access = _access_words(symbol_short)
    path_access = _access_words(path_stem)
    name_part = (0.35 * min(3, len(strong)) + 0.12 * min(2, len(weak)) + 0.1 * min(2, len(path_strong))
                 + 0.25 * min(2, len(access)) + 0.1 * min(1, len(path_access)))
    variety = 0.25 * max(0, len(classes) - 1)
    base = sink_part + guard_part + source_part + route_part + name_part + variety
    multiplier = 1.0
    has_sink = bool(class_scores)
    if has_sink and (source_weights or route_weights or unit.kind == "route-handler"):
        multiplier *= 1.35
    elif has_sink and (context.has_source or context.has_route):
        multiplier *= 1.12
    is_main = bool(symbol_short) and bool(MAIN_RE.match(symbol_short))
    if is_main:
        multiplier *= MAIN_FACTOR
    # unit.entry_depth is a feature only: as a score factor it ranked the vulnerable units lower.
    tags_value = tag_multiplier(unit.tags)
    multiplier *= tags_value
    lines = unit.end - unit.start + 1
    if lines > MAX_FUNCTION_LINES:
        multiplier *= 0.9
    score = base * multiplier
    features = {
        "sink_score": round(sink_part, 4), "guard_score": round(guard_part, 4),
        "source_score": round(source_part, 4), "route_score": round(route_part, 4),
        "name_score": round(name_part, 4), "variety": round(variety, 4),
        "n_sink": sum(len(ws) for ws in sink_classes.values()), "n_classes": len(classes),
        "max_sink_weight": max((max(ws) for ws in sink_classes.values()), default=0.0),
        "n_source": len(source_weights), "n_guard": len(guard_weights), "n_route": len(route_weights),
        "n_semgrep": semgrep_count, "name_strong": len(strong), "name_weak": len(weak),
        "path_strong": len(path_strong), "name_access": len(access), "path_access": len(path_access),
        "cli_entry": int(cli_entry), "is_main": int(is_main), "entry_depth": unit.entry_depth, "file_has_source": int(context.has_source),
        "file_has_route": int(context.has_route), "tag_multiplier": round(tags_value, 4),
        "lines": lines, "file_lines": context.lines, "multiplier": round(multiplier, 4),
    }
    return score, features


def file_upper_bound(packed, rec):
    """An upper bound of the score of any unit of a file (used to skip files)."""
    by_class = defaultdict(list)
    guards, sources, routes = [], [], []
    for value in packed:
        rule = RULES[value & 1023]
        if rule.kind == "sink":
            by_class[rule.cls].append(rule.weight)
        elif rule.kind == "guard":
            guards.append(rule.weight)
        elif rule.kind == "source":
            sources.append(rule.weight)
        elif rule.kind == "route":
            routes.append(rule.weight)
    class_scores = sorted((_aggregate(ws) for ws in by_class.values()), reverse=True)
    base = sum(score * (1.0 if k == 0 else 0.6) for k, score in enumerate(class_scores[:4]))
    base += 0.6 * _aggregate(guards) + min(2.0, 0.5 * _aggregate(sources))
    base += 1.2 * max(routes) if routes else 1.0
    base += 0.35 * 3 + 0.12 * 2 + 0.1 * 2 + 0.25 * 2 + 0.1 + 0.25 * (len(by_class) + 2)
    base += 0.6 * 1.5 + 0.6 * 1.0       # structural signals (unguarded handler, recursion) as further classes
    return base * 1.35 * tag_multiplier(rec.tags)


def _make_logger(log):
    if log is None:
        return None
    if callable(log):
        return log
    if hasattr(log, "write"):
        def write(message, stream=log):
            stream.write(message + "\n")
            try:
                stream.flush()
            except (OSError, ValueError):
                pass
        return write
    return None


def build_inventory(repo_root, *, deadline_seconds=1500.0, max_units=5000, log=None):
    """Build the phase-0 inventory of the repository at repo_root (see the module docstring)."""
    log = _make_logger(log)
    budget = Budget(deadline_seconds)
    root = os.path.abspath(os.fspath(repo_root))
    max_units = max(1, int(max_units))
    steps = {}
    partial = False
    force_python = os.environ.get("FUNNEL_INVENTORY_SCANNER") == "python"
    trace = os.environ.get("FUNNEL_INVENTORY_TRACE") == "1"

    # 1. Census
    mark = time.monotonic()
    files, census_counts, census_partial = census(root, budget, log)
    steps["census"] = round(time.monotonic() - mark, 3)
    partial |= census_partial

    # 2. Scan
    mark = time.monotonic()
    signals, scan_stats = scan(root, files, budget, log, force_python=force_python)
    steps["scan"] = round(time.monotonic() - mark, 3)
    partial |= scan_stats["partial"]

    # 3. Units
    mark = time.monotonic()
    stop_units = budget.at(0.8)
    order = sorted(signals, key=lambda fid: (-file_upper_bound(signals[fid], files[fid]), files[fid].path))
    bounds = {fid: file_upper_bound(signals[fid], files[fid]) for fid in order}
    all_units = []
    routes = []
    contexts = {}
    function_index = defaultdict(list)
    top_scores = []          # min-heap of the best unit scores
    keep = 3 * max_units
    files_skipped_bound = 0
    files_cut = 0
    parse_timeouts = 0
    for position, fid in enumerate(order):
        if time.monotonic() > stop_units:
            files_cut = len(order) - position
            partial = True
            break
        if len(top_scores) >= keep and bounds[fid] < top_scores[0]:
            files_skipped_bound = len(order) - position
            break
        rec = files[fid]
        try:
            with open(os.path.join(root, rec.path), "rb") as handle:
                data = handle.read(MAX_SCAN_BYTES + 1)
        except OSError:
            continue
        text = data.decode("utf-8", "replace")
        if trace and log:
            log(f"unit pass: {rec.path} {len(data)} bytes {text.count(chr(10)) + 1} lines rss={_memory_stats()}")
        parse_seconds = min(PARSE_SECONDS, max(0.2, stop_units - time.monotonic()))
        try:
            units, file_routes, context, blocks_index = build_file_units(fid, rec, text, signals[fid],
                                                                         parse_seconds)
        except (_Timeout, RecursionError, MemoryError):
            continue
        parse_timeouts += int(context.parse_timeout)
        rec.lines = context.lines
        contexts[fid] = context
        routes.extend(file_routes)
        for name, start, end in blocks_index:
            short = name.split(".")[-1].split("::")[-1].lower()
            if len(function_index[short]) < 8:
                function_index[short].append((fid, start, end, name))
        for unit in units:
            unit.raw, unit.features = score_unit(unit, context)
            if len(top_scores) < keep:
                heapq.heappush(top_scores, unit.raw)
            elif unit.raw > top_scores[0]:
                heapq.heapreplace(top_scores, unit.raw)
        all_units.extend(units)
    # Line counts of the files with signals that got no unit pass.
    for fid in order:
        rec = files[fid]
        if fid in contexts or time.monotonic() > budget.at(0.85):
            continue
        try:
            with open(os.path.join(root, rec.path), "rb") as handle:
                rec.lines = handle.read(MAX_SCAN_BYTES + 1).count(b"\n") + 1
        except OSError:
            pass

    # Handler links: a route that names its handler marks that function.
    _link_handlers(routes, all_units, function_index, files, contexts)
    _entry_depths(all_units, function_index)
    steps["units"] = round(time.monotonic() - mark, 3)

    # 4. Semgrep: not part of this release (the measured funnel ran without it).
    semgrep_stats = {"ran": False, "seconds": 0.0, "results": 0, "timed_out": False, "reason": "disabled"}
    steps["semgrep"] = 0.0

    # 5. Score and rank
    mark = time.monotonic()
    empty_context = FileContext()
    for unit in all_units:
        unit.raw, unit.features = score_unit(unit, contexts.get(unit.fid, empty_context))
    by_file = defaultdict(list)
    for unit in all_units:
        by_file[unit.fid].append(unit)
    for fid, units in by_file.items():
        units.sort(key=lambda u: (-u.raw, u.start))
        for rank, unit in enumerate(units):
            unit.file_rank = rank
            unit.score = unit.raw * (FILE_DECAY ** rank)
            unit.features["file_rank"] = rank
            unit.features["raw_score"] = round(unit.raw, 4)
    all_units.sort(key=lambda u: (-u.score, u.path, u.start))
    ranked = all_units[:max_units]
    steps["rank"] = round(time.monotonic() - mark, 3)

    # Output
    unit_out = []
    for number, unit in enumerate(ranked, 1):
        signals_out = []
        seen = set()
        ordered = sorted(unit.signals, key=lambda s: (-s[6], s[3]))
        for kind, cls, cwe, line, rule, text, _weight in ordered:
            key = (kind, rule, line)
            if key in seen:
                continue
            seen.add(key)
            signals_out.append({"kind": kind, "class": cls, "cwe": cwe, "line": line, "rule": rule, "text": text})
            if len(signals_out) >= MAX_SIGNALS_PER_UNIT_OUT:
                break
        name_strong, _ = _security_words((unit.symbol or "").split(".")[-1] if unit.symbol else "")
        if name_strong:
            signals_out.append({"kind": "name", "class": "name", "cwe": None, "line": unit.start,
                                "rule": "name:" + ",".join(sorted(set(name_strong))[:4]),
                                "text": (unit.symbol or "")[:TEXT_MAX]})
        signals_out.sort(key=lambda s: (s["line"], s["kind"], s["rule"]))
        unit_out.append({
            "id": f"u{number:05d}", "path": unit.path, "start_line": unit.start, "end_line": unit.end,
            "symbol": unit.symbol, "language": unit.lang, "kind": unit.kind, "signals": signals_out,
            "tags": sorted(unit.tags), "score": round(unit.score, 4), "features": unit.features,
        })
    file_scores = {}
    for fid, units in by_file.items():
        raws = sorted((u.raw for u in units), reverse=True)
        file_scores[fid] = raws[0] + 0.25 * sum(raws[1:4])
    files_out = []
    for fid in signals:
        rec = files[fid]
        score = file_scores.get(fid)
        if score is None:
            score = 0.25 * bounds.get(fid, 0.0)
        context = contexts.get(fid)
        tags = sorted(context.tags if context else rec.tags)
        files_out.append({"path": rec.path, "language": rec.lang, "lines": rec.lines, "tags": tags,
                          "signal_count": len(signals[fid]), "score": round(score, 4)})
    files_out.sort(key=lambda f: (-f["score"], f["path"]))
    files_out = files_out[:MAX_FILES_OUT]
    routes.sort(key=lambda r: (r["path"], r["line"]))
    routes_out = [{"path": r["path"], "line": r["line"], "method": r["method"], "route": r["route"],
                   "framework": r["framework"], "handler": r["handler"], "guards": r["guards"]}
                  for r in routes[:MAX_ROUTES_OUT]]
    by_language = Counter(rec.lang for rec in files)
    by_tag = Counter(tag for rec in files for tag in rec.tags)
    by_kind = Counter(unit.kind for unit in ranked)
    stats = {
        "files_total": len(files),
        "files_scanned": scan_stats["files_scanned"],
        "by_language": dict(sorted(by_language.items())),
        "by_tag": dict(sorted(by_tag.items())),
        "semgrep": semgrep_stats,
        "steps": steps,
        "engine": scan_stats["engine"],
        "skipped": {**{k: v for k, v in census_counts.items()}, **scan_stats["skipped"],
                    "files_skipped_by_bound": files_skipped_bound, "files_cut_by_deadline": files_cut,
                    "block_parse_timeouts": parse_timeouts},
        "files_with_signals": len(signals),
        "signals": scan_stats["signals"],
        "units_total": len(all_units),
        "units_by_kind": dict(sorted(by_kind.items())),
        "routes_total": len(routes),
        "rules": len(RULES),
        "score_version": SCORE_VERSION,
        "memory": _memory_stats(),
    }
    result = {
        "version": VERSION,
        "elapsed_seconds": round(budget.elapsed(), 3),
        "partial": bool(partial),
        "stats": stats,
        "files": files_out,
        "routes": routes_out,
        "units": unit_out,
    }
    if log:
        log(f"inventory: {len(unit_out)} units, {len(routes_out)} routes, {result['elapsed_seconds']} s, "
            f"partial={partial}")
    return result


def _link_handlers(routes, units, function_index, files, contexts):
    """Mark the functions that a route names as its handler (route-handler units)."""
    by_block = {(unit.fid, unit.start, unit.end): unit for unit in units if unit.kind != "window"}
    for record in routes:
        handler = record.get("handler")
        if not handler or record["framework"] in ("cli",):
            continue
        parts = re.split(r"[.@#:]+", handler)
        method = parts[-1].lower()
        hint = parts[-2].lower() if len(parts) > 1 else None
        candidates = function_index.get(method, [])
        if hint:
            hinted = [c for c in candidates if hint.replace("controller", "") in files[c[0]].path.lower()]
            if hinted:
                candidates = hinted
        if not candidates or len(candidates) > 3:
            continue
        for fid, start, end, name in candidates:
            unit = by_block.get((fid, start, end))
            if unit is None:
                rec = files[fid]
                context = contexts.get(fid)
                tags = context.tags if context else rec.tags
                unit = Unit(fid, rec.path, start, end, name, rec.lang, "route-handler", tags)
                units.append(unit)
                by_block[(fid, start, end)] = unit
            unit.kind = "route-handler"
            text = (f"{record.get('method') or ''} {record.get('route') or ''}".strip())[:TEXT_MAX]
            unit.signals.append(("route", "route", None, start, "route.handler-link", text, 1.0))


def main(argv=None):
    parser = argparse.ArgumentParser(description="The phase-0 inventory of the SentryTower funnel.")
    parser.add_argument("--repo", required=True, help="repository root (read only)")
    parser.add_argument("--out", required=True, help="output JSON file")
    parser.add_argument("--deadline-seconds", type=float, default=1500.0)
    parser.add_argument("--max-units", type=int, default=5000)
    parser.add_argument("--quiet", action="store_true", help="no progress lines on stderr")
    args = parser.parse_args(argv)
    started = time.monotonic()

    def log(message):
        sys.stderr.write(f"[inventory {time.monotonic() - started:7.1f}s] {message}\n")
        sys.stderr.flush()

    result = build_inventory(args.repo, deadline_seconds=args.deadline_seconds, max_units=args.max_units,
                             log=None if args.quiet else log)
    out = os.path.abspath(args.out)
    folder = os.path.dirname(out) or "."
    handle = tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=folder, prefix=".inventory-", suffix=".tmp",
                                         delete=False)
    try:
        with handle:
            json.dump(result, handle, ensure_ascii=False, separators=(",", ":"))
        os.chmod(handle.name, 0o644)
        os.replace(handle.name, out)
    except BaseException:
        try:
            os.unlink(handle.name)
        except OSError:
            pass
        raise
    return 0


if __name__ == "__main__":
    sys.exit(main())
