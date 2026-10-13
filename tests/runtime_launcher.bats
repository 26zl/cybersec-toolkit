#!/usr/bin/env bats

setup() {
    load 'test_helper'
    make_test_tmpdir
    BUNDLE_DIR="$TEST_TMPDIR/install folder/scanner"
    CALLER_DIR="$TEST_TMPDIR/caller folder"
    mkdir -p "$BUNDLE_DIR/.runtime" "$CALLER_DIR" "$TEST_TMPDIR/bin"
    cp "$PROJECT_ROOT/lib/runtime_launcher.py" "$BUNDLE_DIR/runtime_launcher.py"
    chmod +x "$BUNDLE_DIR/runtime_launcher.py"
    printf 'synthetic library fixture\n' > "$BUNDLE_DIR/.runtime/libfixture.so"
    python3 - "$BUNDLE_DIR/.runtime-launcher.json" <<'PY'
import json, sys
standard = 'output:o:p quiet:q:b timeline:t:p'
commands = {
    'inspect-items': 'level:l:v skipProgressBar:s:b '+standard,
    'build-report': standard+' rulepath:r:p dboutput:s:p compact:-:b skipProgressBar:-:b',
    'serve-report': 'timeline:t:p dboutput:s:p compact:-:b',
    'inspect-list': 'apiKey:a:v domainList:d:p jsonOutput:j:p output:o:p rateLimit:r:v quiet:q:b',
    'inspect-events': 'evtxDir:e:p '+standard,
    'batch': standard, 'extract': standard, 'split-table': standard,
    'split-json': standard, 'visualize': standard, 'visualize-rules': 'output:o:p rulesDir:r:p',
}
config = {
    'executable': 'scanner', 'working_directory': '.',
    'argument_style': 'cligen',
    'library_directories': ['.runtime'], 'required_files': ['.runtime/libfixture.so'],
    'commands': {name:'help:h:b version:-:b '+schema for name,schema in commands.items()},
    'informational_options': ['help','version'],
    'default_outputs': {name:{'output':value} for name,value in {
        'batch':'case-data', 'extract':'script-logs', 'split-table':'output',
        'split-json':'output', 'visualize':'heatmap.json', 'visualize-rules':'navigator.json',
    }.items()},
    'conditional_defaults': {name:{
        'option':'dboutput', 'default':'report.db', 'boolean_option':'compact', 'alternate':'report.compact',
    } for name in ('build-report','serve-report')},
}
with open(sys.argv[1],'w') as stream:
    json.dump(config,stream)
PY
    cat > "$BUNDLE_DIR/scanner" <<'EOF'
#!/usr/bin/env python3
import json, os, pathlib, signal, sys
pathlib.Path(os.environ['FIXTURE_CONTEXT']).write_text(json.dumps({
    'cwd':os.getcwd(), 'arguments':sys.argv[1:],
    'library':os.environ.get('LD_LIBRARY_PATH'),
    'pid':os.getpid(),
}))
print('synthetic stdout', flush=True)
print('synthetic stderr', file=sys.stderr, flush=True)
if os.environ.get('FIXTURE_SIGNAL'):
    os.kill(os.getpid(),getattr(signal,os.environ['FIXTURE_SIGNAL']))
sys.exit(int(os.environ.get('FIXTURE_EXIT', '0')))
EOF
    chmod +x "$BUNDLE_DIR/scanner"
    ln -s "$BUNDLE_DIR/runtime_launcher.py" "$TEST_TMPDIR/bin/scanner"
    export FIXTURE_CONTEXT="$TEST_TMPDIR/context.json"
    cd "$CALLER_DIR" || return 1
}

_context_assert() {
    python3 - "$FIXTURE_CONTEXT" "$@" <<'PY'
import json,sys
data=json.load(open(sys.argv[1]))
for argument in sys.argv[2:]:
    assert argument in data['arguments'], (argument, data['arguments'])
PY
}

@test "Runtime launcher resolves its PATH symlink and preserves streams and exit status" {
    run env FIXTURE_EXIT=23 LD_LIBRARY_PATH=/synthetic/inherited \
        "$TEST_TMPDIR/bin/scanner" inspect-items -t 'capture files/timeline.jsonl' \
        --output='report files/result.csv'

    assert_equal "$status" 23
    assert_output $'synthetic stdout\nsynthetic stderr'
    _context_assert "--timeline=$CALLER_DIR/capture files/timeline.jsonl" \
        "--output=$CALLER_DIR/report files/result.csv"
    python3 - "$FIXTURE_CONTEXT" "$BUNDLE_DIR" <<'PY'
import json,sys
data=json.load(open(sys.argv[1]))
assert data['cwd']==sys.argv[2]
assert data['library']==sys.argv[2]+'/.runtime:/synthetic/inherited'
PY
}

@test "Runtime launcher supports cligen style aliases prefixes colon assignments and bool bundles" {
    run "$TEST_TMPDIR/bin/scanner" iNsPeCt-iTe -qst'capture files/timeline.jsonl' \
        --o_U-t:'report files/result.csv'

    assert_success
    _context_assert -q -s "--timeline=$CALLER_DIR/capture files/timeline.jsonl" \
        "--output=$CALLER_DIR/report files/result.csv"
}

@test "Runtime launcher composes path string updates before anchoring the final path" {
    run "$TEST_TMPDIR/bin/scanner" inspect-items -t:../timeline.jsonl \
        --output=reports/ --output+=old.csv --output/=old/new

    assert_success
    _context_assert "--timeline=$CALLER_DIR/../timeline.jsonl" \
        "--output=$CALLER_DIR/reports/new.csv"
}

@test "Runtime launcher rewrites configured database and resource paths while preserving booleans" {
    run "$TEST_TMPDIR/bin/scanner" build-report -tfixture.jsonl -o'report folder' \
        -s:'db folder/case.db' -r'rule folder' --skipProgressBar

    assert_success
    _context_assert "--timeline=$CALLER_DIR/fixture.jsonl" \
        "--output=$CALLER_DIR/report folder" \
        "--dboutput=$CALLER_DIR/db folder/case.db" \
        "--rulepath=$CALLER_DIR/rule folder" --skipProgressBar
}

@test "Runtime launcher translates configured list file options while preserving scalar values" {
    run "$TEST_TMPDIR/bin/scanner" inspect-list -a 'synthetic scalar' \
        -d'domain list.txt' -j='response folder/result.json' -o'report.csv' -r 17

    assert_success
    _context_assert -a 'synthetic scalar' -r 17 \
        "--domainList=$CALLER_DIR/domain list.txt" \
        "--jsonOutput=$CALLER_DIR/response folder/result.json" \
        "--output=$CALLER_DIR/report.csv"
    run "$TEST_TMPDIR/bin/scanner" inspect-events -e'event logs' -t timeline.csv
    assert_success
    _context_assert "--evtxDir=$CALLER_DIR/event logs" "--timeline=$CALLER_DIR/timeline.csv"
}

@test "Runtime launcher keeps documented default output paths in the caller directory" {
    local command default_path path_option
    while IFS='|' read -r command default_path path_option; do
        run "$TEST_TMPDIR/bin/scanner" "$command" "-$path_option" fixture.jsonl
        assert_success
        _context_assert "--output=$CALLER_DIR/$default_path"
    done <<'EOF'
batch|case-data|t
extract|script-logs|t
split-table|output|t
split-json|output|t
visualize|heatmap.json|t
visualize-rules|navigator.json|r
EOF
}

@test "Runtime launcher anchors configured conditional defaults" {
    run "$TEST_TMPDIR/bin/scanner" serve-report -t fixture.jsonl
    assert_success
    _context_assert "--dboutput=$CALLER_DIR/report.db"

    run "$TEST_TMPDIR/bin/scanner" build-report -t fixture.jsonl -o report --compact
    assert_success
    _context_assert "--dboutput=$CALLER_DIR/report.compact"

    run "$TEST_TMPDIR/bin/scanner" build-report -t fixture.jsonl -o report --compact=false
    assert_success
    _context_assert "--dboutput=$CALLER_DIR/report.db"
}

@test "Runtime launcher preserves empty output paths and absolute paths" {
    run "$TEST_TMPDIR/bin/scanner" inspect-items --timeline=/synthetic/absolute.jsonl -o ''
    assert_success
    _context_assert --timeline=/synthetic/absolute.jsonl --output=
}

@test "Runtime help does not receive implicit output files" {
    run "$TEST_TMPDIR/bin/scanner" batch --help
    assert_success
    python3 - "$FIXTURE_CONTEXT" <<'PY'
import json,sys
assert json.load(open(sys.argv[1]))['arguments']==['batch','--help']
PY
}

@test "Runtime launcher refuses missing runtime or escaping executable manifests" {
    rm "$BUNDLE_DIR/.runtime/libfixture.so"
    run "$TEST_TMPDIR/bin/scanner" --help
    assert_failure
    assert_output --partial 'Required bundle runtime file is missing'
    [[ ! -f "$FIXTURE_CONTEXT" ]]

    python3 - "$BUNDLE_DIR/.runtime-launcher.json" <<'PY'
import json,sys
path=sys.argv[1]
data=json.load(open(path))
data['executable']='../outside'
with open(path,'w') as stream:
    json.dump(data,stream)
PY
    run "$TEST_TMPDIR/bin/scanner" --help
    assert_failure
    assert_output --partial 'Bundle paths must stay within the release directory'
    [[ ! -f "$FIXTURE_CONTEXT" ]]
}

@test "Runtime launcher supports bundles without shared libraries or command schemas" {
    python3 - "$BUNDLE_DIR/.runtime-launcher.json" <<'PY'
import json,sys
with open(sys.argv[1],'w') as stream:
    json.dump({'executable':'scanner'},stream)
PY
    run env LD_LIBRARY_PATH=/synthetic/inherited "$TEST_TMPDIR/bin/scanner" --unknown raw-argument
    assert_success
    _context_assert --unknown raw-argument
    python3 - "$FIXTURE_CONTEXT" <<'PY'
import json,sys
assert json.load(open(sys.argv[1]))['library']=='/synthetic/inherited'
PY
}

@test "Runtime launcher defaults to unmodified arguments for an unconfigured CLI style" {
    python3 - "$BUNDLE_DIR/.runtime-launcher.json" <<'PY'
import json,sys
path=sys.argv[1]
data=json.load(open(path))
del data['argument_style']
with open(path,'w') as stream:
    json.dump(data,stream)
PY
    run "$TEST_TMPDIR/bin/scanner" inspect-items -t relative.json --output=literal --output+=suffix
    assert_success
    python3 - "$FIXTURE_CONTEXT" <<'PY'
import json,sys
assert json.load(open(sys.argv[1]))['arguments']==[
    'inspect-items','-t','relative.json','--output=literal','--output+=suffix',
]
PY
}

@test "Runtime launcher preserves caller working directory when no directory is configured" {
    python3 - "$BUNDLE_DIR/.runtime-launcher.json" <<'PY'
import json,sys
with open(sys.argv[1],'w') as stream:
    json.dump({'executable':'scanner'},stream)
PY
    run "$TEST_TMPDIR/bin/scanner" --input relative.json --output report.json
    assert_success
    python3 - "$FIXTURE_CONTEXT" "$CALLER_DIR" <<'PY'
import json,sys
data=json.load(open(sys.argv[1]))
assert data['cwd']==sys.argv[2]
assert data['arguments']==['--input','relative.json','--output','report.json']
PY
}

@test "Runtime launcher replaces its process and preserves executable termination signals" {
    run python3 - "$TEST_TMPDIR/bin/scanner" "$FIXTURE_CONTEXT" <<'PY'
import json,os,signal,subprocess,sys
environment=os.environ.copy()
environment['FIXTURE_SIGNAL']='SIGTERM'
process=subprocess.Popen([sys.argv[1],'--help'],env=environment,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
process.communicate(timeout=5)
assert process.returncode==-signal.SIGTERM, process.returncode
assert json.load(open(sys.argv[2]))['pid']==process.pid
PY
    assert_success
}

@test "Runtime launcher supports executable subdirectories and a configured working directory" {
    mkdir "$BUNDLE_DIR/executables" "$BUNDLE_DIR/resources"
    mv "$BUNDLE_DIR/scanner" "$BUNDLE_DIR/executables/scanner"
    python3 - "$BUNDLE_DIR/.runtime-launcher.json" <<'PY'
import json,sys
path=sys.argv[1]
data=json.load(open(path))
data.update(executable='executables/scanner',working_directory='resources')
with open(path,'w') as stream:
    json.dump(data,stream)
PY
    run "$TEST_TMPDIR/bin/scanner" inspect-items -t evidence.jsonl
    assert_success
    _context_assert "--timeline=$CALLER_DIR/evidence.jsonl"
    python3 - "$FIXTURE_CONTEXT" "$BUNDLE_DIR/resources" <<'PY'
import json,sys
assert json.load(open(sys.argv[1]))['cwd']==sys.argv[2]
PY
}

@test "Runtime launcher rejects symlinked executable runtime and manifest files" {
    mv "$BUNDLE_DIR/scanner" "$BUNDLE_DIR/scanner-real"
    ln -s scanner-real "$BUNDLE_DIR/scanner"
    run "$TEST_TMPDIR/bin/scanner" --help
    assert_failure
    assert_output --partial 'Bundle paths must not use symlinks'
    [[ ! -f "$FIXTURE_CONTEXT" ]]
    rm "$BUNDLE_DIR/scanner"
    mv "$BUNDLE_DIR/scanner-real" "$BUNDLE_DIR/scanner"

    mv "$BUNDLE_DIR/.runtime" "$BUNDLE_DIR/library-files"
    ln -s library-files "$BUNDLE_DIR/.runtime"
    run "$TEST_TMPDIR/bin/scanner" --help
    assert_failure
    assert_output --partial 'Bundle paths must not use symlinks'
    [[ ! -f "$FIXTURE_CONTEXT" ]]
    rm "$BUNDLE_DIR/.runtime"
    mv "$BUNDLE_DIR/library-files" "$BUNDLE_DIR/.runtime"

    mv "$BUNDLE_DIR/.runtime-launcher.json" "$BUNDLE_DIR/config.json"
    ln -s config.json "$BUNDLE_DIR/.runtime-launcher.json"
    run "$TEST_TMPDIR/bin/scanner" --help
    assert_failure
    assert_output --partial 'Bundle paths must not use symlinks'
    [[ ! -f "$FIXTURE_CONTEXT" ]]
}

@test "Runtime launcher rejects malformed schemas and defaults before running the executable" {
    python3 - "$BUNDLE_DIR/.runtime-launcher.json" <<'PY'
import json,sys
path=sys.argv[1]
data=json.load(open(path))
data['commands']['inspect-items']='input:i:p invalid:i:v'
with open(path,'w') as stream:
    json.dump(data,stream)
PY
    run "$TEST_TMPDIR/bin/scanner" --help
    assert_failure
    assert_output --partial 'Invalid short option schema'
    [[ ! -f "$FIXTURE_CONTEXT" ]]
}

@test "Runtime launcher preserves the end of options marker and refuses missing path values" {
    run "$TEST_TMPDIR/bin/scanner" inspect-items -t evidence.jsonl -- --output=literal
    assert_success
    _context_assert "--timeline=$CALLER_DIR/evidence.jsonl" -- --output=literal
    rm "$FIXTURE_CONTEXT"
    run "$TEST_TMPDIR/bin/scanner" inspect-items --timeline
    assert_failure
    assert_output --partial 'Missing value for --timeline'
    [[ ! -f "$FIXTURE_CONTEXT" ]]
}

@test "disabled informational flags retain caller-relative output defaults" {
    local flag
    for flag in --help=false -h:false --version=0; do
        run "$TEST_TMPDIR/bin/scanner" batch "$flag"
        assert_success
        _context_assert "--output=$CALLER_DIR/case-data"
    done
    run "$TEST_TMPDIR/bin/scanner" build-report --help=false
    assert_success
    _context_assert "--dboutput=$CALLER_DIR/report.db"
}
