#!/bin/sh
# /*─────────────────────────────────────────────────────────────────╗
# │ To the extent possible under law, Matthew Pherigo has waived     │
# │ all copyright and related or neighboring rights to this file,    │
# │ as it is written in the following disclaimers:                   │
# │   • http://unlicense.org/                                        │
# ╚─────────────────────────────────────────────────────────────────*/
# extended from source: github.com/ProducerMatt/redbean-template  d81c2e7

OUT="redbean.com"
OUT_CMD="./${OUT}" # called with "build.sh run"

#OUT_CMD="./${OUT} -SSS" # extra-sandboxed version of redbean
# NOTE: https://redbean.dev/#security

RB_VERSION="latest"

RB_URL="https://redbean.dev/redbean-${RB_VERSION}.com"
STOCK=".rb-${RB_VERSION}_stock.com"
ZIP_URL="https://redbean.dev/zip.com"
SQLITE_URL="https://redbean.dev/sqlite3.com"
DEFINITIONS_URL="https://raw.githubusercontent.com/jart/cosmopolitan/master/tool/net/definitions.lua"

_Fetch() {
    # $1 = target filesystem location
    # $2 = URL
    echo "Getting $1 from $2"
    if command -v wget >/dev/null 2>&1; then
        wget -NqcO ".tmp" $2 || exit
    elif command -v curl >/dev/null 2>&1; then
        curl -so ".tmp" -z ".tmp" $2 || exit
    elif command -v fetch >/dev/null 2>&1; then
        fetch -mo ".tmp" $2 || exit
    else echo "No downloaders!"; exit 1;
    fi
    mv -f ".tmp" $1
}

_Init () {
    u=`umask`;
    umask 222;
    _Fetch "$STOCK" "$RB_URL";
    _Fetch "zip.com" "$ZIP_URL";
    chmod +x "zip.com"
    _Fetch "sqlite.com" "$SQLITE_URL";
    chmod +x "sqlite.com"
    mkdir -m 755 -p definitions
    _Fetch "definitions/redbean.lua" "$DEFINITIONS_URL"
    umask $u;
}

_Pack () {
    cp -f $STOCK $OUT
    chmod u+w $OUT
    chmod +x $OUT
    cd srv/ || exit
    ../zip.com -qr "../$OUT" "$(ls -A)"
    cd ..
}

_Clean () {
    rm -f zip.com sqlite.com $STOCK $OUT definitions/redbean.lua .tmp
    [ "$(ls -A definitions)" ] || rm -rf definitions
}

_Test () {
  # $2 = test file path
  TEST_FILE="./test/.init.lua"
  if [ -n "${2}" ]; then
    TEST_FILE="${2}"
  fi

  # -F 	eval Lua code in file
  exec $OUT_CMD -F ${TEST_FILE}
}

case "$1" in
    init )
        _Init;
        ;;
    pack )
        _Pack;
        ;;
    run )
        _Pack;
        exec $OUT_CMD;
        ;;
    test )
        _Pack;
        _Test "${@}";
        ;;
    clean )
        _Clean;
        ;;
    * )
        echo "a builder for redbean projects"
        echo "- '$0 init': fetch redbean, zip and sqlite"
        echo "- '$0 pack': pack \"./srv/\" into a new redbean, overwriting the old"
        echo "- '$0 run': pack, then execute with a customizable command"
        echo "- '$0 test': pack, execute the run.lua and quit redbean"
        echo "- '$0 clean': delete all downloaded and generated files"
        ;;
esac
