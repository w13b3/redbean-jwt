local info = {
    _VERSION = "./test/init.lua 0.1.0",
    _URL = "github.com/w13b3/redbean-jwt",
    _SHORT_DESCRIPTION = "Test runner",
    _LONG_DESCRIPTION = [[
        Test runner
        Loads all the files in the test directory that start or end with 'test'

        Usage:
            # assuming current working directory is the root of the project
            ./redbean.com -F ./test/.init.lua
    ]],
    _LICENSE = [[
        Copyright 2022 w13b3

        Permission to use, copy, modify, and/or distribute this software for
        any purpose with or without fee is hereby granted, provided that the
        above copyright notice and this permission notice appear in all copies.

        THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
        WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
        WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
        AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
        DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
        PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
        TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
        PERFORMANCE OF THIS SOFTWARE.
    ]],
}

-- add .lua directory to package.path
package.path = string.format("%s;%s", ".lua/?.lua", package.path)
-- add test directory to package.path
package.path = string.format("%s;%s", "test/?.lua", package.path)

-- import the required modules which redbean provides
local re = require("re")
local path = require("path")
local unix = require("unix")

-- matches filename of the files that start or end with 'test'
local testFileRGX = re.compile([[(^test.+|.+test)\.]])

-- get the full test directory path
local cwd = assert(unix.getcwd())
cwd = assert(unix.realpath(cwd))
local testDir = path.join(cwd, "test")

if not path.exists(testDir) then
    print("No test directory found")
else
    -- test directory found
    local errorCount = 0

    -- loop over the files in the directory
    for name, kind in assert(unix.opendir(testDir)) do
        local match, stem = testFileRGX:search(name)
        if match and kind == unix.DT_REG then
            -- here the directory item is a file and a name match
            -- use pcall to catch any error
            local bool, error = pcall(require, stem)
            if not bool then
                errorCount = errorCount + 1
                -- write the error to stderr if one occurs
                io.stderr:write(("%s\n"):format(error))
            end
        end
    end
    -- log that the all the test have completed
    print(("Tests completed, %d failed"):format(errorCount))
    io.stdout:flush()
    io.stderr:flush()  -- clean the streams
    -- create exit code
    local exitCode = (errorCount <= 0 and 0 or 1)
    os.exit(exitCode)  -- quit redbean after all the tests
end
