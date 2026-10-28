# Prepare the exact upstream snapshot used by this build, then rebuild the launcher/runtime.
param(
    [string]$CompilerBin = 'C:\msys64\clang64\bin',
    [string]$BuildDirectory = 'build\nba18-prerelease-20261026-win'
)
$ErrorActionPreference = 'Stop'
$revision = '3eecea94ddaca360b19f4b800523b609a8b2ffcc'
$project = $PSScriptRoot
$runtime = Join-Path $project 'third_party\shadPS4-prerelease-3eecea9'
$build = Join-Path $project $BuildDirectory

$env:PATH = "$CompilerBin;$env:PATH"
foreach ($tool in @('git','cmake','ninja','clang','clang++','pkg-config')) {
    if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) {
        throw "Ferramenta não encontrada: $tool. Instale o toolchain MSYS2 CLANG64 e tente novamente."
    }
}

if (-not (Test-Path -LiteralPath $runtime)) {
    & git clone --filter=blob:none --no-checkout https://github.com/shadps4-emu/shadPS4.git $runtime
    if ($LASTEXITCODE -ne 0) { throw 'Falha ao obter o código-base shadPS4.' }
}
$head = (& git -C $runtime rev-parse HEAD 2>$null).Trim()
if ($head -ne $revision) {
    & git -C $runtime fetch origin $revision
    if ($LASTEXITCODE -ne 0) { throw 'Falha ao obter a revisão indicada do shadPS4.' }
    & git -C $runtime checkout --detach $revision
    if ($LASTEXITCODE -ne 0) { throw 'Falha ao selecionar a revisão indicada do shadPS4.' }
}
& git -C $runtime submodule update --init --recursive
if ($LASTEXITCODE -ne 0) { throw 'Falha ao obter os submódulos fixados por essa revisão.' }

$cmakeArgs = @(
    '-S', $project, '-B', $build, '-G', 'Ninja',
    "-DCMAKE_C_COMPILER=$CompilerBin\clang.exe",
    "-DCMAKE_CXX_COMPILER=$CompilerBin\clang++.exe",
    "-DCMAKE_ASM_COMPILER=$CompilerBin\clang.exe",
    '-DCMAKE_BUILD_TYPE=Release',
    '-DNBA16_BUILD_SHADPS4_RUNTIME=ON',
    '-DNBA16_BUILD_SHADPS4_CORE=ON',
    "-DNBA16_SHADPS4_SOURCE_DIR=$runtime",
    "-DNBA16_SHADPS4_CORE_PATCH=$project\patches\shadps4\nba16-reusable-core-prerelease.patch"
)
& cmake @cmakeArgs
if ($LASTEXITCODE -ne 0) { throw 'A configuração CMake falhou.' }
& cmake --build $build --target nba16-launcher --config Release --parallel
if ($LASTEXITCODE -ne 0) { throw 'A compilação falhou.' }
Write-Host "Executáveis compilados em: $(Join-Path $build 'shadPS4-runtime')"
