param(
    [string]$Python = "$PSScriptRoot\..\.venv\Scripts\python.exe",
    [string]$OutputRoot = 'dist\v1.0.0'
)
$ErrorActionPreference = 'Stop'
Push-Location "$PSScriptRoot\.."
try {
    $destination = Join-Path $OutputRoot 'RemoteCaptureDesk'
    if (Test-Path -LiteralPath $destination) {
        throw '输出目录已存在。为避免批量删除，请指定新的 -OutputRoot，或自行处理已有输出。'
    }
    & $Python -m PyInstaller --distpath $OutputRoot scripts\RemoteCaptureDesk.spec
    if ($LASTEXITCODE -ne 0) { throw 'Windows 程序打包失败' }
    Copy-Item -LiteralPath README.md -Destination (Join-Path $destination '使用说明.md')
    if (Test-Path TEST_REPORT.md) { Copy-Item -LiteralPath TEST_REPORT.md -Destination (Join-Path $destination '测试报告.md') }
    & $Python scripts\collect_licenses.py $destination
    if ($LASTEXITCODE -ne 0) { throw '复制第三方许可失败' }
    Write-Output "程序：$destination\RemoteCaptureDesk.exe（请保留整个目录）"
} finally { Pop-Location }
