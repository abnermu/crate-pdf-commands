# 判断是否已将原始的远程仓库名origin重命名为gitlab
function Is-Origin-Renamed {
    $remotev = git remote -v
    $remotevarr = $remotev -split '\s+'
    for ($i = 0; $i -lt $remotevarr.Length; $i += 3) {
        if ($remotevarr[$i] -eq "gitlab") {
            return $true
        }
    }
    return $false
}

# 判断是否已添加github远程仓库
function Is-Gitlhub-Added {
    $remotev = git remote -v
    $remotevarr = $remotev -split '\s+'
    for ($i = 0; $i -lt $remotevarr.Length; $i += 3) {
        if ($remotevarr[$i] -eq "github") {
            return $true
        }
    }
    return $false;
}

$renamed = Is-Origin-Renamed
if ($renamed) {
    Write-Host "gitlab远程仓库已重命名，无须再次操作。"
}
else {
    git remote rename origin gitlab
    Write-Host "gitlab远程仓库（origin）已重命名为gitlab。"
}

$githubadded = Is-Gitlhub-Added
if ($githubadded) {
    Write-Host "当前gitlab仓库已与github仓库关联完成，无须再次操作。"
}
else {
    git remote add github https://github.com/abnermu/crate-pdf-commands.git
    git push -u github main
    Write-Host "gitlab远程仓库已关联到github并进行了初始化push。"
}

# 执行外部命令，实际上是起了个命令行去跑命令，但这里边不需要这么做
# $process = Start-Process "git" -ArgumentList "remote", "-v" -PassThru
# $process.WaitForExit()
# Write-Host "git remote -v 命令执行结束"