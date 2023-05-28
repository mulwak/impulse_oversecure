Set-StrictMode -Version 1.0

# 管理者権限を強制
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole("Administrators")) { Start-Process pwsh.exe "-File `"$PSCommandPath`"" -Verb RunAs; exit }

# configロード
. ".\config.ps1"
$vpn_subnetmask=$config_vpn_subnetmask

# 関数定義
# インタフェースインデックスを渡すと詳細を表示する
function Write-InterfaceInfo($if){
  $ifdata=(Get-NetIPConfiguration -ifIndex $if)
  $ifdata | Select-Object InterfaceDescription,`
                          InterfaceIndex,`
                          InterfaceAlias,`
                          @{n="NetProfile";e={$_.NetProfile.name}},`
                          @{n="IPv4Address";e={$_.IPv4Address.IPAddress}},`
                          @{n="IPv4DefaultGateway";e={$_.IPv4DefaultGateway.nexthop}}
}

# IPアドレス表記 -> 整数
function Convert-IPToDecimal {
    param (
        [Parameter(Mandatory=$true)]
        [string]$ip
    )

    $ipSegments = $ip.Split('.')
    if ($ipSegments.Count -ne 4) {
        Write-Error "Invalid IP address"
        return
    }

    $decimalIP = 0
    for ($i = 0; $i -lt 4; $i++) {
        $decimalIP += [int]$ipSegments[$i] * [Math]::Pow(256, 3 - $i)
    }

    return $decimalIP
}

# 整数 -> IPアドレス表記
function Convert-DecimalToIP {
    param (
        [Parameter(Mandatory=$true)]
        [int64]$decimal
    )

    if ($decimal -lt 0 -or $decimal -gt 4294967295) {
        Write-Error "Invalid decimal for IP conversion"
        return
    }

    $ip = New-Object -TypeName System.Collections.Generic.List[int]
    for ($i = 0; $i -lt 4; $i++) {
        $ip.Insert(0, $decimal % 256)
        $decimal = $decimal -shr 8
    }

    return ($ip -join '.')
}

# サブネットマスク -> CIDR
function Convert-SubnetMaskToCIDR {
    param (
        [Parameter(Mandatory=$true)]
        [string]$subnetMask
    )

    $subnetMaskSegments = $subnetMask.Split('.')
    if ($subnetMaskSegments.Count -ne 4) {
        Write-Error "Invalid subnet mask"
        return
    }

    $cidr = 0
    foreach ($segment in $subnetMaskSegments) {
        $bin = [Convert]::ToString([int]$segment, 2)
        $cidr += ($bin.ToCharArray() | Where-Object { $_ -eq '1' }).Count
    }

    return $cidr
}

# アドレスとサブネットマスクからドメインを求める
function Calc-Domain($addr, $mask){
  return "$(Convert-DecimalToIP ((Convert-IPToDecimal $addr) -band (Convert-IPToDecimal $mask)))/$(Convert-SubnetMaskToCIDR $mask)"
}

# 挨拶
echo "[Impulse Oversecure]"
echo " * VPNクライアントソフトによる接続前であることを確認してください。"

# 起動前テーブル取得
$clean_table=get-netroute -addressfamily ipv4
echo " * 現状ルーティングテーブルを取得しました。"
$default_ifindex=(get-netroute -DestinationPrefix 0.0.0.0/0)[0].ifindex
$default_nexthop=(get-netroute -DestinationPrefix 0.0.0.0/0)[0].nexthop
#echo " * デフォルトゲートウェイ：${default_nexthop}"
#echo "    * インタフェース：「$((Get-netipinterface -AddressFamily ipv4 -ifindex $default_ifindex).interfacealias)」 (ifindex=${default_ifindex})"
Write-InterfaceInfo $default_ifindex

# VPN起動を待機
echo " * VPNクライアントソフトによる接続を待機中。"
#read-host " - 接続が完了したらEnterキーを押してください。"
$new_dfgw_cnt=(get-netroute -AddressFamily ipv4 -DestinationPrefix 0.0.0.0/0).count
do{
  $old_dfgw_cnt=$new_dfgw_cnt
  $new_dfgw_cnt=(get-netroute -AddressFamily ipv4 -DestinationPrefix 0.0.0.0/0).count
  #echo "$old_dfgw_cnt $new_dfgw_cnt"
  Start-Sleep -Seconds 0.5
}while($old_dfgw_cnt -eq $new_dfgw_cnt)
Start-Sleep -Seconds 0.5

# VPNインタフェースを特定
$connected_table=get-netroute -addressfamily ipv4
$clean_if_list=$clean_table|foreach-object{$_.ifindex}|select-object -unique|sort-object
$new_if_list=$connected_table|foreach-object{$_.ifindex}|select-object -unique|sort-object
$diff=compare-object $clean_if_list $new_if_list|where-object{$_.sideindicator -like "=>"}

# インタフェース特定エラー処理
if($diff.count -eq 0){
  echo "[error] インタフェースが増えていません。"
  exit
}elseif($diff.count -ne 1){
  echo "[error] インタフェースが2つ以上増えています。"
  exit
}

# 確認表示
$vpn_ifindex=$diff.inputobject
#echo " * VPNインタフェースを検出しました：「$((Get-netipinterface -AddressFamily ipv4|where-object {$_.ifindex -like $vpn_ifindex}).interfacealias)」 (ifindex=${vpn_ifindex})"
Write-InterfaceInfo $vpn_ifindex
read-host " - このインタフェースへのルーティングを無効化してよければ、Enterキーを押してください。"

# VPNインタフェースのレコードを消す
Get-NetRoute -addressfamily ipv4 -ifindex $vpn_ifindex|
  where-object{$_.DestinationPrefix.split("/")[1] -ne 32}|  # 単一IPを対象とするものを除外
  remove-netroute -confirm:$false
echo " * VPNインタフェースへのルーティングテーブルエントリを削除しました。"

# ルーティングテーブルの復旧
$null=&{
  # VPNに消されたエントリの追加
  @(compare-object $clean_table $connected_table -Property interfaceindex,destinationprefix) |
    where-object {$_.sideindicator -like "<="} |
    foreach-object{ `
      New-NetRoute  -InterfaceIndex $_.interfaceindex `
                    -DestinationPrefix $_.destinationprefix `
                    -PolicyStore ActiveStore
    }
  # VPNドメインに対する経路設定
  $vpn_myip=(Get-NetIPConfiguration | where-object interfaceindex -eq $vpn_ifindex).IPv4Address.IPaddress
  New-NetRoute -DestinationPrefix $(Calc-Domain $vpn_myip $vpn_subnetmask) `
               -ifindex $vpn_ifindex `
               -PolicyStore ActiveStore
  # デフォルトゲートウェイの作成
  "0.0.0.0","128.0.0.0"|foreach-object{ # 0.0.0.0/0がなぜか機能しないので、上位1bitの2パターンに分けて定義
    $ip=$_
    new-NetRoute -DestinationPrefix "$ip/1" `
                 -ifIndex $default_ifindex `
                 -nexthop $default_nexthop `
                 -PolicyStore ActiveStore
    # なぜか発生する0.0.0.0hopを削除
    $restored_table=get-netroute -addressfamily ipv4 # 復旧されたテーブルを取得
    $dust_table=$restored_table|where-object{($_.destinationprefix -eq "$ip/1") -and ($_.ifindex -eq $default_ifindex) -and ($_.nexthop -eq "0.0.0.0")} # 削除リスト作成
    if($null -ne $dust_table){
      # 空でなければ削除
      $dust_table|remove-NetRoute -confirm:$false
    }
  }
}

echo " * 起動前のルーティングテーブルを復元しました。"

read-host

