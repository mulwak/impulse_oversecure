# 管理者権限を強制
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole("Administrators")) { Start-Process pwsh.exe "-File `"$PSCommandPath`"" -Verb RunAs; echo $PSCommandPath; exit }

# 関数定義
# インタフェースインデックスを渡すと詳細を表示する
function Out-InterfaceInfo($if){
  $ifdata=(Get-NetIPConfiguration -ifIndex $if)
  Write-Host "`
 InterfaceDescription    : $($ifdata.InterfaceDescription)
 InterfaceIndex          : $($ifdata.InterfaceIndex)
 InterfaceAlias          : $($ifdata.InterfaceAlias)
 NetProfile              : $($ifdata.NetProfile.Name)
 IPv4Address             : $($ifdata.IPv4Address.ipaddress)
 IPv4DefaultGateway      : $($ifdata.IPv4DefaultGateway.nexthop)
  "
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
Out-InterfaceInfo $default_ifindex

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
Start-Sleep -Seconds 1

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
Out-InterfaceInfo $vpn_ifindex
read-host " - このインタフェースへのルーティングを無効化してよければ、Enterキーを押してください。"

# VPNインタフェースのレコードを消す
Get-NetRoute -addressfamily ipv4 -ifindex $vpn_ifindex | remove-netroute -confirm:$false
echo " * VPNインタフェースへのルーティングテーブルエントリを削除しました。"

# ルーティングテーブルの復旧
$null=&{
  # VPNに消されたエントリの追加
  compare-object ($clean_table|select-object -property interfaceindex,destinationprefix)`
                 ($connected_table|select-object -property interfaceindex,destinationprefix)|
    where-object {$_.sideindicator -like "<="} |
    foreach-object{$_.InputObject} |
    foreach-object{New-NetRoute -InterfaceIndex $_.interfaceindex -DestinationPrefix $_.destinationprefix -PolicyStore ActiveStore}
  # デフォルトゲートウェイの作成
  "0.0.0.0","128.0.0.0"|foreach-object{ # 0.0.0.0/0がなぜか機能しないので、上位1bitの2パターンに分けて定義
    $ip=$_
    new-NetRoute -DestinationPrefix "$ip/1" -ifIndex $default_ifindex -nexthop $default_nexthop -PolicyStore ActiveStore
    # なぜか発生する0.0.0.0hopを削除
    $restored_table=get-netroute -addressfamily ipv4 # 復旧されたテーブルを取得
    $dust_table=$restored_table|where-object{($_.destinationprefix -eq "$ip/1") -and ($_.ifindex -eq $default_ifindex) -and ($_.nexthop -eq 0.0.0.0)} # 削除リスト作成
    if($null -ne $dust_table){
      # 空でなければ削除
      $dust_table|remove-NetRoute -confirm:$false
    }
  }
}

echo " * 起動前のルーティングテーブルを復元しました。"

read-host

