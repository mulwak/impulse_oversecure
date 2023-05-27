# 管理者権限を強制
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole("Administrators")) { Start-Process pwsh.exe "-File `"$PSCommandPath`"" -Verb RunAs; echo $PSCommandPath; exit }

# 挨拶
echo "[Impulse Oversecure]"
echo " * VPNクライアントソフトによる接続前であることを確認してください。"

# 起動前テーブル取得
$clean_table=get-netroute -addressfamily ipv4
echo " * 現状ルーティングテーブルを取得しました。"
$default_ifindex=(get-netroute -DestinationPrefix 0.0.0.0/0)[0].ifindex
$default_nexthop=(get-netroute -DestinationPrefix 0.0.0.0/0)[0].nexthop
echo " * デフォルトゲートウェイ：${default_nexthop}"
echo "    * インタフェース：$((Get-netipinterface -AddressFamily ipv4|where-object {$_.ifindex -like $default_ifindex}).interfacealias) (ifindex=${default_ifindex})"

# VPN起動を待機
echo " * VPNクライアントソフトによる接続をしてください。"
read-host " - 接続が完了したらEnterキーを押してください。"

# VPNインタフェースを特定
$new_table=get-netroute -addressfamily ipv4
$clean_if_list=$clean_table|foreach-object{$_.ifindex}|select-object -unique|sort-object
$new_if_list=$new_table|foreach-object{$_.ifindex}|select-object -unique|sort-object
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
echo " * VPNインタフェースを特定しました："
Get-netipinterface -AddressFamily ipv4|where-object {$_.ifindex -like $vpn_ifindex}
read-host " - このインタフェースへのルーティングを無効化するには、Enterキーを押してください。"

# VPNインタフェースのレコードを消す
Get-NetRoute -addressfamily ipv4 -ifindex $vpn_ifindex | remove-netroute -confirm false
echo " * VPNインタフェースへのルーティングテーブルエントリを削除しました。"

# ルーティングテーブルの復旧
$null=&{
  # VPNに消されたエントリの追加
  compare-object $clean_table $new_table |
    where-object {$_.sideindicator -like "<="} |
    foreach-object{$_.InputObject} |
    foreach-object{New-NetRoute -InterfaceIndex $_.interfaceindex `
      -DestinationPrefix $_.destinationprefix -PolicyStore ActiveStore}
  # デフォルトゲートウェイの作成
  0,128|foreach-object{ # 0.0.0.0/0がなぜか機能しないので、上位1bitの2パターンに分けて定義
    new-NetRoute -DestinationPrefix "$_/1" `
      -ifIndex $default_ifindex -nexthop $default_nexthop -PolicyStore ActiveStore
    remove-NetRoute -DestinationPrefix "$_/1" ` # なぜか発生する0.0.0.0hopを削除
      -ifIndex $default_ifindex -nexthop 0.0.0.0 -PolicyStore ActiveStore -confirm false
  }
}

echo " * 起動前のルーティングテーブルを復元しました。"

