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

# アドレスとサブネットマスクからネットワークアドレスを求める
function Calc-NetworkAddr($addr, $mask){
  return "$(Convert-DecimalToIP ((Convert-IPToDecimal $addr) -band (Convert-IPToDecimal $mask)))/$(Convert-SubnetMaskToCIDR $mask)"
}

function Do-Sequence(){
  # シーケンス冒頭
  Write-Host " [ スプリットトンネリング接続を開始します。 ]"
  Write-Host " * VPNクライアントソフトによる接続の前であることを確認してください。"

  # 起動前テーブル取得
  Write-Host " * 現状のルーティングテーブルを取得します。" -NoNewline
  $clean_table=get-netroute -addressfamily ipv4
  Write-Host "<OK>"

  # デフォルトゲートウェイ取得
  Write-Host " * デフォルトゲートウェイを取得します。" -NoNewline
  $default_route=$($clean_table|where-object destinationprefix -eq "0.0.0.0/0")[0]
  if($null -eq $default_route){
    Write-Host "<?>"
    Write-Host "[error] デフォルトゲートウェイが見つかりません。"
    return
  }else{
    $default_ifindex=$default_route.ifindex
    $default_nexthop=$default_route.nexthop
    Write-Host "<OK>"
    Write-Host " ** 検出されたデフォルトゲートウェイ **" -NoNewline
    Write-InterfaceInfo $default_ifindex
  }

  # VPN起動を待機
  Write-Host " * VPNクライアントソフトによる接続を待ち受けています…。" -NoNewline
  $new_dfgw_cnt=(get-netroute -AddressFamily ipv4 -DestinationPrefix "0.0.0.0/0").count
  do{
    $old_dfgw_cnt=$new_dfgw_cnt
    $new_dfgw_cnt=(get-netroute -AddressFamily ipv4 -DestinationPrefix "0.0.0.0/0").count
    Start-Sleep -Seconds 0.5
  }while($old_dfgw_cnt -eq $new_dfgw_cnt)

  # VPNインタフェースを特定
  Start-Sleep -Seconds 0.5
  $connected_table=get-netroute -addressfamily ipv4
  $clean_if_list=$clean_table|foreach-object{$_.ifindex}|select-object -unique|sort-object
  $new_if_list=$connected_table|foreach-object{$_.ifindex}|select-object -unique|sort-object
  $diff=compare-object $clean_if_list $new_if_list|where-object{$_.sideindicator -like "=>"}

  # インタフェース特定エラー処理
  if($diff.count -eq 0){
    Write-Host "<?>"
    Write-Host "[error] インタフェースが増えていません。"
    return
  }elseif($diff.count -ne 1){
    Write-Host "<?>"
    Write-Host "[error] インタフェースが2つ以上増えています。"
    return
  }else{
    Write-Host "<OK>"
  }

  # 確認表示
  Write-Host " ** 検出されたVPNネットワークインタフェース **"
  $vpn_ifindex=$diff.inputobject
  Write-InterfaceInfo $vpn_ifindex
  read-host " - このインタフェースへの経路を限定する操作をします。Enterキーを押してください。"

  # VPNインタフェースのレコードを消す
  Write-Host " * VPNインタフェースへのルーティングテーブルエントリを削除します。" -NoNewline
  Get-NetRoute -addressfamily ipv4 -ifindex $vpn_ifindex|
    where-object{$_.DestinationPrefix.split("/")[1] -ne 32}|  # 単一IPを対象とするものを除外
    remove-netroute -confirm:$false
  Write-Host "<OK>"

  # ルーティングテーブルの復旧
  $null=&{
    # VPNに消されたエントリの追加
    Write-Host " * VPNによって上書きされた経路を回復します。" -NoNewline
    @(compare-object $clean_table $connected_table -Property interfaceindex,destinationprefix) |
      where-object {$_.sideindicator -like "<="} |
      foreach-object{ `
        New-NetRoute  -InterfaceIndex $_.interfaceindex `
                      -DestinationPrefix $_.destinationprefix `
                      -PolicyStore ActiveStore
      }
    Write-Host "<OK>"
    # VPNネットワークに対する経路設定
    Write-Host " * 接続先ネットワークに対する経路のみをVPNインタフェースに設定します。"
    $vpn_myip=(Get-NetIPConfiguration | where-object interfaceindex -eq $vpn_ifindex).IPv4Address.IPaddress
    $vpn_networkaddr=Calc-NetworkAddr $vpn_myip $vpn_subnetmask
    Write-Host "   * 接続先ネットワーク：$vpn_networkaddr"
    New-NetRoute -DestinationPrefix $vpn_networkaddr `
                 -ifindex $vpn_ifindex `
                 -PolicyStore ActiveStore
    Write-Host "   * <OK>"
    # デフォルトゲートウェイの作成
    Write-Host " * デフォルトゲートウェイを再設定します。" -NoNewline
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
    Write-Host "<OK>"
  }

  Write-Host " [ スプリットトンネリング設定が完了しました。 ]"

  read-host
}


# 挨拶
Write-Host " [ Impulse Oversecure ]"
Do-Sequence
# TODO:メニューダイアログ
# 終了、ルーティングテーブルの表示、再度接続
#
read-host

