import "pe"

rule MAL_Compromised_Cert_RdViewer_Certum_5ABB6B22CC40B9A35B7567962A5DF318 {
   meta:
      description         = "Detects RdViewer with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-11-05"
      version             = "1.0"

      hash                = "ff53740f61b315bfd8fe8276b50957ae5523272c1454347bccff4466a04f6d98"
      malware             = "RdViewer"
      malware_type        = "Unknown"
      malware_notes       = "https://rogueauthority.org/signed-disk-manager-installs-rdviewer-backdoor"

      signer              = "尹昌贵"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Code Signing 2021 CA"
      cert_serial         = "5a:bb:6b:22:cc:40:b9:a3:5b:75:67:96:2a:5d:f3:18"
      cert_thumbprint     = "173e900fecb797e20491936cec92abfa5ccdefdb"
      cert_valid_from     = "2026-11-05"
      cert_valid_to       = "2027-11-05"

      country             = "CN"
      state               = "安徽省"
      locality            = "泾县"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Code Signing 2021 CA" and
         sig.serial == "5a:bb:6b:22:cc:40:b9:a3:5b:75:67:96:2a:5d:f3:18"
      )
}
