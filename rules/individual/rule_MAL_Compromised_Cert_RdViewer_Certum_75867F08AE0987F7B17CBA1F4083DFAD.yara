import "pe"

rule MAL_Compromised_Cert_RdViewer_Certum_75867F08AE0987F7B17CBA1F4083DFAD {
   meta:
      description         = "Detects RdViewer with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-01"
      version             = "1.0"

      hash                = "9d1f17fa9d12198165a507f4d4bee2b730318492b8f756354b5b1be7bb444b76"
      malware             = "RdViewer"
      malware_type        = "Remote access tool"
      malware_notes       = ""

      signer              = "Changwen Li"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Code Signing 2021 CA"
      cert_serial         = "75:86:7f:08:ae:09:87:f7:b1:7c:ba:1f:40:83:df:ad"
      cert_thumbprint     = "8021279bbf27d44d2b03d266ff7b207f43c9b0a8"
      cert_valid_from     = "2026-04-01"
      cert_valid_to       = "2027-04-01"

      country             = "CN"
      state               = "Hebei"
      locality            = "Qinhuangdao"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Code Signing 2021 CA" and
         sig.serial == "75:86:7f:08:ae:09:87:f7:b1:7c:ba:1f:40:83:df:ad"
      )
}
