import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_Sectigo_008A56400E67CF955565985A1EC21E6D90 {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-02-24"
      version             = "1.0"

      hash                = "13289da026158286a619c2aaa11efe2901ca5bb61c5d6b46681da338e7469cf7"
      malware             = "ScreenConnectLoader"
      malware_type        = "Remote access tool"
      malware_notes       = ""

      signer              = "ZHEJIANG WILLING FOREIGN TR CO MAKİNA TİCARET LİMİTED ŞİRKETİ"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "00:8a:56:40:0e:67:cf:95:55:65:98:5a:1e:c2:1e:6d:90"
      cert_thumbprint     = "BEE0E578D9819C58087DF6D620362E3088C11AAB"
      cert_valid_from     = "2026-02-24"
      cert_valid_to       = "2027-02-24"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "00:8a:56:40:0e:67:cf:95:55:65:98:5a:1e:c2:1e:6d:90"
      )
}
