import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_Sectigo_00EA351A91002323088C3B25ACB951C549 {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-28"
      version             = "1.0"

      hash                = "c308360ef189136c2b1b4fab167394cce5d361a405f84f51c9714a6bf586f4b0"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "XRYUS TECHNOLOGIES LIMITED"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "00:ea:35:1a:91:00:23:23:08:8c:3b:25:ac:b9:51:c5:49"
      cert_thumbprint     = "7646621277243AF67367CED7E6E00FDA544AB2CF"
      cert_valid_from     = "2026-04-28"
      cert_valid_to       = "2027-04-28"

      country             = "JP"
      state               = "Tokyo"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "2900-01-095356"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "00:ea:35:1a:91:00:23:23:08:8c:3b:25:ac:b9:51:c5:49"
      )
}
