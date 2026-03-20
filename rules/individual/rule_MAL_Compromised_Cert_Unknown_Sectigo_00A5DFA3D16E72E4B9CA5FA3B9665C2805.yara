import "pe"

rule MAL_Compromised_Cert_Unknown_Sectigo_00A5DFA3D16E72E4B9CA5FA3B9665C2805 {
   meta:
      description         = "Detects Unknown with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-01-23"
      version             = "1.0"

      hash                = "e0ba6b57913ae6c29a18ccee23bdd17263f062bbdb25feef0ba43b23cd54d0f3"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Xiamen Lede Song Information Technology Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "00:a5:df:a3:d1:6e:72:e4:b9:ca:5f:a3:b9:66:5c:28:05"
      cert_thumbprint     = "FEC827C25EF8D92D9647E0BC10A5B444C94F2901"
      cert_valid_from     = "2026-01-23"
      cert_valid_to       = "2027-01-23"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "00:a5:df:a3:d1:6e:72:e4:b9:ca:5f:a3:b9:66:5c:28:05"
      )
}
