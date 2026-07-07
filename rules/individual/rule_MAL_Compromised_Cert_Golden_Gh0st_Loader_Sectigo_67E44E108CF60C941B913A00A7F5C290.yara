import "pe"

rule MAL_Compromised_Cert_Golden_Gh0st_Loader_Sectigo_67E44E108CF60C941B913A00A7F5C290 {
   meta:
      description         = "Detects Golden Gh0st Loader with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-10-31"
      version             = "1.0"

      hash                = "778f20d1c46f2427238c3e8c38fb3825fd3af80a022d03aa56be0dca2a1a593a"
      malware             = "Golden Gh0st Loader"
      malware_type        = "Remote access tool"
      malware_notes       = ""

      signer              = "Gemini Technologies Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "67:e4:4e:10:8c:f6:0c:94:1b:91:3a:00:a7:f5:c2:90"
      cert_thumbprint     = "D0C56580D299E65612564CBE9D875E5EAA470AB6"
      cert_valid_from     = "2025-10-31"
      cert_valid_to       = "2026-10-31"

      country             = "CN"
      state               = "Sichuan Sheng"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "67:e4:4e:10:8c:f6:0c:94:1b:91:3a:00:a7:f5:c2:90"
      )
}
