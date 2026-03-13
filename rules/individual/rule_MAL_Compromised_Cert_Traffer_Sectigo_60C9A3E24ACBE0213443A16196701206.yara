import "pe"

rule MAL_Compromised_Cert_Traffer_Sectigo_60C9A3E24ACBE0213443A16196701206 {
   meta:
      description         = "Detects Traffer with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-02-27"
      version             = "1.0"

      hash                = "b1285b1622d7236bc61d09d2602f36521c7a3cc5a9decb95f3c4090f3841b7a6"
      malware             = "Traffer"
      malware_type        = "Unknown"
      malware_notes       = "Fake software targeting crypto users worldwide"

      signer              = "Xiamen Nexsea Technology Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "60:c9:a3:e2:4a:cb:e0:21:34:43:a1:61:96:70:12:06"
      cert_thumbprint     = "C5A0E2881DED0B0CFD9F13B1F09CA2DA21EAE4A1"
      cert_valid_from     = "2026-02-27"
      cert_valid_to       = "2027-02-27"

      country             = "---"
      state               = "---"
      locality            = "---"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "60:c9:a3:e2:4a:cb:e0:21:34:43:a1:61:96:70:12:06"
      )
}
