import "pe"

rule MAL_Compromised_Cert_CastleLoader_GlobalSign_75E94AE5DFB761F53B22F808 {
   meta:
      description         = "Detects CastleLoader with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-07"
      version             = "1.0"

      hash                = "c4691308fff4cb451b600e9e47598d711015e051256f666e71397443b8fac4dc"
      malware             = "CastleLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "MillerSoft OÜ"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "75:e9:4a:e5:df:b7:61:f5:3b:22:f8:08"
      cert_thumbprint     = "3FA4698020A51320C0E94D954F380CFA3AB6D0B5"
      cert_valid_from     = "2026-04-07"
      cert_valid_to       = "2027-04-08"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "75:e9:4a:e5:df:b7:61:f5:3b:22:f8:08"
      )
}
