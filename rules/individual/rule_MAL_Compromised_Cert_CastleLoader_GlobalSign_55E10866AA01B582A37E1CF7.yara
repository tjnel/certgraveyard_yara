import "pe"

rule MAL_Compromised_Cert_CastleLoader_GlobalSign_55E10866AA01B582A37E1CF7 {
   meta:
      description         = "Detects CastleLoader with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-08"
      version             = "1.0"

      hash                = "15f848dfe1797a6356ea510a4cc46985be164ef15e25a0496ff0882726ead4cc"
      malware             = "CastleLoader"
      malware_type        = "Unknown"
      malware_notes       = "C2: johnmacroskgf[.]com"

      signer              = "LLC MK Grand Stroy"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "55:e1:08:66:aa:01:b5:82:a3:7e:1c:f7"
      cert_thumbprint     = "2CE0A82B9EAE6DC5855FF1FF7C14752887FC841B"
      cert_valid_from     = "2026-04-08"
      cert_valid_to       = "2027-04-09"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "55:e1:08:66:aa:01:b5:82:a3:7e:1c:f7"
      )
}
