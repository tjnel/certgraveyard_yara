import "pe"

rule MAL_Compromised_Cert_Remcos_RAT_GlobalSign_258E91BD0C0CC0A8C4BC5D8A {
   meta:
      description         = "Detects Remcos RAT with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-11-27"
      version             = "1.0"

      hash                = "a08293e23e09d53692aca4b20974f270e48c58c53532c6cc715993d24e928e35"
      malware             = "Remcos RAT"
      malware_type        = "Remote access tool"
      malware_notes       = "File's metadata claims to be a CrowdStrike Falcon installer."

      signer              = "HYPERBOLA TRADECOM LIMITED"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "25:8e:91:bd:0c:0c:c0:a8:c4:bc:5d:8a"
      cert_thumbprint     = "2CD39CB64393756174636228F62B47E2EB0698AE"
      cert_valid_from     = "2025-11-27"
      cert_valid_to       = "2026-11-28"

      country             = "IN"
      state               = "West Bengal"
      locality            = "Kolkata"
      email               = "???"
      rdn_serial_number   = "U74900WB2013PLC191576"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "25:8e:91:bd:0c:0c:c0:a8:c4:bc:5d:8a"
      )
}
