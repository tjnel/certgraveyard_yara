import "pe"

rule MAL_Compromised_Cert_UpdateLogger_GlobalSign_481C460436F5FCAE70171C7C {
   meta:
      description         = "Detects UpdateLogger with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-05-04"
      version             = "1.0"

      hash                = "8718dc15475c3e12d5bdae6d3153229b12358a45d0f7d095d8da743a4696a7d9"
      malware             = "UpdateLogger"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Soft Journeys Design LLC"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "48:1c:46:04:36:f5:fc:ae:70:17:1c:7c"
      cert_thumbprint     = "3ad83aaa1cdf728ce9f8b181d2ceddde1a54c1e1"
      cert_valid_from     = "2026-05-04"
      cert_valid_to       = "2027-05-05"

      country             = "US"
      state               = "Arizona"
      locality            = "Mesa"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "48:1c:46:04:36:f5:fc:ae:70:17:1c:7c"
      )
}
