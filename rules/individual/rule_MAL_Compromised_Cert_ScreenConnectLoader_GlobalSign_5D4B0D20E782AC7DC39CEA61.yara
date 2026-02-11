import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_GlobalSign_5D4B0D20E782AC7DC39CEA61 {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-12-29"
      version             = "1.0"

      hash                = "edbb4d8d6b549ea5ec04e8a43e51d5fffad9276a52dacad8bba4ea09d9b41063"
      malware             = "ScreenConnectLoader"
      malware_type        = "Remote access tool"
      malware_notes       = "The malware was distributed disguised as a document, connects to the domain zkyhgfvluyvjh[.]im"

      signer              = "ALTERNATIVE HOME HEALTHCARE SERVICES LLC"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "5d:4b:0d:20:e7:82:ac:7d:c3:9c:ea:61"
      cert_thumbprint     = "33E8E4820D1E45C70467FA92480C03A362688F7C"
      cert_valid_from     = "2025-12-29"
      cert_valid_to       = "2026-12-30"

      country             = "US"
      state               = "South Carolina"
      locality            = "Lancaster"
      email               = "???"
      rdn_serial_number   = "00765152"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "5d:4b:0d:20:e7:82:ac:7d:c3:9c:ea:61"
      )
}
