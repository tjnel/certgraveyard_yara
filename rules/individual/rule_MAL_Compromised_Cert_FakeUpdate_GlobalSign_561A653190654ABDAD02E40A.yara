import "pe"

rule MAL_Compromised_Cert_FakeUpdate_GlobalSign_561A653190654ABDAD02E40A {
   meta:
      description         = "Detects FakeUpdate with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-02-17"
      version             = "1.0"

      hash                = "6a2642ed05187a4d428eb7c9b609b03c69a427a9a0508c419b15ad277a518e73"
      malware             = "FakeUpdate"
      malware_type        = "Unknown"
      malware_notes       = "Malicious installer impersonating a Google Update"

      signer              = "WASH & CUT HAIR SALOON LIMITED"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "56:1a:65:31:90:65:4a:bd:ad:02:e4:0a"
      cert_thumbprint     = "FB69800B66B67DC2F225A83B047629A26D716CCC"
      cert_valid_from     = "2026-02-17"
      cert_valid_to       = "2027-02-18"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "56:1a:65:31:90:65:4a:bd:ad:02:e4:0a"
      )
}
