import "pe"

rule MAL_Compromised_Cert_ScreenConnect_GlobalSign_247DF4F340735BEFACC958F3 {
   meta:
      description         = "Detects ScreenConnect with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-02-13"
      version             = "1.0"

      hash                = "5238b57ce76064b977a6d5800f00f4120d795381f12fab93c7491997de6cfe67"
      malware             = "ScreenConnect"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "STEPHEN WHANG, CPA, INC."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "24:7d:f4:f3:40:73:5b:ef:ac:c9:58:f3"
      cert_thumbprint     = "A1E395A1317DC918673E3E63CA6F5EE51B321AF6"
      cert_valid_from     = "2026-02-13"
      cert_valid_to       = "2027-02-14"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "24:7d:f4:f3:40:73:5b:ef:ac:c9:58:f3"
      )
}
