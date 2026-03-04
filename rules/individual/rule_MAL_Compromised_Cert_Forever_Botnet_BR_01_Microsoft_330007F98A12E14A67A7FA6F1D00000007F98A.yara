import "pe"

rule MAL_Compromised_Cert_Forever_Botnet_BR_01_Microsoft_330007F98A12E14A67A7FA6F1D00000007F98A {
   meta:
      description         = "Detects Forever Botnet,BR-01 with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-02-24"
      version             = "1.0"

      hash                = "fa0bea1d8ca48f71e5f0a89c943bcccb4837d8f3f71a804772e4b8451a069020"
      malware             = "Forever Botnet,BR-01"
      malware_type        = "Unknown"
      malware_notes       = "Malware campaign targeting BR users via fake documents. C2: segurancak[.]org"

      signer              = "Julie Jorgensen"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 01"
      cert_serial         = "33:00:07:f9:8a:12:e1:4a:67:a7:fa:6f:1d:00:00:00:07:f9:8a"
      cert_thumbprint     = "EE12224017440A2F82AFA4BE22D0611D8AA809A7"
      cert_valid_from     = "2026-02-24"
      cert_valid_to       = "2026-02-27"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 01" and
         sig.serial == "33:00:07:f9:8a:12:e1:4a:67:a7:fa:6f:1d:00:00:00:07:f9:8a"
      )
}
