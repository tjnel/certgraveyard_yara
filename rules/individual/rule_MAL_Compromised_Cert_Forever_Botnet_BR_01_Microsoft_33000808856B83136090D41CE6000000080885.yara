import "pe"

rule MAL_Compromised_Cert_Forever_Botnet_BR_01_Microsoft_33000808856B83136090D41CE6000000080885 {
   meta:
      description         = "Detects Forever Botnet,BR-01 with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-08"
      version             = "1.0"

      hash                = "e81c9825936156152f52ab17caae50cd5a457c58ea714880629f5dcd2637c9cf"
      malware             = "Forever Botnet,BR-01"
      malware_type        = "Unknown"
      malware_notes       = "Malware campaign targeting BR users via fake documents. C2: jmkkload[.]com/bba13d314ed6c2ec94/"

      signer              = "Jerry Hayes"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 02"
      cert_serial         = "33:00:08:08:85:6b:83:13:60:90:d4:1c:e6:00:00:00:08:08:85"
      cert_thumbprint     = "920E7B97EC4281F019BFDD58809A42E59D43C8AD"
      cert_valid_from     = "2026-03-08"
      cert_valid_to       = "2026-03-11"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 02" and
         sig.serial == "33:00:08:08:85:6b:83:13:60:90:d4:1c:e6:00:00:00:08:08:85"
      )
}
