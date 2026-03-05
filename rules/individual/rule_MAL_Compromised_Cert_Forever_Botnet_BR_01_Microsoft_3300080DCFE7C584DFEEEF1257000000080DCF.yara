import "pe"

rule MAL_Compromised_Cert_Forever_Botnet_BR_01_Microsoft_3300080DCFE7C584DFEEEF1257000000080DCF {
   meta:
      description         = "Detects Forever Botnet,BR-01 with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-02-26"
      version             = "1.0"

      hash                = "698b6bcbdcc300ccc14569ad066872125e670571fbf2b24c721fdfbb6323959f"
      malware             = "Forever Botnet,BR-01"
      malware_type        = "Unknown"
      malware_notes       = "Malware campaign targeting BR users via fake documents. C2: jmkkload[.]com/bba13d314ed6c2ec94/"

      signer              = "Julie Jorgensen"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 01"
      cert_serial         = "33:00:08:0d:cf:e7:c5:84:df:ee:ef:12:57:00:00:00:08:0d:cf"
      cert_thumbprint     = "883B807ECEC8262ECF5DD31FFB62B9F8765D1304"
      cert_valid_from     = "2026-02-26"
      cert_valid_to       = "2026-03-01"

      country             = "US"
      state               = "Maryland"
      locality            = "BALTIMORE"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 01" and
         sig.serial == "33:00:08:0d:cf:e7:c5:84:df:ee:ef:12:57:00:00:00:08:0d:cf"
      )
}
