import "pe"

rule MAL_Compromised_Cert_Forever_Botnet_BR_01_Microsoft_3300072BFDB49FB17014EC2F01000000072BFD {
   meta:
      description         = "Detects Forever Botnet,BR-01 with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-01"
      version             = "1.0"

      hash                = "1936cdf04ecac3f44c463f6db324cea93f7f6e4b3498212b89005a49054098b1"
      malware             = "Forever Botnet,BR-01"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Julie Jorgensen"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 01"
      cert_serial         = "33:00:07:2b:fd:b4:9f:b1:70:14:ec:2f:01:00:00:00:07:2b:fd"
      cert_thumbprint     = "3DF9FB8296CCD50B6FAE7092B301B95965A7A4EE"
      cert_valid_from     = "2026-03-01"
      cert_valid_to       = "2026-03-04"

      country             = "US"
      state               = "Maryland"
      locality            = "BALTIMORE"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 01" and
         sig.serial == "33:00:07:2b:fd:b4:9f:b1:70:14:ec:2f:01:00:00:00:07:2b:fd"
      )
}
