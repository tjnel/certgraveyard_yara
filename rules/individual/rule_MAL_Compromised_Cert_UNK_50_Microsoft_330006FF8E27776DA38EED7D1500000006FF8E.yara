import "pe"

rule MAL_Compromised_Cert_UNK_50_Microsoft_330006FF8E27776DA38EED7D1500000006FF8E {
   meta:
      description         = "Detects UNK-50 with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-02-19"
      version             = "1.0"

      hash                = "22ba925d5a801655ddd6012e066c270fd5065933611cd0dc88a71c2c779b39ae"
      malware             = "UNK-50"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Anquesia Gray"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 01"
      cert_serial         = "33:00:06:ff:8e:27:77:6d:a3:8e:ed:7d:15:00:00:00:06:ff:8e"
      cert_thumbprint     = "E726048E3BE74AFA9944BE517B69338C558C8773"
      cert_valid_from     = "2026-02-19"
      cert_valid_to       = "2026-02-22"

      country             = "US"
      state               = "Georgia"
      locality            = "Atlanta"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 01" and
         sig.serial == "33:00:06:ff:8e:27:77:6d:a3:8e:ed:7d:15:00:00:00:06:ff:8e"
      )
}
