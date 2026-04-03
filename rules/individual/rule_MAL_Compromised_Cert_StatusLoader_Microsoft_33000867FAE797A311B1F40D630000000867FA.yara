import "pe"

rule MAL_Compromised_Cert_StatusLoader_Microsoft_33000867FAE797A311B1F40D630000000867FA {
   meta:
      description         = "Detects StatusLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-14"
      version             = "1.0"

      hash                = "c78ab5681ef9ab603d45f1cfd92caa1b557a0d483adbabf462c1473e01a33653"
      malware             = "StatusLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Christopher Brown"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 01"
      cert_serial         = "33:00:08:67:fa:e7:97:a3:11:b1:f4:0d:63:00:00:00:08:67:fa"
      cert_thumbprint     = "10F6C9F961B152853B5BBFD669EABF7D016D3ED3"
      cert_valid_from     = "2026-03-14"
      cert_valid_to       = "2026-03-17"

      country             = "US"
      state               = "Arizona"
      locality            = "PHOENIX"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 01" and
         sig.serial == "33:00:08:67:fa:e7:97:a3:11:b1:f4:0d:63:00:00:00:08:67:fa"
      )
}
