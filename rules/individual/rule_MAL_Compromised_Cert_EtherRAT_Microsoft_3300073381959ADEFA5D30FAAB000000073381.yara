import "pe"

rule MAL_Compromised_Cert_EtherRAT_Microsoft_3300073381959ADEFA5D30FAAB000000073381 {
   meta:
      description         = "Detects EtherRAT with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-03"
      version             = "1.0"

      hash                = "87f1d74617e1654644ad2e49b4bb471d0026a7552a5ae8bc9e281f3f3b1dc97f"
      malware             = "EtherRAT"
      malware_type        = "Unknown"
      malware_notes       = "C2 - donttouchpleasemodaf[.]com"

      signer              = "Jerry Hayes"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 02"
      cert_serial         = "33:00:07:33:81:95:9a:de:fa:5d:30:fa:ab:00:00:00:07:33:81"
      cert_thumbprint     = "FB36DE421B7D3B5BCEC749B39A28D56FC5072A19"
      cert_valid_from     = "2026-03-03"
      cert_valid_to       = "2026-03-06"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 02" and
         sig.serial == "33:00:07:33:81:95:9a:de:fa:5d:30:fa:ab:00:00:00:07:33:81"
      )
}
