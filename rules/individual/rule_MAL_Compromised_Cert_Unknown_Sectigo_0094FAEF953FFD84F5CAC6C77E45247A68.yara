import "pe"

rule MAL_Compromised_Cert_Unknown_Sectigo_0094FAEF953FFD84F5CAC6C77E45247A68 {
   meta:
      description         = "Detects Unknown with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-11-06"
      version             = "1.0"

      hash                = "071ea43c2a6ffeea0a5f7a9fe940dd81288174601d50847faaee5d62263454a5"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Reach Spark Labs LLC"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "00:94:fa:ef:95:3f:fd:84:f5:ca:c6:c7:7e:45:24:7a:68"
      cert_thumbprint     = "A89017F826EDABA95248443557F3CAC571A098E2"
      cert_valid_from     = "2025-11-06"
      cert_valid_to       = "2026-11-06"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "00:94:fa:ef:95:3f:fd:84:f5:ca:c6:c7:7e:45:24:7a:68"
      )
}
