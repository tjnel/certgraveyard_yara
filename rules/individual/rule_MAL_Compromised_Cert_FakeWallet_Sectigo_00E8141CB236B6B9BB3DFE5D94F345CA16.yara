import "pe"

rule MAL_Compromised_Cert_FakeWallet_Sectigo_00E8141CB236B6B9BB3DFE5D94F345CA16 {
   meta:
      description         = "Detects FakeWallet with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-12-31"
      version             = "1.0"

      hash                = "3b2df007a63e449e1bc4240c29b8c64c39c1b86c27213bde876f8ffb271446cb"
      malware             = "FakeWallet"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Wuxi ENJOY International Trading Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "00:e8:14:1c:b2:36:b6:b9:bb:3d:fe:5d:94:f3:45:ca:16"
      cert_thumbprint     = "A3B9E64D35D1C7684F8BBD32917CCDAACB7B5125"
      cert_valid_from     = "2025-12-31"
      cert_valid_to       = "2026-12-31"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "00:e8:14:1c:b2:36:b6:b9:bb:3d:fe:5d:94:f3:45:ca:16"
      )
}
