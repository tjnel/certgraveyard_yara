import "pe"

rule MAL_Compromised_Cert_SoftWorkers_Sectigo_7BC2A20AD43C05E8D3D7F7DF15996F2F {
   meta:
      description         = "Detects SoftWorkers with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-11-04"
      version             = "1.0"

      hash                = "96cbfe40db66a360804742c61d4d8fe8f7dcf3a2bfb29dbbe16ce0ed14f71fb1"
      malware             = "SoftWorkers"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "PRZEDSIĘBIORSTWO HANDLOWE KOMERS Sp. z o.o."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "7b:c2:a2:0a:d4:3c:05:e8:d3:d7:f7:df:15:99:6f:2f"
      cert_thumbprint     = "eba307c5491d68c03169dd3f50f11438abd0ea17"
      cert_valid_from     = "2026-11-04"
      cert_valid_to       = "2027-11-04"

      country             = "PL"
      state               = "Pomorskie"
      locality            = "---"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "7b:c2:a2:0a:d4:3c:05:e8:d3:d7:f7:df:15:99:6f:2f"
      )
}
