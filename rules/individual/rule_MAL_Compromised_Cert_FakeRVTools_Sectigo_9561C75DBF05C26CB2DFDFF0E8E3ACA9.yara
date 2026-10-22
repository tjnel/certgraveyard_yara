import "pe"

rule MAL_Compromised_Cert_FakeRVTools_Sectigo_9561C75DBF05C26CB2DFDFF0E8E3ACA9 {
   meta:
      description         = "Detects FakeRVTools with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-08-06"
      version             = "1.0"

      hash                = "7281c360399e7124638f35040995dc417f2f6591f01522a9230105831d1d513d"
      malware             = "FakeRVTools"
      malware_type        = "Unknown"
      malware_notes       = "Loads Action1 RMM"

      signer              = "MAA AS"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "95:61:c7:5d:bf:05:c2:6c:b2:df:df:f0:e8:e3:ac:a9"
      cert_thumbprint     = "a6431a8b9aec82ee20502a73a1a67a31fa73c58d"
      cert_valid_from     = "2026-08-06"
      cert_valid_to       = "2027-08-06"

      country             = "NO"
      state               = "Nordland"
      locality            = "---"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "95:61:c7:5d:bf:05:c2:6c:b2:df:df:f0:e8:e3:ac:a9"
      )
}
