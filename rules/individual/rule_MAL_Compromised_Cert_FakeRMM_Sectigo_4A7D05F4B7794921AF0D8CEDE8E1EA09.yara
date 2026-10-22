import "pe"

rule MAL_Compromised_Cert_FakeRMM_Sectigo_4A7D05F4B7794921AF0D8CEDE8E1EA09 {
   meta:
      description         = "Detects FakeRMM with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-03"
      version             = "1.0"

      hash                = "cbc7daf17c4feded3d25c3116e0c27ceda94268d1eb73ba65299b4fdd9d83ef6"
      malware             = "FakeRMM"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "El Azab Olivier"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA R36"
      cert_serial         = "4a:7d:05:f4:b7:79:49:21:af:0d:8c:ed:e8:e1:ea:09"
      cert_thumbprint     = "7d1fd14eba16d8307b9f85a7b1d8ec426cd9d8f4"
      cert_valid_from     = "2026-03-03"
      cert_valid_to       = "2027-06-01"

      country             = "FR"
      state               = "Occitanie"
      locality            = "---"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA R36" and
         sig.serial == "4a:7d:05:f4:b7:79:49:21:af:0d:8c:ed:e8:e1:ea:09"
      )
}
