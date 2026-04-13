import "pe"

rule MAL_Compromised_Cert_FakeUtility_Sectigo_00FB9FD9D5CF4778459DA4762CFDD4CA55 {
   meta:
      description         = "Detects FakeUtility with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-10-03"
      version             = "1.0"

      hash                = "5bcf518c3e0d81a5c16eddfefbee3311c7bcc380f1f2f20797027acaacb7e281"
      malware             = "FakeUtility"
      malware_type        = "Browser Hijacker"
      malware_notes       = "Distributed as Get It Steps"

      signer              = "Sichuan Youyixing Technology Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "00:fb:9f:d9:d5:cf:47:78:45:9d:a4:76:2c:fd:d4:ca:55"
      cert_thumbprint     = "86AA17918768C6CC2F65E7579BC17AFC16AA16B4"
      cert_valid_from     = "2025-10-03"
      cert_valid_to       = "2026-10-03"

      country             = "CN"
      state               = "Sichuan Sheng"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "91510100MADJ6CPP7M"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "00:fb:9f:d9:d5:cf:47:78:45:9d:a4:76:2c:fd:d4:ca:55"
      )
}
