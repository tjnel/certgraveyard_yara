import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_GlobalSign_6E2B391C7FF99AB597A70E5B {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-12-15"
      version             = "1.0"

      hash                = "a67637afafdd1045cf28ccbacf5e503e9a9d12af6fe9640fc68d3f3a1e3954e8"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "SAKHRI YANIS Entrepreneur individuel"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "6e:2b:39:1c:7f:f9:9a:b5:97:a7:0e:5b"
      cert_thumbprint     = "CF49FBF2A3790CEDB24C3AC4315E3498953FFFC7"
      cert_valid_from     = "2025-12-15"
      cert_valid_to       = "2026-12-16"

      country             = "FR"
      state               = "Hauts-de-Seine"
      locality            = "Issy-les-Moulineaux"
      email               = "mohamedhaje04@gmail.com"
      rdn_serial_number   = "989 260 229"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "6e:2b:39:1c:7f:f9:9a:b5:97:a7:0e:5b"
      )
}
