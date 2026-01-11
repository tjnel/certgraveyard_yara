import "pe"

rule MAL_Compromised_Cert_FakeBinance_GlobalSign_1EC5118D01550617398147F2 {
   meta:
      description         = "Detects FakeBinance with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-04-25"
      version             = "1.0"

      hash                = "c4123d0488577f66e98f8833bcbcd9ea8752e0f440ad91f3e0065270edd589fa"
      malware             = "FakeBinance"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "SR TRADING Limited Liability Company"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "1e:c5:11:8d:01:55:06:17:39:81:47:f2"
      cert_thumbprint     = "DA32D4E683D6B45D0D8B6193D0459A49F0565B04"
      cert_valid_from     = "2025-04-25"
      cert_valid_to       = "2026-04-26"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "1e:c5:11:8d:01:55:06:17:39:81:47:f2"
      )
}
