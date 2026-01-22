import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_GlobalSign_1DA8F5EBC1E0C908D1AD1BE6 {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-11-25"
      version             = "1.0"

      hash                = "1928fc51879838e6447f2232bcf788f7837d789fc08ba2bcb83eca70cc73dbef"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = "Malicious installer disguised as a fake transaction document that loads a legit RMM tool"

      signer              = "PAKINPAKORN LIMITED PARTNERSHIP"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "1d:a8:f5:eb:c1:e0:c9:08:d1:ad:1b:e6"
      cert_thumbprint     = "3DE69FAF9E46C8129AF6326714AC60A36C62877D"
      cert_valid_from     = "2025-11-25"
      cert_valid_to       = "2026-11-26"

      country             = "TH"
      state               = "CHIANG MAI"
      locality            = "SAN SAI"
      email               = "???"
      rdn_serial_number   = "0503552004900"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "1d:a8:f5:eb:c1:e0:c9:08:d1:ad:1b:e6"
      )
}
