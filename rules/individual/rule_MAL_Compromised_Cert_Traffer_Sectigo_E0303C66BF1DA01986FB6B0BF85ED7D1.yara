import "pe"

rule MAL_Compromised_Cert_Traffer_Sectigo_E0303C66BF1DA01986FB6B0BF85ED7D1 {
   meta:
      description         = "Detects Traffer with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-02-06"
      version             = "1.0"

      hash                = "fcf48487c4ef55ee78f9dafb61231b0573c5bc17cec5aa52b980d8b7f72be9a2"
      malware             = "Traffer"
      malware_type        = "Unknown"
      malware_notes       = "Fake Slack workspace"

      signer              = "Xiamen Jueyi Dazhan Network Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "e0:30:3c:66:bf:1d:a0:19:86:fb:6b:0b:f8:5e:d7:d1"
      cert_thumbprint     = "77496d47e230e82df9dac60229eb137205f8bfb3"
      cert_valid_from     = "2026-02-06"
      cert_valid_to       = "2027-02-06"

      country             = "CN"
      state               = "Fujian Sheng"
      locality            = "---"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "e0:30:3c:66:bf:1d:a0:19:86:fb:6b:0b:f8:5e:d7:d1"
      )
}
