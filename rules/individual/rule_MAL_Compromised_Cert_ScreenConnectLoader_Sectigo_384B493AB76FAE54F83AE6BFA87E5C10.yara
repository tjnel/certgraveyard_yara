import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_Sectigo_384B493AB76FAE54F83AE6BFA87E5C10 {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-12-24"
      version             = "1.0"

      hash                = "af214ddb9be8c439f16f7cdb2e982557e957c87cfbe612a51f67f5a4195347be"
      malware             = "ScreenConnectLoader"
      malware_type        = "Remote access tool"
      malware_notes       = ""

      signer              = "STEPHEN WHANG, CPA, INC."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "38:4b:49:3a:b7:6f:ae:54:f8:3a:e6:bf:a8:7e:5c:10"
      cert_thumbprint     = "D45D60B20006BC3A39AE1761CB5F5F5B067B4EE5"
      cert_valid_from     = "2025-12-24"
      cert_valid_to       = "2026-12-24"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "38:4b:49:3a:b7:6f:ae:54:f8:3a:e6:bf:a8:7e:5c:10"
      )
}
