import "pe"

rule MAL_Compromised_Cert_OffLoader_Certum_6797CF88841092C96699CD2AE6857E1E {
   meta:
      description         = "Detects OffLoader with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-12-30"
      version             = "1.0"

      hash                = "eb2df1ba4f3b1a8681594ddcfe605c38749fd6e723bbe5c60dc885d03da0f578"
      malware             = "OffLoader"
      malware_type        = "Initial access tool"
      malware_notes       = "The malware was delivered disguised as a bill. The malware was flagged as OffLoader by MalwareBazaar."

      signer              = "Leshan Huilai Technology Co., Ltd."
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "67:97:cf:88:84:10:92:c9:66:99:cd:2a:e6:85:7e:1e"
      cert_thumbprint     = "84B319205D9089F274B74C274CABEADA68990F97"
      cert_valid_from     = "2025-12-30"
      cert_valid_to       = "2026-12-30"

      country             = "CN"
      state               = "Sichuan"
      locality            = "Leshan"
      email               = "???"
      rdn_serial_number   = "91511102MABUFY4X4J"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "67:97:cf:88:84:10:92:c9:66:99:cd:2a:e6:85:7e:1e"
      )
}
