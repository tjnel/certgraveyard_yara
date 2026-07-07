import "pe"

rule MAL_Compromised_Cert_Golden_Gh0st_Loader_Certum_33DB6C7028FCF6AFB84646806433D226 {
   meta:
      description         = "Detects Golden Gh0st Loader with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-11-17"
      version             = "1.0"

      hash                = "900eac9aac32dce2f1acba2e8f8462edf6bfd59d642c4701428e84e9aa08d25a"
      malware             = "Golden Gh0st Loader"
      malware_type        = "Remote access tool"
      malware_notes       = ""

      signer              = "Shi Hu"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Code Signing 2021 CA"
      cert_serial         = "33:db:6c:70:28:fc:f6:af:b8:46:46:80:64:33:d2:26"
      cert_thumbprint     = "8159AA348C4476640C89827C166BD2FFF41697FE"
      cert_valid_from     = "2025-11-17"
      cert_valid_to       = "2026-11-17"

      country             = "CN"
      state               = "四川"
      locality            = "达州"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Code Signing 2021 CA" and
         sig.serial == "33:db:6c:70:28:fc:f6:af:b8:46:46:80:64:33:d2:26"
      )
}
