import "pe"

rule MAL_Compromised_Cert_EvilAI_Certum_3FF2B6872A6D7018078C820704F95028 {
   meta:
      description         = "Detects EvilAI with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2023-07-26"
      version             = "1.0"

      hash                = "2b2937df3e5ae5465058b45ddaf6e46432613fa5ac678d4d64a8daf0c2f56bfc"
      malware             = "EvilAI"
      malware_type        = "Unknown"
      malware_notes       = "Discussion: https://www.reddit.com/r/antivirus/comments/1r368h4/malware_analysis_networkgraphicssetupexe"

      signer              = "Danylo Babenko"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Code Signing 2021 CA"
      cert_serial         = "3f:f2:b6:87:2a:6d:70:18:07:8c:82:07:04:f9:50:28"
      cert_thumbprint     = "17B64AA8D6C8A1F04BF19F48023B8D315022B2F5"
      cert_valid_from     = "2023-07-26"
      cert_valid_to       = "2026-07-25"

      country             = "UA"
      state               = "Kyiv"
      locality            = "Kyiv"
      email               = "support@fivemods.io"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Code Signing 2021 CA" and
         sig.serial == "3f:f2:b6:87:2a:6d:70:18:07:8c:82:07:04:f9:50:28"
      )
}
