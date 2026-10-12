import "pe"

rule MAL_Compromised_Cert_WingsLab_SSL_com_2FE4486D9B0541102A11F02F58A28755 {
   meta:
      description         = "Detects WingsLab with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-06-19"
      version             = "1.0"

      hash                = "164b98f315ba8ed9fcd011843c3f55ead965f199e79c692b085da2a5a731566d"
      malware             = "WingsLab"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Evelyn Paredes"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "2f:e4:48:6d:9b:05:41:10:2a:11:f0:2f:58:a2:87:55"
      cert_thumbprint     = "0a7ec8073db17ca6b0de24a0c4014677293efaf6"
      cert_valid_from     = "2026-06-19"
      cert_valid_to       = "2027-06-19"

      country             = "US"
      state               = "Texas"
      locality            = "Garland"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "2f:e4:48:6d:9b:05:41:10:2a:11:f0:2f:58:a2:87:55"
      )
}
