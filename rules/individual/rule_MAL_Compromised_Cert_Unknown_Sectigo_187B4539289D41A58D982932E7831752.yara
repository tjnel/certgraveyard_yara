import "pe"

rule MAL_Compromised_Cert_Unknown_Sectigo_187B4539289D41A58D982932E7831752 {
   meta:
      description         = "Detects Unknown with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-11-06"
      version             = "1.0"

      hash                = "90a87fb3a52e07bb24c023832deed25cfd7e3988ca1bfee64a88989273a96a07"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = "File distributed via the malicious LabInstalls PPI network. Ref: https://loaderinsight.agency/?p=payload_view&hash=90a87fb3a52e07bb24c023832deed25cfd7e3988ca1bfee64a88989273a96a07"

      signer              = "WASH AND CUT HAIR SALOON LIMITED"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV E36"
      cert_serial         = "18:7b:45:39:28:9d:41:a5:8d:98:29:32:e7:83:17:52"
      cert_thumbprint     = "07A54802BA299BECC6BBD88621A860FD7D8040D0"
      cert_valid_from     = "2025-11-06"
      cert_valid_to       = "2026-11-06"

      country             = "GB"
      state               = "England"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "06905521"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV E36" and
         sig.serial == "18:7b:45:39:28:9d:41:a5:8d:98:29:32:e7:83:17:52"
      )
}
