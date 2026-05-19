import "pe"

rule MAL_Compromised_Cert_ValleyRAT_Certum_16E2CE36A3379CBF4103780925D01952 {
   meta:
      description         = "Detects ValleyRAT with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-02-18"
      version             = "1.0"

      hash                = "caef6fe85c234616913702344fbbe8e57ada39cdf5003705f665f5310c3a1198"
      malware             = "ValleyRAT"
      malware_type        = "Remote access tool"
      malware_notes       = ""

      signer              = "武汉市阙桑翁科技有限公司"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Code Signing 2021 CA"
      cert_serial         = "16:e2:ce:36:a3:37:9c:bf:41:03:78:09:25:d0:19:52"
      cert_thumbprint     = "CDE01B581313FA22901FB3672F4DA9D5D956C9C7"
      cert_valid_from     = "2026-02-18"
      cert_valid_to       = "2027-02-18"

      country             = "---"
      state               = "---"
      locality            = "---"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Code Signing 2021 CA" and
         sig.serial == "16:e2:ce:36:a3:37:9c:bf:41:03:78:09:25:d0:19:52"
      )
}
