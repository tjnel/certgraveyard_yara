import "pe"

rule MAL_Compromised_Cert_Gh0stRAT_Certum_76E2ACF0F2F39C06A0B34E4309A8EAF2 {
   meta:
      description         = "Detects Gh0stRAT with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-11-08"
      version             = "1.0"

      hash                = "779272fd234deb25d4275715eb9e72e58492a149ed48c8ab1819b710864d29ed"
      malware             = "Gh0stRAT"
      malware_type        = "Remote access tool"
      malware_notes       = "The malware appears to be a newer version of GhostRAT. Disguised as a fake invoice."

      signer              = "北京谷云达吉商贸有限公司"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "76:e2:ac:f0:f2:f3:9c:06:a0:b3:4e:43:09:a8:ea:f2"
      cert_thumbprint     = "A55D45182DD2D9CF4455F21E3B63ED498424276C"
      cert_valid_from     = "2025-11-08"
      cert_valid_to       = "2026-10-30"

      country             = "CN"
      state               = "北京市"
      locality            = "北京市"
      email               = "???"
      rdn_serial_number   = "91110112MAENGGCR13"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "76:e2:ac:f0:f2:f3:9c:06:a0:b3:4e:43:09:a8:ea:f2"
      )
}
