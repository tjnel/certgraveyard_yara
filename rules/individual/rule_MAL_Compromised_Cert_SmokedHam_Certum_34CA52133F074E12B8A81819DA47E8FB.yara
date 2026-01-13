import "pe"

rule MAL_Compromised_Cert_SmokedHam_Certum_34CA52133F074E12B8A81819DA47E8FB {
   meta:
      description         = "Detects SmokedHam with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-12-19"
      version             = "1.0"

      hash                = "cbbe98e1b36eb68a7afe534c21055f9cc793c2a6a7ca63256d273020a096f7a7"
      malware             = "SmokedHam"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Wuhan Shuoxi Technology Co., Ltd."
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "34:ca:52:13:3f:07:4e:12:b8:a8:18:19:da:47:e8:fb"
      cert_thumbprint     = "A3682074F5896CB276A2E2A6CCB8C8423C0D8187"
      cert_valid_from     = "2025-12-19"
      cert_valid_to       = "2026-12-19"

      country             = "CN"
      state               = "Hubei"
      locality            = "Wuhan"
      email               = "???"
      rdn_serial_number   = "91420103MA4F4TL53L"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "34:ca:52:13:3f:07:4e:12:b8:a8:18:19:da:47:e8:fb"
      )
}
