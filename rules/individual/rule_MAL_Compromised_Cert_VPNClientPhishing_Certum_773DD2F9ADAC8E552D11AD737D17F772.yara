import "pe"

rule MAL_Compromised_Cert_VPNClientPhishing_Certum_773DD2F9ADAC8E552D11AD737D17F772 {
   meta:
      description         = "Detects VPNClientPhishing with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-12-11"
      version             = "1.0"

      hash                = "cfa4781ebfa5a8d68b233efb723dbde434ca70b2f76ff28127ecf13753bfe011"
      malware             = "VPNClientPhishing"
      malware_type        = "Unknown"
      malware_notes       = "Fake VPN Client spread via SEO poisoning sending credentials to vpn-connection[.]pro. Detonation: https://app.any.run/tasks/e83886f5-d9bf-498c-b98a-ab9ae52c299c"

      signer              = "Taiyuan Lihua Near Information Technology Co., Ltd."
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "77:3d:d2:f9:ad:ac:8e:55:2d:11:ad:73:7d:17:f7:72"
      cert_thumbprint     = "731B7470AA8F16ADBDEF712A01C2FCBCA5A1D554"
      cert_valid_from     = "2025-12-11"
      cert_valid_to       = "2026-12-11"

      country             = "CN"
      state               = "Shanxi"
      locality            = "Taiyuan"
      email               = "???"
      rdn_serial_number   = "91140106MA0M4T3R8E"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "77:3d:d2:f9:ad:ac:8e:55:2d:11:ad:73:7d:17:f7:72"
      )
}
