import "pe"

rule MAL_Compromised_Cert_NetSupport_RAT_Certum_52AD5759DB8B13B015D918CAF77AE355 {
   meta:
      description         = "Detects NetSupport RAT with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-09-17"
      version             = "1.0"

      hash                = "64008a46157a6636e497f4ef20e0b320d44e66c68debc98c84fea12beab83f58"
      malware             = "NetSupport RAT"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Amir Software Inc"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "52:ad:57:59:db:8b:13:b0:15:d9:18:ca:f7:7a:e3:55"
      cert_thumbprint     = "83deb6a864f363c036cfe882a2b574b82dc0139b"
      cert_valid_from     = "2026-09-17"
      cert_valid_to       = "2027-09-17"

      country             = "CA"
      state               = "Ontario"
      locality            = "Richmond Hill"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "52:ad:57:59:db:8b:13:b0:15:d9:18:ca:f7:7a:e3:55"
      )
}
