import "pe"

rule MAL_Compromised_Cert_ScreenConnect_Loader_Certum_75FC85C5802706A4CC78ABFCFED190BB {
   meta:
      description         = "Detects ScreenConnect Loader with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-22"
      version             = "1.0"

      hash                = "e11955b675405d310da057af3a5d56da27c1f0da078a907b52d6055dd4e20455"
      malware             = "ScreenConnect Loader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Hao He"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Code Signing 2021 CA"
      cert_serial         = "75:fc:85:c5:80:27:06:a4:cc:78:ab:fc:fe:d1:90:bb"
      cert_thumbprint     = "96f7d0216b2abd1da7cbf45f7a0dc67d368a82cc"
      cert_valid_from     = "2026-04-22"
      cert_valid_to       = "2027-04-22"

      country             = "CN"
      state               = "Sichuan"
      locality            = "Shehong"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Code Signing 2021 CA" and
         sig.serial == "75:fc:85:c5:80:27:06:a4:cc:78:ab:fc:fe:d1:90:bb"
      )
}
