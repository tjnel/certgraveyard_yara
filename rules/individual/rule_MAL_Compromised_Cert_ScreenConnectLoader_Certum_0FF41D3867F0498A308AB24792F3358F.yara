import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_Certum_0FF41D3867F0498A308AB24792F3358F {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-01-07"
      version             = "1.0"

      hash                = "3f2de9f29834ca7fb64dc53ac7415e9903b1cfb23e52b1b0a28dc08798c2f790"
      malware             = "ScreenConnectLoader"
      malware_type        = "Remote access tool"
      malware_notes       = "This ScreenConnect installer was disguised as a Microsoft Teams installer. It connects to app.zyabozadpap.top and Telegram."

      signer              = "Joyce Baloyi"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Code Signing 2021 CA"
      cert_serial         = "0f:f4:1d:38:67:f0:49:8a:30:8a:b2:47:92:f3:35:8f"
      cert_thumbprint     = "D3A6F3AA7DC8FCAF0746D87FFEEB7946EA279E82"
      cert_valid_from     = "2026-01-07"
      cert_valid_to       = "2027-01-07"

      country             = "ZA"
      state               = "???"
      locality            = "Johannesburg"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Code Signing 2021 CA" and
         sig.serial == "0f:f4:1d:38:67:f0:49:8a:30:8a:b2:47:92:f3:35:8f"
      )
}
