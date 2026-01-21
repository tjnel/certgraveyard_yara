import "pe"

rule MAL_Compromised_Cert_DragonBreath_Certum_2CA603826E9AA069165C691F969F326D {
   meta:
      description         = "Detects DragonBreath with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-03-25"
      version             = "1.0"

      hash                = "627169b1bad0744f636c72a86f6f8e0ff1f4fbb475e8629576a2462a0341ca4f"
      malware             = "DragonBreath"
      malware_type        = "Unknown"
      malware_notes       = "APT DragonBreath campaign spotted targeting Cambodia. Ref: https://x.com/PrakkiSathwik/status/2013512888875655436"

      signer              = "Open Source Developer, Jiawu Wang"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Code Signing 2021 CA"
      cert_serial         = "2c:a6:03:82:6e:9a:a0:69:16:5c:69:1f:96:9f:32:6d"
      cert_thumbprint     = "21A279CE005CB11FD0968416F484BC411CC85389"
      cert_valid_from     = "2025-03-25"
      cert_valid_to       = "2026-03-25"

      country             = "CN"
      state               = "Guizhou"
      locality            = "Anshun"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Code Signing 2021 CA" and
         sig.serial == "2c:a6:03:82:6e:9a:a0:69:16:5c:69:1f:96:9f:32:6d"
      )
}
