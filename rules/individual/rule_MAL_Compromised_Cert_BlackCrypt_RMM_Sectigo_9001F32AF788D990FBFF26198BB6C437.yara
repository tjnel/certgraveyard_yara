import "pe"

rule MAL_Compromised_Cert_BlackCrypt_RMM_Sectigo_9001F32AF788D990FBFF26198BB6C437 {
   meta:
      description         = "Detects BlackCrypt RMM with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-09-22"
      version             = "1.0"

      hash                = "f58b67e61ee947afd2e9e45f7ecd392d5fedc8f6b29a3d2ec5a323e38aba253c"
      malware             = "BlackCrypt RMM"
      malware_type        = "Remote access tool"
      malware_notes       = ""

      signer              = "C&P Global Investors LLC"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "90:01:f3:2a:f7:88:d9:90:fb:ff:26:19:8b:b6:c4:37"
      cert_thumbprint     = "0aa55d396490cc2de9d27ef33af10771170dcb91"
      cert_valid_from     = "2026-09-22"
      cert_valid_to       = "2027-10-26"

      country             = "US"
      state               = "California"
      locality            = "---"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "90:01:f3:2a:f7:88:d9:90:fb:ff:26:19:8b:b6:c4:37"
      )
}
