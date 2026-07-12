import "pe"

rule MAL_Compromised_Cert_EvilAI_GlobalSign_75CFED98ACF1D361FBFF156B {
   meta:
      description         = "Detects EvilAI with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-28"
      version             = "1.0"

      hash                = "6451eb28eb29c067d8ca421b7a73462b669562ef5e06c447d13914c5d4116150"
      malware             = "EvilAI"
      malware_type        = "Unknown"
      malware_notes       = "Installer for a stager masquerading as a fake productivity utility named “TXTconverter”."

      signer              = "KALIM LIMITED"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "75:cf:ed:98:ac:f1:d3:61:fb:ff:15:6b"
      cert_thumbprint     = "2860AA08C990BFA2436094132D98FC0B4638F2E9"
      cert_valid_from     = "2026-04-28"
      cert_valid_to       = "2027-04-29"

      country             = "CY"
      state               = "Nicosia"
      locality            = "Tseri"
      email               = "andri@UpKalim.com"
      rdn_serial_number   = "HE484332"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "75:cf:ed:98:ac:f1:d3:61:fb:ff:15:6b"
      )
}
