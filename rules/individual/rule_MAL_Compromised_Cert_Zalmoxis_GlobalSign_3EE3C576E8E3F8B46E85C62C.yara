import "pe"

rule MAL_Compromised_Cert_Zalmoxis_GlobalSign_3EE3C576E8E3F8B46E85C62C {
   meta:
      description         = "Detects Zalmoxis with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-08-26"
      version             = "1.0"

      hash                = "ad0d08d54c9bbe2309bb7a8ae92def8a04297d0238f2799764d93929b57cbd5f"
      malware             = "Zalmoxis"
      malware_type        = "Infostealer"
      malware_notes       = "Analysis of the malware here: https://rogueauthority.org/signed-crash-handler-name-gate-zalmoxis-stealer"

      signer              = "YOUR CHANCE j.d.o.o."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "3e:e3:c5:76:e8:e3:f8:b4:6e:85:c6:2c"
      cert_thumbprint     = "0d6d03d1c3665bff43aec7d0e04b78000c35c3bc"
      cert_valid_from     = "2026-08-26"
      cert_valid_to       = "2027-08-27"

      country             = "HR"
      state               = "Zagreb"
      locality            = "Zagreb"
      email               = "contact@yourchance.hr"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "3e:e3:c5:76:e8:e3:f8:b4:6e:85:c6:2c"
      )
}
