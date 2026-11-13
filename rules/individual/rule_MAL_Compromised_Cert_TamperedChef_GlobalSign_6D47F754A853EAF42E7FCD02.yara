import "pe"

rule MAL_Compromised_Cert_TamperedChef_GlobalSign_6D47F754A853EAF42E7FCD02 {
   meta:
      description         = "Detects TamperedChef with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-19"
      version             = "1.0"

      hash                = "0c19ea5b0e0f646bd0cab476f8b38e57f282399e6489075e1ea66066f5925c9d"
      malware             = "TamperedChef"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Alternate Financial, LLC"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "6d:47:f7:54:a8:53:ea:f4:2e:7f:cd:02"
      cert_thumbprint     = "e4f3e398dbe646536d5dacf0f25f14563004b7a2"
      cert_valid_from     = "2026-03-19"
      cert_valid_to       = "2027-03-20"

      country             = "US"
      state               = "Virginia"
      locality            = "Virginia Beach"
      email               = "greg@alternatefintech.com"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "6d:47:f7:54:a8:53:ea:f4:2e:7f:cd:02"
      )
}
