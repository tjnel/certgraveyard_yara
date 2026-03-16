import "pe"

rule MAL_Compromised_Cert_Unknown_GlobalSign_4929DE367C94EB3414B5797D {
   meta:
      description         = "Detects Unknown with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-12"
      version             = "1.0"

      hash                = "5175ae4c75a8e1d10decb0a787d31784a986cafe5e4a24d3aa0eb7e7748f916f"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = "Dropped by Amadey - LabInstalls PPI service"

      signer              = "IP Shusharin Matvei Anatolievich"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "49:29:de:36:7c:94:eb:34:14:b5:79:7d"
      cert_thumbprint     = "0558086FDDD157D89011174DF15B4B6A22EA9ED3"
      cert_valid_from     = "2026-03-12"
      cert_valid_to       = "2027-03-13"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "49:29:de:36:7c:94:eb:34:14:b5:79:7d"
      )
}
