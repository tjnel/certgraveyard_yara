import "pe"

rule MAL_Compromised_Cert_Remcos_RAT_GlobalSign_6F35B24C2D6C5F4BB1E08659 {
   meta:
      description         = "Detects Remcos RAT with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-12-08"
      version             = "1.0"

      hash                = "d563450fb7bcc2ecb0b3c1bb1c1d8657d87165dadea10116f696b530a8237a12"
      malware             = "Remcos RAT"
      malware_type        = "Unknown"
      malware_notes       = "Ref: https://tria.ge/260224-vwn1saht4b/behavioral1"

      signer              = "Guangzhou Recorda Technology Ltd"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "6f:35:b2:4c:2d:6c:5f:4b:b1:e0:86:59"
      cert_thumbprint     = "8009FFC9F68E8476133E3C0FEF6173548E300ED2"
      cert_valid_from     = "2025-12-08"
      cert_valid_to       = "2026-11-26"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "6f:35:b2:4c:2d:6c:5f:4b:b1:e0:86:59"
      )
}
