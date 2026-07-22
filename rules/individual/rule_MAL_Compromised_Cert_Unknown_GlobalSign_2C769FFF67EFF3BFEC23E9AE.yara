import "pe"

rule MAL_Compromised_Cert_Unknown_GlobalSign_2C769FFF67EFF3BFEC23E9AE {
   meta:
      description         = "Detects Unknown with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-31"
      version             = "1.0"

      hash                = "46b426b6e25231d731d7cb2822f1435f65778f168c9d838568e9012d3507abda"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Legacy Roots Co., Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "2c:76:9f:ff:67:ef:f3:bf:ec:23:e9:ae"
      cert_thumbprint     = "BB0DE6119150388409296D8BEE662EC5F9E4B973"
      cert_valid_from     = "2026-03-31"
      cert_valid_to       = "2027-04-01"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "2c:76:9f:ff:67:ef:f3:bf:ec:23:e9:ae"
      )
}
