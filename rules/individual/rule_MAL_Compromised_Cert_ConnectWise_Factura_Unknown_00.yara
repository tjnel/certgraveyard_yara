import "pe"

rule MAL_Compromised_Cert_ConnectWise_Factura_Unknown_00 {
   meta:
      description         = "Detects ConnectWise-Factura with compromised cert (Unknown)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2023-04-01"
      version             = "1.0"

      hash                = "180b959eaecaa6c410af4f4445befcde5947a537ec396196fda014258625e2dd"
      malware             = "ConnectWise-Factura"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "ScreenConnect Client"
      cert_issuer_short   = "Unknown"
      cert_issuer         = "ScreenConnect Client Root"
      cert_serial         = "00"
      cert_thumbprint     = "159e02d18c3f70b33127d2274ed976fe69ff4c55c2b633cac4f416c67a027003"
      cert_valid_from     = "2023-04-01"
      cert_valid_to       = "2038-01-01"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "ScreenConnect Client Root" and
         sig.serial == "00"
      )
}
