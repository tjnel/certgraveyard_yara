import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_SSL_com_0E4842A69FD35DC87F25E6411F2272D4 {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-07-08"
      version             = "1.0"

      hash                = "39030298332d4ad0b3b3cb987a4bb9501f19d8ba48b393f187cf560db6b60a79"
      malware             = "ScreenConnectLoader"
      malware_type        = "Remote access tool"
      malware_notes       = ""

      signer              = "Edgar Palacios"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "0e:48:42:a6:9f:d3:5d:c8:7f:25:e6:41:1f:22:72:d4"
      cert_thumbprint     = "E82F69496E03A61ACCBE806484FC5F320231120E"
      cert_valid_from     = "2026-07-08"
      cert_valid_to       = "2027-07-08"

      country             = "US"
      state               = "Texas"
      locality            = "San Antonio"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "0e:48:42:a6:9f:d3:5d:c8:7f:25:e6:41:1f:22:72:d4"
      )
}
