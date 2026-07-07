import "pe"

rule MAL_Compromised_Cert_Golden_Gh0st_Loader_Sectigo_70205E32FEFDB3E3D948AF5E67472901 {
   meta:
      description         = "Detects Golden Gh0st Loader with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-05-23"
      version             = "1.0"

      hash                = "749edc4ed6c6e9c861dcdf452c7acc7ec521cd1b4ac91ffee4158ab53ec57730"
      malware             = "Golden Gh0st Loader"
      malware_type        = "Remote access tool"
      malware_notes       = ""

      signer              = "Ventis Media, Inc."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA E36"
      cert_serial         = "70:20:5e:32:fe:fd:b3:e3:d9:48:af:5e:67:47:29:01"
      cert_thumbprint     = "758253C0037839EBAAFEA8EAC9AAD6311399E8B3"
      cert_valid_from     = "2025-05-23"
      cert_valid_to       = "2026-01-01"

      country             = "CA"
      state               = "Quebec"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA E36" and
         sig.serial == "70:20:5e:32:fe:fd:b3:e3:d9:48:af:5e:67:47:29:01"
      )
}
