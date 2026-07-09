import "pe"

rule MAL_Compromised_Cert_Forever_Botnet_BR_01_GlobalSign_23B4D5276B68C9EA136DF5E3 {
   meta:
      description         = "Detects Forever Botnet,BR-01 with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-05-29"
      version             = "1.0"

      hash                = "8b3f0c4984c5448977c3e7e8330504b949a1c4fc47772697ceb07beb4710b87d"
      malware             = "Forever Botnet,BR-01"
      malware_type        = "Infostealer"
      malware_notes       = ""

      signer              = "TRADECONSULT AS"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "23:b4:d5:27:6b:68:c9:ea:13:6d:f5:e3"
      cert_thumbprint     = "551C63C5E920514EDFF0B2713C8C407A356B5E0D"
      cert_valid_from     = "2026-05-29"
      cert_valid_to       = "2027-04-23"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "23:b4:d5:27:6b:68:c9:ea:13:6d:f5:e3"
      )
}
