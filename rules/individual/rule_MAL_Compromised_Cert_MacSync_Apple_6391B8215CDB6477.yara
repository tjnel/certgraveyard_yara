import "pe"

rule MAL_Compromised_Cert_MacSync_Apple_6391B8215CDB6477 {
   meta:
      description         = "Detects MacSync with compromised cert (Apple)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-11-01"
      version             = "1.0"

      hash                = "0a070d32e5b8648c6515cb5a0b6fba202c5c8f80e15f7c3621bd8fecd7708b04"
      malware             = "MacSync"
      malware_type        = "Infostealer"
      malware_notes       = "Recently identified infostealer documented here: https://www.jamf.com/blog/macsync-stealer-evolution-code-signed-swift-malware-analysis/"

      signer              = "Victor Redmond"
      cert_issuer_short   = "Apple"
      cert_issuer         = "Apple Inc."
      cert_serial         = "63:91:b8:21:5c:db:64:77"
      cert_thumbprint     = "3660BD4E40539976567F3E4607BAFAB4D98DF5E5"
      cert_valid_from     = "2024-11-01"
      cert_valid_to       = "2027-02-01"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Apple Inc." and
         sig.serial == "63:91:b8:21:5c:db:64:77"
      )
}
