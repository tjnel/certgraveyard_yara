import "pe"

rule MAL_Compromised_Cert_EvilAI_Sectigo_00A4969B69DD31D1AFA2F2937A2844FF73 {
   meta:
      description         = "Detects EvilAI with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-04"
      version             = "1.0"

      hash                = "af6cc7c04d6f344e18fe82d8be6910ab57e05bdf97195f8292dfa0e8b256cb40"
      malware             = "EvilAI"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Ice Ignite LTD"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "00:a4:96:9b:69:dd:31:d1:af:a2:f2:93:7a:28:44:ff:73"
      cert_thumbprint     = "0875A15751EF581DB2EB28D71F87E7A35C811941"
      cert_valid_from     = "2026-03-04"
      cert_valid_to       = "2027-03-04"

      country             = "IL"
      state               = "Central"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "514875400"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "00:a4:96:9b:69:dd:31:d1:af:a2:f2:93:7a:28:44:ff:73"
      )
}
