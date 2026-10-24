import "pe"

rule MAL_Compromised_Cert_CNCMachineRMS_Sectigo_34D898FA7A8CA1EC63FCF8FB76874AD3 {
   meta:
      description         = "Detects CNCMachineRMS with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-09-15"
      version             = "1.0"

      hash                = "b74b2bfc895f1205dfb389772b201a8e31b7bc4464ff3c4463b417626ecedb1c"
      malware             = "CNCMachineRMS"
      malware_type        = "Remote access tool"
      malware_notes       = "https://rogueauthority.org/signed-teams-installer-calibre-babadeda-rat"

      signer              = "Lway Firmware"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "34:d8:98:fa:7a:8c:a1:ec:63:fc:f8:fb:76:87:4a:d3"
      cert_thumbprint     = "be76c3a78309a24f024365a6293d09a26adaa978"
      cert_valid_from     = "2026-09-15"
      cert_valid_to       = "2027-12-14"

      country             = "FI"
      state               = "Uusimaa"
      locality            = "---"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "34:d8:98:fa:7a:8c:a1:ec:63:fc:f8:fb:76:87:4a:d3"
      )
}
