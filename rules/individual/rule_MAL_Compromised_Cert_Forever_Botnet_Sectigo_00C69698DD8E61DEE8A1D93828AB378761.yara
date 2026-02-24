import "pe"

rule MAL_Compromised_Cert_Forever_Botnet_Sectigo_00C69698DD8E61DEE8A1D93828AB378761 {
   meta:
      description         = "Detects Forever Botnet with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-02-04"
      version             = "1.0"

      hash                = "d6b507696400dc1d67412872cb02f3f813cec2bdb70b00083ef718331a444bab"
      malware             = "Forever Botnet"
      malware_type        = "Unknown"
      malware_notes       = "Builds loaded as a stage 2 on infected machines. Malware campaign targeting BR users via fake documents."

      signer              = "Xiamen Gejie Ya Intelligent Technology Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "00:c6:96:98:dd:8e:61:de:e8:a1:d9:38:28:ab:37:87:61"
      cert_thumbprint     = "48BD2F170B27AE826EC09597ADCABD8EF46C5EDE"
      cert_valid_from     = "2026-02-04"
      cert_valid_to       = "2027-02-04"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "00:c6:96:98:dd:8e:61:de:e8:a1:d9:38:28:ab:37:87:61"
      )
}
