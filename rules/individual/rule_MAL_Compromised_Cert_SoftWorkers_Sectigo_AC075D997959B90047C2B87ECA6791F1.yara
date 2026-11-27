import "pe"

rule MAL_Compromised_Cert_SoftWorkers_Sectigo_AC075D997959B90047C2B87ECA6791F1 {
   meta:
      description         = "Detects SoftWorkers with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-10-27"
      version             = "1.0"

      hash                = "b27314a6696532ec6b68a9aac4a260f58b7545e0823d3df6b866a3c57558641d"
      malware             = "SoftWorkers"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "INLINE SOFTWARE ANS"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "ac:07:5d:99:79:59:b9:00:47:c2:b8:7e:ca:67:91:f1"
      cert_thumbprint     = "1d8220e9a1ae681d928fffe276cea5a37d57145f"
      cert_valid_from     = "2026-10-27"
      cert_valid_to       = "2027-10-27"

      country             = "NO"
      state               = "Oslo"
      locality            = "---"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "ac:07:5d:99:79:59:b9:00:47:c2:b8:7e:ca:67:91:f1"
      )
}
