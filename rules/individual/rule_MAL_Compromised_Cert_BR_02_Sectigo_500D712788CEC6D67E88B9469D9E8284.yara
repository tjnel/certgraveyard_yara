import "pe"

rule MAL_Compromised_Cert_BR_02_Sectigo_500D712788CEC6D67E88B9469D9E8284 {
   meta:
      description         = "Detects BR-02 with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-02-12"
      version             = "1.0"

      hash                = "a59cba001f2093aa44758293c6efca87110339e3c68fe25da49a986f948c16fb"
      malware             = "BR-02"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "TERYAKİ GRUP REKLAM ORGANİZASYON VE PRODÜKSİYON TİC LTD ŞTI"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "50:0d:71:27:88:ce:c6:d6:7e:88:b9:46:9d:9e:82:84"
      cert_thumbprint     = "13E800DC16BC2D36B90BF6EDA8612519E0A077A2"
      cert_valid_from     = "2026-02-12"
      cert_valid_to       = "2027-02-12"

      country             = "TR"
      state               = "İstanbul"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "1122490"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "50:0d:71:27:88:ce:c6:d6:7e:88:b9:46:9d:9e:82:84"
      )
}
