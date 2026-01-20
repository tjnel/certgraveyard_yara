import "pe"

rule MAL_Compromised_Cert_Wagmi_Traffer_team_SSL_com_1D4EF724D40A79B6CCA06EB1076CBFF9 {
   meta:
      description         = "Detects Wagmi Traffer team with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-01-10"
      version             = "1.0"

      hash                = "5a5d7eb08e963c140cba3e4176c1fbc59031ff195452f0068641427c388f257b"
      malware             = "Wagmi Traffer team"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "SAFARPE TECHNOLOGY LLP"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "1d:4e:f7:24:d4:0a:79:b6:cc:a0:6e:b1:07:6c:bf:f9"
      cert_thumbprint     = ""
      cert_valid_from     = "2026-01-10"
      cert_valid_to       = "2027-01-09"

      country             = "IN"
      state               = "West Bengal"
      locality            = "Kolkata"
      email               = ""
      rdn_serial_number   = "UDYAM-WB-10-0169920"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "1d:4e:f7:24:d4:0a:79:b6:cc:a0:6e:b1:07:6c:bf:f9"
      )
}
