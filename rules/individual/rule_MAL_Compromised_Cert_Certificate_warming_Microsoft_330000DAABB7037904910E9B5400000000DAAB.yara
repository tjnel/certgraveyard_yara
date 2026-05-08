import "pe"

rule MAL_Compromised_Cert_Certificate_warming_Microsoft_330000DAABB7037904910E9B5400000000DAAB {
   meta:
      description         = "Detects Certificate warming with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-05-07"
      version             = "1.0"

      hash                = "9b1880fd0160bdc71d2d23b4170c637af9259fd439a8f8f054b8d5c94ad095ad"
      malware             = "Certificate warming"
      malware_type        = "Unknown"
      malware_notes       = "This file was signed for certificate warming, that is, signing benign files to increase the reputation of the certificate before signing malware."

      signer              = "SONYA MAIZE"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 04"
      cert_serial         = "33:00:00:da:ab:b7:03:79:04:91:0e:9b:54:00:00:00:00:da:ab"
      cert_thumbprint     = "EEAF1B8889CFFDC23134634A97FD2CD06F7B13BB"
      cert_valid_from     = "2026-05-07"
      cert_valid_to       = "2026-05-10"

      country             = "US"
      state               = "Arizona"
      locality            = "TUBA CITY"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 04" and
         sig.serial == "33:00:00:da:ab:b7:03:79:04:91:0e:9b:54:00:00:00:00:da:ab"
      )
}
